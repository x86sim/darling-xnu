#include <darling/emulation/xnu_syscall/bsd/impl/select/select.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/impl/select/pselect.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockutil.h>
#include <darling/emulation/common/sigsafe_lock.h>
#include <libsimple/lock.h>

extern void* memcpy(void* destination, const void* source, __SIZE_TYPE__ n);
extern void* memset(void* destination, int value, __SIZE_TYPE__ length);
#define LINUX_EBADF 9

// x86Sim: a TCP socket that was never connected (Linux's TCP_CLOSE with no segment either way, not listening) is
// neither readable nor writable to XNU's select (soreadable(): no data, no SS_CANTRCVMORE, no connections, no
// so_error; sowriteable(): not connected and PR_CONNREQUIRED), while Linux's tcp_poll() reports it hung up and
// writable at once (POLLHUP, POLLOUT), which select() counts as both. MultipeerConnectivity's GCKSession keeps such a
// socket in its receive loop's read set only as a wake-up: another thread closes it, and XNU's select() then fails
// with EBADF (close() wakes a select() waiting on the descriptor, whose rescan finds it gone), which the loop takes as
// "look again". Under Linux the loop never slept, ~4000 rounds a second, and its OSPF Hello after the ICE check was
// never sent, so an MCSession invitation stayed "connecting" until it timed out. Such a socket's bits are taken out of
// the result; when nothing else was ready, the wait goes on (Linux leaves the time remaining in the timeout) without
// it, watched for close() as XNU's select() would (select_fd_closed(): an eventfd in the read set), then EBADF.
#define SELECT_FILTER_MAX_FDS 1024 // Darwin's FD_SETSIZE: larger sets (_DARWIN_UNLIMITED_SELECT) are left alone

#define LINUX_EFD_CLOEXEC 02000000
#define LINUX_EFD_NONBLOCK 04000
#define SELECT_WATCHES 32
#define SELECT_WATCH_FDS 8

// the waits watching never-connected sockets for close(): the sockets, and the eventfd close() writes to
static struct select_watch {
	int wake; // -1: free
	int fds[SELECT_WATCH_FDS];
	int count;
} select_watches[SELECT_WATCHES] = { [0 ... SELECT_WATCHES - 1] = { .wake = -1 } };
static libsimple_lock_t select_watches_lock = LIBSIMPLE_LOCK_INITIALIZER;
static volatile int select_watch_count;

void select_fd_closed(int fd)
{
	if (select_watch_count == 0)
		return;
	unsigned long long mask = sigsafe_lock(&select_watches_lock);
	for (int i = 0; i < SELECT_WATCHES; i++) {
		struct select_watch* w = &select_watches[i];
		if (w->wake < 0)
			continue;
		for (int j = 0; j < w->count; j++) {
			if (w->fds[j] == fd) {
				unsigned long long one = 1;
				LINUX_SYSCALL(__NR_write, w->wake, &one, sizeof(one));
				break;
			}
		}
	}
	sigsafe_unlock(&select_watches_lock, mask);
}

// a watch over the never-connected sockets of the sets asked for (fds[], count): its slot, or -1 (none free, or no
// eventfd: the wait goes on unwatched)
static int watch_start(const int* fds, int count)
{
	int wake = LINUX_SYSCALL(__NR_eventfd2, 0, LINUX_EFD_CLOEXEC | LINUX_EFD_NONBLOCK);
	if (wake < 0)
		return -1;
	unsigned long long mask = sigsafe_lock(&select_watches_lock);
	for (int i = 0; i < SELECT_WATCHES; i++) {
		struct select_watch* w = &select_watches[i];
		if (w->wake >= 0)
			continue;
		w->wake = wake;
		w->count = count;
		for (int j = 0; j < count; j++)
			w->fds[j] = fds[j];
		select_watch_count++;
		sigsafe_unlock(&select_watches_lock, mask);
		return i;
	}
	sigsafe_unlock(&select_watches_lock, mask);
	LINUX_SYSCALL1(__NR_close, wake);
	return -1;
}

static void watch_end(int slot)
{
	unsigned long long mask = sigsafe_lock(&select_watches_lock);
	int wake = select_watches[slot].wake;
	select_watches[slot].wake = -1;
	select_watch_count--;
	sigsafe_unlock(&select_watches_lock, mask);
	LINUX_SYSCALL1(__NR_close, wake);
}

static int fd_isset(const void* set, int fd) { return set && (((const unsigned char*) set)[fd / 8] >> (fd % 8)) & 1; }
static void fd_clr(void* set, int fd) { if (set) ((unsigned char*) set)[fd / 8] &= ~(1 << (fd % 8)); }

static int tcp_never_connected(int fd)
{
	struct linux_tcp_info info;
	return linux_tcp_info(fd, &info) == 0 && info.state == LINUX_TCP_CLOSE && info.segs_out == 0 && info.segs_in == 0;
}

// Takes the never-connected TCP sockets out of a select() result of ret bits; returns the bits left. Those sockets
// are also taken out of the sets asked for (in_*), for the next wait, and added to removed[] (*nremoved).
static int filter_never_connected(int nfds, void* rfds, void* wfds, void* in_r, void* in_w, int ret, int* removed,
		int* nremoved)
{
	for (int fd = 0; fd < nfds && ret > 0; fd++) {
		int r = fd_isset(rfds, fd), w = fd_isset(wfds, fd);
		if (!r && !w)
			continue;
		if (!tcp_never_connected(fd))
			continue;
		fd_clr(rfds, fd);
		fd_clr(wfds, fd);
		fd_clr(in_r, fd);
		fd_clr(in_w, fd);
		ret -= r + w;
		if (*nremoved < SELECT_WATCH_FDS)
			removed[(*nremoved)++] = fd;
	}
	return ret;
}

long sys_select(int nfds, void* rfds, void* wfds, void* efds, struct bsd_timeval* timeout)
{
	CANCELATION_POINT();
	return sys_select_nocancel(nfds, rfds, wfds, efds, timeout);
}

long sys_select_nocancel(int nfds, void* rfds, void* wfds, void* efds, struct bsd_timeval* timeout)
{
	#if defined(__NR__newselect) || defined(__NR_select)
		int ret;
		struct linux_timeval ltv;

		if (timeout != NULL)
		{
			ltv.tv_sec = timeout->tv_sec;
			ltv.tv_usec = timeout->tv_usec;
		}

		// the sets asked for, to wait again with (x86Sim, see filter_never_connected())
		unsigned char in_r[SELECT_FILTER_MAX_FDS / 8], in_w[SELECT_FILTER_MAX_FDS / 8], in_e[SELECT_FILTER_MAX_FDS / 8];
		int filter = nfds > 0 && nfds <= SELECT_FILTER_MAX_FDS && (rfds || wfds);
		unsigned long set_bytes = ((nfds + 63) / 64) * 8; // Linux's fd_set words

		int removed[SELECT_WATCH_FDS], nremoved = 0, watch = -1, wait_nfds = nfds;
		unsigned char empty_r[SELECT_FILTER_MAX_FDS / 8];

		if (filter)
		{
			if (rfds) memcpy(in_r, rfds, set_bytes);
			if (wfds) memcpy(in_w, wfds, set_bytes);
			if (efds) memcpy(in_e, efds, set_bytes);
		}
		for (;;)
		{
		#if defined(__NR__newselect)
			ret = LINUX_SYSCALL(__NR__newselect, wait_nfds, rfds, wfds, efds,
					(timeout != NULL) ? &ltv : NULL);
		#else
			ret = LINUX_SYSCALL(__NR_select, wait_nfds, rfds, wfds, efds,
					(timeout != NULL) ? &ltv : NULL);
		#endif
			if (ret > 0 && watch >= 0)
			{
				// a watched socket was closed: XNU's select() fails with EBADF
				int wake = select_watches[watch].wake;
				void* r = rfds ? rfds : empty_r;
				if (fd_isset(r, wake))
				{
					ret = -LINUX_EBADF;
					break;
				}
			}
			if (ret <= 0 || !filter)
				break;
			int left = filter_never_connected(nfds, rfds, wfds, rfds ? in_r : NULL, wfds ? in_w : NULL, ret,
					removed, &nremoved);
			if (left > 0 || (timeout != NULL && ltv.tv_sec == 0 && ltv.tv_usec == 0))
			{
				ret = left;
				break;
			}
			// nothing else was ready: wait again for the rest of the time, without those sockets but woken by their
			// close()
			if (rfds) memcpy(rfds, in_r, set_bytes);
			if (wfds) memcpy(wfds, in_w, set_bytes);
			if (efds) memcpy(efds, in_e, set_bytes);
			if (watch < 0 && nremoved > 0 && (watch = watch_start(removed, nremoved)) >= 0)
			{
				int wake = select_watches[watch].wake;
				if (wake >= SELECT_FILTER_MAX_FDS)
				{
					watch_end(watch);
					watch = -1;
				}
				else
				{
					if (!rfds)
					{
						memset(empty_r, 0, sizeof(empty_r));
						rfds = empty_r;
					}
					wait_nfds = wake + 1 > nfds ? wake + 1 : nfds;
				}
			}
			if (watch >= 0)
			{
				unsigned char* r = rfds;
				int wake = select_watches[watch].wake;
				r[wake / 8] |= 1 << (wake % 8);
			}
		}
		if (watch >= 0)
		{
			// the eventfd is no bit of the caller's
			if (rfds && ret >= 0)
			{
				int wake = select_watches[watch].wake;
				((unsigned char*) rfds)[wake / 8] &= ~(1 << (wake % 8));
			}
			if (rfds == empty_r)
				rfds = NULL;
			watch_end(watch);
		}
		if (ret < 0)
			ret = errno_linux_to_bsd(ret);

		return ret;
	#else
		// pselect() takes a timespec, not a timeval
		struct bsd_timespec ts;

		if (timeout != NULL)
		{
			ts.tv_sec = timeout->tv_sec;
			ts.tv_nsec = (long)timeout->tv_usec * 1000L;
		}

		return sys_pselect_nocancel(nfds, rfds, wfds, efds,
				(timeout != NULL) ? &ts : NULL, NULL);
	#endif
}
