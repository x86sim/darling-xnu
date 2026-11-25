#include <darling/emulation/xnu_syscall/bsd/impl/network/connect.h>

#include <sys/socket.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/other/mach/foreign_hook.h>

extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);
extern __SIZE_TYPE__ strlen(const char* src);
extern char* strcpy(char* dest, const char* src);
extern char *strncpy(char *dest, const char *src, __SIZE_TYPE__ n);

// libkqueue's, when it's there (for-libkqueue.h)
__attribute__((weak))
__attribute__((visibility("default")))
void kqueue_socket_changed(int fd)
{
	// x86Sim: on the simulator's libSystem libkqueue is libkqueue_sim, found by name (foreign_hook.h)
	FOREIGN_HOOK(void (*)(int), foreign, "__darling_sim_kqueue_socket_changed");
	if (foreign)
		foreign(fd);
}

// x86Sim: libkqueue's, when it's there (for-libkqueue.h)
__attribute__((weak))
__attribute__((visibility("default")))
void kqueue_socket_unpark(int fd)
{
	FOREIGN_HOOK(void (*)(int), foreign, "__darling_sim_kqueue_socket_unpark");
	if (foreign)
		foreign(fd);
}

// Must be included after strncpy
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

static long sys_connect_common(int fd, const void* name, int socklen, bool cancelable);

#include <darling/emulation/xnu_syscall/bsd/impl/network/getsockopt.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/getpeername.h>

// QUIRK: on a non-blocking stream socket whose connection attempt has
// completed, a further connect() fails with EISCONN. Linux instead reports
// success once, because it treats the call as confirming the pending attempt.
// Evidence: black-box observation on macOS 26.7.3 (tier 2): the repeated call
// returns EALREADY while the attempt is pending and EISCONN afterwards, never 0;
// connect(2) documents EISCONN for an already connected socket.
// Test: tests/src/socket_nonblocking_connect.c (check_repeat_done and the
// repeated connect right after the connect started).
static int stream_already_connected(int fd)
{
	int type = 0, typelen = sizeof(type);
	long flags = LINUX_SYSCALL(__NR_fcntl, fd, 3 /*F_GETFL*/, 0);
	char peer[128];
	int peerlen = sizeof(peer);

	if (flags < 0 || !(flags & 0x800 /*O_NONBLOCK*/))
		return 0;
	if (sys_getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &typelen) < 0 || type != SOCK_STREAM)
		return 0;
	return sys_getpeername(fd, peer, &peerlen) == 0;
}

long sys_connect(int fd, const void* name, int socklen)
{
	CANCELATION_POINT();
	return sys_connect_common(fd, name, socklen, true);
}

long sys_connect_nocancel(int fd, const void* name, int socklen)
{
	return sys_connect_common(fd, name, socklen, false);
}

static long sys_connect_common(int fd, const void* name, int socklen, bool cancelable)
{
	int ret;
	struct sockaddr_fixup* fixed;

	if (socklen > 512)
		return -EINVAL;

	fixed = __builtin_alloca(sockaddr_fixup_size_from_bsd(name, socklen));
	ret = socklen = sockaddr_fixup_from_bsd(fixed, name, socklen);
	if (ret < 0)
		return ret;

	if (((const struct sockaddr*) name)->sa_family != AF_UNSPEC && stream_already_connected(fd))
		return -EISCONN;

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL_C(cancelable, __NR_socketcall, LINUX_SYS_CONNECT, ((long[6]) { fd, fixed, socklen }));
#else
	ret = LINUX_SYSCALL_C(cancelable, __NR_connect, fd, fixed, socklen);
#endif

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	// connected, or failed; a connect still in progress changes nothing yet
	if (ret != -EINPROGRESS && ret != -EALREADY)
		SOCKET_CHANGED(fd);
	// x86Sim: but it ends the hang-up of a socket that was never connected (libkqueue parks knotes on that)
	SOCKET_UNPARK(fd);

	return ret;
}

#include <darling/emulation/xnu_syscall/bsd/impl/network/bind.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/writev.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/shutdown.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/getsockopt.h>

// x86Sim: connectx (BSD 447). iOS 27's Network.framework opens every TCP flow with connectx(), not connect(); without it
// the call failed and NSURLSession reported "The Internet connection appears to be offline" (ENETDOWN on the flow).
// sa_endpoints_t: sae_srcif (u32), sae_srcaddr, sae_srcaddrlen, sae_dstaddr, sae_dstaddrlen. A source address is bound
// first; the interface index (IP_BOUND_IF) is advisory here. Data passed with the call (TCP fast open / resume on
// read-write) is not sent: *len = 0 tells the caller none was written, and it writes it once connected.
struct bsd_sa_endpoints {
	unsigned int sae_srcif;
	const void* sae_srcaddr;
	unsigned int sae_srcaddrlen;
	const void* sae_dstaddr;
	unsigned int sae_dstaddrlen;
};

long sys_connectx(int fd, const void* endpoints, unsigned int associd, unsigned int flags, const void* iov,
		unsigned int iovcnt, unsigned long* len, unsigned int* connid)
{
	const struct bsd_sa_endpoints* ep = (const struct bsd_sa_endpoints*) endpoints;
	long ret;

	CANCELATION_POINT();
	if (!ep || !ep->sae_dstaddr || !ep->sae_dstaddrlen)
		return -EINVAL;
	if (len)
		*len = 0;
	if (ep->sae_srcaddr && ep->sae_srcaddrlen)
	{
		ret = sys_bind(fd, ep->sae_srcaddr, ep->sae_srcaddrlen);
		if (ret < 0)
			return ret;
	}
	ret = sys_connect_nocancel(fd, ep->sae_dstaddr, ep->sae_dstaddrlen);
	if (ret < 0)
		return ret;
	if (connid)
		*connid = 1;
	return 0;
}

// disconnectx (BSD 448), upstream Darling's: a stream connection is shut down, a datagram socket drops its peer
long sys_disconnectx(int fd, unsigned int associd, unsigned int connid)
{
	int type = 0, typelen = sizeof(type);
	long ret = sys_getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &typelen);
	if (ret < 0)
		return ret;

	// A stream connection is closed gracefully (FIN), as on macOS. Linux
	// aborts it with a reset when a TCP socket is connected to AF_UNSPEC.
	if (type == SOCK_STREAM)
	{
		ret = sys_shutdown(fd, SHUT_RDWR);
		return (ret < 0) ? ret : 0;
	}

	// Other sockets drop their peer address.
	struct sockaddr sa;
	__builtin_memset(&sa, 0, sizeof(sa));
	sa.sa_family = AF_UNSPEC;
	ret = sys_connect_nocancel(fd, &sa, sizeof(sa));
	return (ret < 0) ? ret : 0;
}
