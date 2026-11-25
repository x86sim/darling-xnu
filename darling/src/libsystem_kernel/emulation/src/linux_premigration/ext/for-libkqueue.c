#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>

#include <sys/errno.h>

#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/fcntl.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/linux_premigration/signal/sigexc.h>

#include <darlingserver/rpc.h>

int _dserver_rpc_kqchan_mach_port_open_4libkqueue(uint32_t port_name, void* receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags, int* out_socket) {
	return dserver_rpc_kqchan_mach_port_open(port_name, receive_buffer, receive_buffer_size, saved_filter_flags, out_socket);
};

int _dserver_rpc_kqchan_proc_open_4libkqueue(int32_t pid, uint32_t flags, int* out_socket) {
	return dserver_rpc_kqchan_proc_open(pid, flags, out_socket);
};

int _dup_4libkqueue(int fd) {
	int ret;

	// close-on-exec, as the other descriptors libkqueue makes are: a knote's copy must not keep the socket (or
	// file) open in a program this one execs
	ret = LINUX_SYSCALL3(__NR_fcntl, fd, LINUX_F_DUPFD_CLOEXEC, 0);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
};

// x86Sim: from willi/darling-xnu#8: EVFILT_SOCK's view of a socket (sostate.h)
int _socket_state_4libkqueue(int fd, struct socket_state_4libkqueue* state) {
	return socket_state(fd, state);
};

int _socket_error_4libkqueue(int fd, int linux_error) {
	return socket_error(fd, linux_error);
};

void _socket_watch_4libkqueue(int fd, int delta) {
	socket_watch(fd, delta);
};

void _socket_park_4libkqueue(int delta) {
	__atomic_add_fetch(&socket_parked, delta, __ATOMIC_SEQ_CST);
};

int _signal_watch_4libkqueue(int signum, int eventfd) {
	int linux_signum = signum_bsd_to_linux(signum);
	if (linux_signum <= 0)
		return -EINVAL;
	return sigexc_kqueue_watch(linux_signum, eventfd);
};

void _signal_unwatch_4libkqueue(int signum, int eventfd) {
	int linux_signum = signum_bsd_to_linux(signum);
	if (linux_signum > 0)
		sigexc_kqueue_unwatch(linux_signum, eventfd);
};
