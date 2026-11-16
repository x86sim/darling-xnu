#include <darling/emulation/xnu_syscall/bsd/impl/network/socket.h>

#include <sys/socket.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/misc/getrlimit.h>
#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/conversion/network/socket.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/nofile_limit.h>

long sys_socket(int domain, int type, int protocol)
{
	int ret;
	int linux_domain;

	switch (domain)
	{
		case PF_LOCAL:
			linux_domain = LINUX_PF_LOCAL; break;
		case PF_INET:
			linux_domain = LINUX_PF_INET; break;
		case PF_IPX:
			linux_domain = LINUX_PF_IPX; break;
		case PF_INET6:
			linux_domain = LINUX_PF_INET6; break;
		case PF_ROUTE:
			return route_socket_create(type, protocol);
		// a domain Darling has no sockets for (PF_SYSTEM's kernel controls and events, PF_NDRV, ...; XNU has them): the
		// answer socreate_internal() gives for a domain XNU lacks, EAFNOSUPPORT
		default:
			return -EAFNOSUPPORT;
	}

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SOCKET,
			((long[6]) { linux_domain, type, protocol }));
#else
	ret = LINUX_SYSCALL(__NR_socket, linux_domain, type, protocol);
#endif

	if (ret == -24 /*-EMFILE*/) {
		// DARLING arm64 fix: per-thread RPC sockets occupy fd 1021/1022/1023;
		// combined with the initial dyld-mmap'd dylib fds, a fresh Darwin
		// process already has all 1024 of its soft-limited fd slots taken,
		// so the very first user socket() call hits EMFILE. Raise the soft
		// limit to the hard limit (~512k in our container) and retry.
		// prlimit64 always takes 64-bit limits, also on i386.
		struct xnu_rlimit rlim;
		if (LINUX_SYSCALL(__NR_prlimit64, 0, LINUX_RLIMIT_NOFILE, 0, &rlim) == 0
			&& rlim.rlim_cur < rlim.rlim_max)
		{
			rlim.rlim_cur = rlim.rlim_max;
			LINUX_SYSCALL(__NR_prlimit64, 0, LINUX_RLIMIT_NOFILE, &rlim, 0);
		}

#ifdef __NR_socketcall
		ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SOCKET, ((long[6]){ linux_domain, type, protocol }));
#else
		ret = LINUX_SYSCALL(__NR_socket, linux_domain, type, protocol);
#endif
	}

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return nofile_limit_check_new(ret);
}

// x86Sim: socket_delegate (BSD 450): a socket whose traffic is attributed to another process (epid). iOS 27's
// Network.framework creates its flow sockets with it (NSURLSession in WebKit's Networking process, mobileassetd ...);
// without it no TCP socket was made and every request failed "offline". Attribution has no Linux meaning: a socket.
long sys_socket_delegate(int domain, int type, int protocol, int epid)
{
	(void) epid;
	return sys_socket(domain, type, protocol);
}
