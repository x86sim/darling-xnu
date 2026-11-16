#include <darling/emulation/xnu_syscall/bsd/impl/misc/setrlimit.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

long sys_setrlimit(unsigned int which, const struct xnu_rlimit* rlp)
{
	int ret;
	// Darwin's RLIM_INFINITY (2^63 - 1) as a finite Linux limit would make "unlimited" a hard limit that an
	// unprivileged process can never raise again.
	struct xnu_rlimit lim = { rlim_bsd_to_linux(rlp->rlim_cur), rlim_bsd_to_linux(rlp->rlim_max) };

	which = rlimit_bsd_to_linux(which);
	if (which == -1)
		return -EINVAL;

	if (which == LINUX_RLIMIT_NOFILE)
	{
		// x86Sim: mldr gives every thread its own darlingserver RPC socket and puts those at the top of the fd
		// range the process started with (socket_bitmap_get: down from the initial RLIMIT_NOFILE), and libkqueue's
		// and libdispatch's descriptors live up there too. A process that lowered its limit could then create no
		// thread (dup2 to the high fd fails; mldr aborts with "Failed to create socket": revisiond, which sets 1000).
		// A request below the current Linux limit is accepted and changes nothing, as the request that raises the
		// hard limit to RLIM_INFINITY (notifyd) already did (Linux refused it with EPERM and notifyd ignores that).
		struct xnu_rlimit cur;
		if (LINUX_SYSCALL(__NR_prlimit64, 0, which, 0, &cur) == 0 && rlp->rlim_cur + 1 < cur.rlim_cur)
			return rlp->rlim_cur > rlp->rlim_max ? -EINVAL : 0;
		if (lim.rlim_cur != LINUX_RLIM_INFINITY)
			lim.rlim_cur++;
		if (lim.rlim_max != LINUX_RLIM_INFINITY)
			lim.rlim_max++;
	}

	ret = LINUX_SYSCALL(__NR_prlimit64, 0, which, &lim, 0);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
