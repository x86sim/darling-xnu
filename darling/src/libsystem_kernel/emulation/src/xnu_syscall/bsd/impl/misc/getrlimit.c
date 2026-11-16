#include <darling/emulation/xnu_syscall/bsd/impl/misc/getrlimit.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

long sys_getrlimit(unsigned int which, struct xnu_rlimit* rlp)
{
	int ret;

	which = rlimit_bsd_to_linux(which);
	if (which == -1)
		return -EINVAL;

	ret = LINUX_SYSCALL(__NR_prlimit64, 0, which, 0, rlp);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if (rlp == NULL)
		return ret;

	if (which == LINUX_RLIMIT_NOFILE)
	{
		rlp->rlim_cur--;
		rlp->rlim_max--;
	}

	// Linux's RLIM_INFINITY (~0) never equals Darwin's, and a guest casting it to int64_t sees -1 (Chromium's
	// gin::IsolateHolder checked_cast traps on it).
	rlp->rlim_cur = rlim_linux_to_bsd(rlp->rlim_cur);
	rlp->rlim_max = rlim_linux_to_bsd(rlp->rlim_max);

	return ret;
}

unsigned int rlimit_bsd_to_linux(unsigned int which)
{
	which &= ~BSD_RLIMIT_POSIX;

	switch (which)
	{
		case BSD_RLIMIT_CPU:
			return LINUX_RLIMIT_CPU;
		case BSD_RLIMIT_FSIZE:
			return LINUX_RLIMIT_FSIZE;
		case BSD_RLIMIT_DATA:
			return LINUX_RLIMIT_DATA;
		case BSD_RLIMIT_STACK:
			return LINUX_RLIMIT_STACK;
		case BSD_RLIMIT_CORE:
			return LINUX_RLIMIT_CORE;
		case BSD_RLIMIT_AS:
			return LINUX_RLIMIT_AS;
		case BSD_RLIMIT_MEMLOCK:
			return LINUX_RLIMIT_MEMLOCK;
		case BSD_RLIMIT_NPROC:
			return LINUX_RLIMIT_NPROC;
		case BSD_RLIMIT_NOFILE:
			return LINUX_RLIMIT_NOFILE;
		default:
			return -1;
	}
}
