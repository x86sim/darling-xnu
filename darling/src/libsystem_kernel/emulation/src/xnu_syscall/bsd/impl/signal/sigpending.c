#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigpending.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

// sigpending(sigset_t *set): the syscall's argument is the caller's set to fill in. This took the set by value (the
// pointer, truncated), converted it the wrong way round and never wrote the result back: sigpending() always reported
// the caller's unchanged (usually empty) set.
long sys_sigpending(sigset_t* set)
{
	linux_sigset_t set_linux = 0;
	int ret;

	ret = LINUX_SYSCALL(__NR_rt_sigpending, &set_linux, sizeof(set_linux));

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if (set != NULL)
		sigset_linux_to_bsd(&set_linux, set);

	return 0;
}
