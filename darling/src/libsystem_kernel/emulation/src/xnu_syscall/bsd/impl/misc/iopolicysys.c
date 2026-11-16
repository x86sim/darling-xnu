#include <darling/emulation/xnu_syscall/bsd/impl/misc/iopolicysys.h>

#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/tsd.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/dataless.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getpid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/mkdir.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/unlink.h>

/*
 * x86Sim: iopolicysys (322) keeps the policies it is given, per process and per thread, and GET returns them.
 * It used to return 0 without filling anything in, so getiopolicy_np() read back an uninitialized value.
 * NSFileCoordinator sets IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES to OFF for its thread around an accessor and
 * asserts that GET then says OFF ("materializationOffState == IOPOL_MATERIALIZE_DATALESS_FILES_OFF",
 * NSFileCoordinator.m:1002): News' widget extensions aborted there. Nothing here acts on a policy (Linux has no
 * dataless files, throttling tiers etc.); it is bookkeeping, as XNU's GET reports it. Policies are 4 bits per type
 * (types 0-15), packed into one word per scope: the thread's in a Darling TSD slot, the process's in a global.
 * x86Sim: except IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, which decides whether a thread faults dataless files in
 * (helper/misc/dataless.c). As XNU, the process's comes from its spawn attributes (posix_spawnattr_setdataless_iopolicy_np:
 * launchd gives apps "dataless file mode") and lasts across exec: the spawned child records it in
 * /private/var/run/x86sim-iopol/<pid> ("<policy> <Linux start time>", so a reused pid doesn't inherit it), read back
 * the first time the new image needs it (only ON is recorded); the process scope reads back ON or OFF (XNU
 * get_proc_materialize_policy).
 */
#define IOPOL_CMD_GET 0x00000001
#define IOPOL_CMD_SET 0x00000002
#define IOPOL_SCOPE_PROCESS   0
#define IOPOL_SCOPE_THREAD    1
#define IOPOL_SCOPE_DARWIN_BG 2

struct darling_iopol_param {
	int iop_scope;
	int iop_iotype;
	int iop_policy;
};


static volatile uint64_t process_policies;
static uint64_t darwin_bg_policies;

#define IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES 3
#define IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT 0
#define IOPOL_MATERIALIZE_DATALESS_FILES_OFF     1
#define IOPOL_MATERIALIZE_DATALESS_FILES_ON      2
#define DATALESS_SHIFT (IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES * 4)
#define DATALESS_DIR "/private/var/run/x86sim-iopol"

static void set_process_policy(int type, int policy)
{
	uint64_t old, new, mask = (uint64_t) 0xf << (type * 4);
	do {
		old = process_policies;
		new = (old & ~mask) | ((uint64_t) policy << (type * 4));
	} while (!__sync_bool_compare_and_swap(&process_policies, old, new));
}

// this process's start time (/proc/self/stat field 22): unchanged by exec, different for a later process with the pid
static unsigned long long proc_starttime(void)
{
	char buf[512];
	int fd = LINUX_SYSCALL(__NR_openat, -100, "/proc/self/stat", 0, 0);
	if (fd < 0)
		return 0;
	long n = LINUX_SYSCALL(__NR_read, fd, buf, sizeof(buf) - 1);
	LINUX_SYSCALL(__NR_close, fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	const char* p = buf + n;
	while (p > buf && *p != ')')
		p--;
	if (*p != ')')
		return 0;
	p++;
	for (int field = 3; field < 22 && *p; field++) // skip fields 3 (state) .. 21: field 22 is starttime
	{
		while (*p == ' ')
			p++;
		while (*p && *p != ' ')
			p++;
	}
	while (*p == ' ')
		p++;
	unsigned long long v = 0;
	while (*p >= '0' && *p <= '9')
		v = v * 10 + (unsigned) (*p++ - '0');
	return v;
}

static void dataless_record_path(char* path)
{
	__simple_sprintf(path, DATALESS_DIR "/%d", (int) sys_getpid());
}

static volatile int dataless_loaded;

static void dataless_load(void)
{
	char path[96], buf[64];
	dataless_loaded = 1;
	dataless_record_path(path);
	long fd = sys_openat(-2 /* AT_FDCWD */, path, 0 /* O_RDONLY */, 0);
	if (fd < 0)
		return;
	long n = sys_read(fd, buf, sizeof(buf) - 1);
	sys_close(fd);
	if (n <= 0)
		return;
	buf[n] = 0;
	const char* p = buf;
	int policy = 0;
	while (*p >= '0' && *p <= '9')
		policy = policy * 10 + (*p++ - '0');
	while (*p == ' ')
		p++;
	unsigned long long st = 0;
	while (*p >= '0' && *p <= '9')
		st = st * 10 + (unsigned) (*p++ - '0');
	if (st != proc_starttime() || policy < 0 || policy > IOPOL_MATERIALIZE_DATALESS_FILES_ON)
		return;
	// a policy the process set itself since wins
	if (((process_policies >> DATALESS_SHIFT) & 0xf) == 0)
		set_process_policy(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, policy);
}

void x86sim_dataless_spawned(int policy)
{
	char path[96], buf[64];
	set_process_policy(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, policy);
	dataless_loaded = 1;
	dataless_record_path(path);
	// only ON needs a record (the default materializes nothing); an earlier image's one goes
	if (policy != IOPOL_MATERIALIZE_DATALESS_FILES_ON)
	{
		sys_unlink(path);
		return;
	}
	long fd = sys_openat(-2, path, 0x1 | 0x200 | 0x400 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
	if (fd == -2 /* ENOENT: no directory yet */)
	{
		sys_mkdir(DATALESS_DIR, 0777);
		fd = sys_openat(-2, path, 0x1 | 0x200 | 0x400, 0644);
	}
	if (fd < 0)
		return;
	__simple_sprintf(buf, "%d %llu\n", policy, proc_starttime());
	sys_write(fd, buf, __simple_strlen(buf));
	sys_close(fd);
}

// XNU vfs_context_dataless_materialization_is_prevented, less the entitlement (helper/misc/dataless.c checks it)
int x86sim_dataless_policy_materializes(void)
{
	uint64_t word = (uint64_t) _pthread_getspecific_direct(__PTK_DARLING_IOPOL);
	int t = (int) ((word >> DATALESS_SHIFT) & 0xf);
	if (t == IOPOL_MATERIALIZE_DATALESS_FILES_OFF)
		return 0;
	if (t == IOPOL_MATERIALIZE_DATALESS_FILES_ON)
		return 1;
	if (!dataless_loaded)
		dataless_load();
	return ((process_policies >> DATALESS_SHIFT) & 0xf) == IOPOL_MATERIALIZE_DATALESS_FILES_ON;
}

long sys_iopolicysys(int cmd, void* arg)
{
	struct darling_iopol_param* p = (struct darling_iopol_param*) arg;
	uint64_t word, mask;
	int shift;

	if (p == NULL)
		return -EFAULT;
	if (cmd != IOPOL_CMD_GET && cmd != IOPOL_CMD_SET)
		return -EINVAL;
	if (p->iop_iotype < 0 || p->iop_iotype > 15)
		return -EINVAL;
	if (p->iop_scope != IOPOL_SCOPE_PROCESS && p->iop_scope != IOPOL_SCOPE_THREAD && p->iop_scope != IOPOL_SCOPE_DARWIN_BG)
		return -EINVAL;
	if (cmd == IOPOL_CMD_SET && (p->iop_policy < 0 || p->iop_policy > 15))
		return -EINVAL;

	shift = p->iop_iotype * 4;
	mask = (uint64_t) 0xf << shift;

	switch (p->iop_scope) {
	case IOPOL_SCOPE_THREAD:
		word = (uint64_t) _pthread_getspecific_direct(__PTK_DARLING_IOPOL);
		if (cmd == IOPOL_CMD_GET)
			p->iop_policy = (int) ((word & mask) >> shift);
		else
			_pthread_setspecific_direct(__PTK_DARLING_IOPOL, (void*) ((word & ~mask) | ((uint64_t) p->iop_policy << shift)));
		break;
	case IOPOL_SCOPE_PROCESS:
		if (cmd == IOPOL_CMD_GET && p->iop_iotype == IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES) {
			if (!dataless_loaded)
				dataless_load();
			p->iop_policy = ((process_policies & mask) >> shift) == IOPOL_MATERIALIZE_DATALESS_FILES_ON
				? IOPOL_MATERIALIZE_DATALESS_FILES_ON : IOPOL_MATERIALIZE_DATALESS_FILES_OFF;
		} else if (cmd == IOPOL_CMD_GET)
			p->iop_policy = (int) ((process_policies & mask) >> shift);
		else {
			uint64_t old, new;
			do {
				old = process_policies;
				new = (old & ~mask) | ((uint64_t) p->iop_policy << shift);
			} while (!__sync_bool_compare_and_swap(&process_policies, old, new));
		}
		break;
	default: /* IOPOL_SCOPE_DARWIN_BG */
		if (cmd == IOPOL_CMD_GET)
			p->iop_policy = (int) ((darwin_bg_policies & mask) >> shift);
		else
			darwin_bg_policies = (darwin_bg_policies & ~mask) | ((uint64_t) p->iop_policy << shift);
		break;
	}
	return 0;
}
