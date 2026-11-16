/*
 * x86Sim: materialization of APFS dataless files and directories.
 *
 * File Provider keeps a replicated domain's items dataless (SF_DATALESS, no data; a directory whose children were never
 * enumerated) until something uses them. On a Mac, XNU then makes an upcall (vfs_syscalls.c resolve_nspace_item_ext:
 * filecoordinationd's port, nspace_resolve_path) and blocks the thread until the resolver completes it; for a simulator
 * the host's fileproviderd answers it by calling the materialization handler the simulator's fileproviderd registered
 * for the domain (sim2host sim_registerMaterializationHandler:forURL:, FPSimulatorMaterializationHandler
 * materializeURL:withInfo:completionHandler:). That is what lists a domain's root in an app ("NSFileCoordinator
 * requested ... to provide item ... kernelOperation: 0x1001" in Apple's fileproviderd log) and reads a file's
 * content. Here nothing ever faulted: a replicated domain's root listed empty forever and its extension never ran
 * (tests/apps/sdkcov func:FileProvider.replicated-extension-domain).
 *
 * Here: the dataless bit is a chflags flag (helper/misc/bsdflags.h; host/fpsim2host, the sim2host stand-in, sets and
 * clears it as APFS does). When a thread that materializes dataless files (XNU vfs_context_dataless_materialization_is_prevented:
 * its IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES policy, else its process's - launchd gives apps "dataless file mode"
 * through posix_spawnattr_setdataless_iopolicy_np - and not a dataless manipulator / resolver by entitlement) opens a
 * dataless object, or looks up a name in a dataless directory, the request (operation, pid, path) goes to fpsim2host
 * over the device's Unix socket /private/var/run/com.x86sim.nspace, which calls the domain's handler; the open waits
 * for its answer, as XNU's waits for vfs.nspace.complete. Deviations: the fault is taken at open (APFS faults a file on
 * read), and a thread that does not materialize reads a dataless file's zeros instead of failing EDEADLK. The object is
 * opened again once it is materialized: a Linux (btrfs) directory descriptor never returns entries added after it was
 * opened (a materialized directory listed empty), and the provider may have replaced a file.
 */
#include <darling/emulation/xnu_syscall/bsd/helper/misc/dataless.h>

#include <stdint.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/bsdflags.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/socket.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/connect.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getpid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/csops.h>

// BSD errno values (the emulation's functions return negative BSD errnos)
#define DL_EIO       5
#define DL_EINTR     4
#define DL_ETIMEDOUT 60

// bsd/sys/fsctl.h
#define NAMESPACE_HANDLER_READ_OP     0x0001
#define NAMESPACE_HANDLER_WRITE_OP    0x0002
#define NAMESPACE_HANDLER_TRUNCATE_OP 0x0008
#define NAMESPACE_HANDLER_NSPACE_EVENT 0x1000

#define BSD_O_ACCMODE 0x0003
#define BSD_O_TRUNC   0x0400
#define BSD_O_EVTONLY 0x8000

// the request and its answer (host/fpsim2host/fpsim2host.m has the same layout)
#define X86SIM_NSPACE_SOCKET "/private/var/run/com.x86sim.nspace"
#define X86SIM_NSPACE_MAGIC 0x3150534eu // "NSP1"
struct x86sim_nspace_request
{
	uint32_t magic;
	uint32_t op;       // NAMESPACE_HANDLER_*
	int32_t pid;       // the faulting process
	uint32_t reserved;
	char path[1024];   // the object, as the simulator sees it
};
struct x86sim_nspace_reply
{
	uint32_t magic;
	int32_t error;     // BSD errno, 0 = materialized
};

// how long an open waits for the resolver (XNU waits until it answers or the thread is interrupted)
#define X86SIM_NSPACE_TIMEOUT_MS (180 * 1000)

#define CS_OPS_ENTITLEMENTS_BLOB 7

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);
extern void* memset(void* s, int c, __SIZE_TYPE__ n);
extern int memcmp(const void* a, const void* b, __SIZE_TYPE__ n);
extern __SIZE_TYPE__ strlen(const char* s);

static int contains(const uint8_t* h, __SIZE_TYPE__ hl, const char* n)
{
	__SIZE_TYPE__ nl = strlen(n);
	for (__SIZE_TYPE__ i = 0; i + nl <= hl; i++)
		if (h[i] == (uint8_t) n[0] && memcmp(h + i, n, nl) == 0)
			return 1;
	return 0;
}

// XNU vfs_context_is_dataless_manipulator: such a process (fileproviderd, filecoordinationd) sees dataless objects as
// they are and never faults
static int is_dataless_manipulator(void)
{
	static int cached; // 0 unknown, 1 no, 2 yes
	if (cached)
		return cached == 2;
	int yes = 0;
	uint8_t hdr[8];
	long r = sys_csops(0, CS_OPS_ENTITLEMENTS_BLOB, hdr, sizeof(hdr));
	if (r == -34 /* ERANGE: the blob's length is in the header */)
	{
		uint32_t len = __builtin_bswap32(*(uint32_t*) (hdr + 4));
		if (len > 8 && len < (16u << 20))
		{
			long m = LINUX_SYSCALL(__NR_mmap, 0, len, 3 /* PROT_READ|WRITE */, 0x22 /* MAP_PRIVATE|ANONYMOUS */, -1, 0);
			if (m > 0 || m < -4095)
			{
				if (sys_csops(0, CS_OPS_ENTITLEMENTS_BLOB, (void*) m, len) == 0)
				{
					yes = contains((const uint8_t*) m, len, "com.apple.private.vfs.dataless-manipulation")
						|| contains((const uint8_t*) m, len, "com.apple.private.vfs.dataless-resolver");
				}
				LINUX_SYSCALL(__NR_munmap, m, len);
			}
		}
	}
	cached = yes ? 2 : 1;
	return yes;
}

// the upcall: 0 = materialized, else a negative BSD errno
static long resolve(const char* path, uint32_t op)
{
	struct { uint8_t len, family; char path[104]; } sun;
	struct x86sim_nspace_request req;
	struct x86sim_nspace_reply rep;
	long fd, r;

	memset(&req, 0, sizeof(req));
	req.magic = X86SIM_NSPACE_MAGIC;
	req.op = op;
	req.pid = (int32_t) sys_getpid();
	__SIZE_TYPE__ plen = strlen(path);
	if (plen >= sizeof(req.path))
		return -DL_EIO;
	memcpy(req.path, path, plen + 1);

	fd = sys_socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0);
	if (fd < 0)
		return -DL_ETIMEDOUT;
	LINUX_SYSCALL(__NR_fcntl, fd, 2 /* F_SETFD */, 1 /* FD_CLOEXEC */);
	memset(&sun, 0, sizeof(sun));
	sun.family = 1;
	memcpy(sun.path, X86SIM_NSPACE_SOCKET, sizeof(X86SIM_NSPACE_SOCKET));
	sun.len = (uint8_t) (2 + sizeof(X86SIM_NSPACE_SOCKET));
	// no resolver: as XNU without filecoordinationd's port ("unable to access the backing store server")
	if (sys_connect_nocancel(fd, &sun, sun.len) < 0)
	{
		sys_close_nocancel(fd);
		return -DL_ETIMEDOUT;
	}
	for (__SIZE_TYPE__ done = 0; done < sizeof(req);)
	{
		r = sys_write_nocancel(fd, (char*) &req + done, sizeof(req) - done);
		if (r == -DL_EINTR)
			continue;
		if (r <= 0)
		{
			sys_close_nocancel(fd);
			return -DL_EIO;
		}
		done += r;
	}
	long err = -DL_ETIMEDOUT;
	__SIZE_TYPE__ got = 0;
	int waited = 0;
	while (got < sizeof(rep) && waited < X86SIM_NSPACE_TIMEOUT_MS)
	{
		struct { int fd; short events, revents; } pfd = { (int) fd, 1 /* POLLIN */, 0 };
		r = LINUX_SYSCALL(__NR_poll, &pfd, 1, 1000);
		if (r == 0)
		{
			waited += 1000;
			continue;
		}
		if (r < 0)
		{
			if (r == -4 /* Linux EINTR */)
				continue;
			break;
		}
		r = sys_read_nocancel(fd, (char*) &rep + got, sizeof(rep) - got);
		if (r == -DL_EINTR)
			continue;
		if (r <= 0)
		{
			err = -DL_EIO; // the resolver went away
			break;
		}
		got += r;
	}
	sys_close_nocancel(fd);
	if (got == sizeof(rep) && rep.magic == X86SIM_NSPACE_MAGIC)
		err = rep.error > 0 ? -rep.error : 0;
	return err;
}

long x86sim_dataless_fault_fd(int lfd, int oflags)
{
	if (oflags & BSD_O_EVTONLY)
		return 0;
	if (!x86sim_dataless_policy_materializes())
		return 0;
	if (!(x86sim_bsdflags_get_fd(lfd) & X86SIM_SF_DATALESS))
		return 0;
	if (is_dataless_manipulator())
		return 0;

	struct linux_stat st;
	uint32_t op = NAMESPACE_HANDLER_READ_OP;
	if (LINUX_SYSCALL(__NR_fstat, lfd, &st) == 0 && (st.st_mode & 0170000) != 0040000)
	{
		if (oflags & BSD_O_TRUNC)
			op = NAMESPACE_HANDLER_TRUNCATE_OP;
		else if ((oflags & BSD_O_ACCMODE) != 0)
			op = NAMESPACE_HANDLER_WRITE_OP;
	}
	char path[1024];
	if (fdpath(lfd, path, sizeof(path)) < 0)
		return -DL_EIO;
	long e = resolve(path, op | NAMESPACE_HANDLER_NSPACE_EVENT);
	return e < 0 ? e : 1;
}

long x86sim_dataless_fault_parent(int ldfd, const char* lpath)
{
	if (!x86sim_dataless_policy_materializes())
		return 0;
	char parent[1100];
	__SIZE_TYPE__ n = strlen(lpath);
	if (n == 0 || n >= sizeof(parent))
		return 0;
	memcpy(parent, lpath, n + 1);
	while (n > 1 && parent[n - 1] == '/')
		parent[--n] = 0;
	while (n > 0 && parent[n - 1] != '/')
		n--;
	if (n == 0)
		parent[0] = '.', parent[1] = 0;      // a name in ldfd itself
	else
	{
		while (n > 1 && parent[n - 1] == '/')
			n--;
		parent[n] = 0;
	}
	if (!(x86sim_bsdflags_get_at(ldfd, parent, 0) & X86SIM_SF_DATALESS))
		return 0;
	if (is_dataless_manipulator())
		return 0;
	int pfd = LINUX_SYSCALL(__NR_openat, ldfd, parent, 010000000 /* O_PATH */ | 0200000 /* O_DIRECTORY */ | 02000000 /* O_CLOEXEC */, 0);
	if (pfd < 0)
		return 0;
	char path[1024];
	int r = fdpath(pfd, path, sizeof(path));
	LINUX_SYSCALL(__NR_close, pfd);
	if (r < 0)
		return 0;
	long e = resolve(path, NAMESPACE_HANDLER_READ_OP | NAMESPACE_HANDLER_NSPACE_EVENT);
	return e < 0 ? e : 1;
}
