#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>

#include <sys/fcntl.h>

#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/dataless.h> // x86Sim
#include <darling/emulation/xnu_syscall/bsd/helper/misc/nofile_limit.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bpf/bpf_device.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsgetpath.h> // x86Sim: /.vol

#include <darlingserver/rpc.h>

#ifndef O_NOFOLLOW
#	define O_NOFOLLOW 0x0100
#endif
#ifndef O_CLOEXEC
#	define O_CLOEXEC 0x1000000
#endif
#ifndef O_DIRECTORY
#	define O_DIRECTORY 0x100000
#endif

extern int strcmp(const char *s1, const char *s2);
extern char* strcpy(char* dst, const char* src);

// x86Sim: O_SYMLINK opens the object itself; on XNU that only differs from a plain open when the object is a
// symlink. The O_PATH descriptor we need for a symlink can't be read, have its xattrs read (EBADF) and so on, so a
// regular file or directory is reopened through /proc/self/fd with the access asked for (O_PATH kept if that
// fails, e.g. EACCES or a directory opened for writing). FileProvider opens every item with O_SYMLINK
// (fpfs_openat) and then reads its attributes and xattrs: the On My iPhone extension failed "can't obtain VFSItem
// ... [9: Bad file descriptor]" for every file, and Files could not open a document.
#ifndef LINUX_O_PATH
#	define LINUX_O_PATH 010000000
#endif
static int reopen_non_symlink(int pfd, int linux_flags)
{
	unsigned long st[18]; // Linux x86_64 struct stat (144 bytes); st_mode is the u32 at offset 24
	if (LINUX_SYSCALL(__NR_fstat, pfd, st) < 0)
		return pfd;
	unsigned int fmt = ((unsigned int*) st)[6] & 0170000;
	if (fmt != 0100000 && fmt != 0040000) // S_IFREG, S_IFDIR
		return pfd;
	char path[32];
	__simple_sprintf(path, "/proc/self/fd/%d", pfd);
	int nfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, path, linux_flags & ~(LINUX_O_PATH | LINUX_O_NOFOLLOW), 0);
	if (nfd < 0)
		return pfd;
	LINUX_SYSCALL(__NR_close, pfd); // never seen by the caller
	return nfd;
}

long sys_openat(int fd, const char* filename, int flags, unsigned int mode)
{
	CANCELATION_POINT();
	return sys_openat_common(fd, filename, flags, mode, true);
}

long sys_openat_nocancel(int fd, const char* filename, int flags, unsigned int mode)
{
	return sys_openat_common(fd, filename, flags, mode, false);
}

long sys_openat_common(int fd, const char* filename, int flags, unsigned int mode, bool cancelable)
{
	int ret, linux_flags;
	if (!filename)
		return -EFAULT;

	linux_flags = oflags_bsd_to_linux(flags);

	if (sizeof(void*) == 4)
	{
		linux_flags |= LINUX_O_LARGEFILE;
	}

	// XNU /dev/random behaves like Linux /dev/urandom
	if (strcmp(filename, "/dev/random") == 0)
		filename = "/dev/urandom";
	// Expected by launchd and CF
	else if (strcmp(filename, "/dev/autofs_nowait") == 0)
		filename = "/dev/null";
	else if (strcmp(filename, "/dev/console") == 0) {
		// redirect console output to darlingserver
		int err = dserver_rpc_console_open(&ret);
		if (err < 0) {
			__simple_printf("dserver_rpc_console_open failed internally: %d", err);
			__simple_abort();
		}
		if (err > 0) {
			ret = errno_linux_to_bsd(-err);
		}
		return nofile_limit_check_new(ret);
	}

	// x86Sim: volfs. XNU opens "/.vol/<fsid>/<object id>[/name...]" by id (the volume's fsid as a decimal, the
	// object's file id); Linux has no such tree. Resolved like fsgetpath (the ids this prefix has handed out), then
	// opened by path. FileProvider's fileproviderd opens the items it tracks that way when the sim2host host speaks
	// protocol version 1, as Apple's Mac does (fpsim2host)
	char volpath[1024];
	if (filename[0] == '/' && filename[1] == '.' && filename[2] == 'v' && filename[3] == 'o' && filename[4] == 'l' && filename[5] == '/')
	{
		const char* p = filename + 6;
		unsigned long long fsidv = 0, objid = 0;
		int nd = 0;
		while (*p >= '0' && *p <= '9') { fsidv = fsidv * 10 + (*p++ - '0'); nd++; }
		if (!nd || *p != '/')
			return -ENOENT;
		p++; nd = 0;
		while (*p >= '0' && *p <= '9') { objid = objid * 10 + (*p++ - '0'); nd++; }
		if (!nd || (*p && *p != '/'))
			return -ENOENT;
		int fsid[2] = { (int) fsidv, 0 };
		long r = sys_fsgetpath(volpath, sizeof(volpath), fsid, objid);
		if (r < 0)
			return r;
		__SIZE_TYPE__ len = __simple_strlen(volpath), rest = __simple_strlen(p);
		if (len + rest + 1 > sizeof(volpath))
			return -ENAMETOOLONG;
		for (__SIZE_TYPE__ i = 0; i <= rest; i++)
			volpath[len + i] = p[i];
		filename = volpath;
	}

	struct vchroot_expand_args vc;
	vc.flags = (flags & BSD_O_SYMLINK || flags & BSD_O_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	strcpy(vc.path, filename);
	ret = vchroot_expand(&vc);
	if (ret < 0) {
		return errno_linux_to_bsd(ret);
	}

	// /dev/bpfN has no Linux counterpart; it is emulated on packet sockets.
	int bpf_minor = bpf_device_minor(vc.path);
	if (bpf_minor >= 0)
		return bpf_device_open(bpf_minor, flags);

	// when we're given O_SYMLINK, `oflags_bsd_to_linux` translates it into
	// O_NOFOLLOW and O_PATH
	// this is the only way to open the symlink itself on Linux
	// unfortunately, this presents additional challenges
	// only a select few Linux syscalls support O_PATH descriptors, which means
	// that for other syscalls, we either have to check for this and use an
	// `l` variant (e.g. `llistxattr` instead of `listxatrr`) or we're screwed

	ret = LINUX_SYSCALL_C(cancelable, __NR_openat, vc.dfd, vc.path, linux_flags, mode);
	// x86Sim: a name looked up in a dataless directory makes it materialize first (helper/misc/dataless.c)
	if (ret == -2 /* Linux ENOENT */ && x86sim_dataless_fault_parent(vc.dfd, vc.path) == 1)
		ret = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path, linux_flags, mode);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else if (linux_flags & LINUX_O_PATH)
		ret = reopen_non_symlink(ret, linux_flags);

	// x86Sim: opening a dataless file or directory materializes it, and then it is opened again: the descriptor of a
	// directory would not see the entries materialization added (helper/misc/dataless.c)
	if (ret >= 0)
	{
		long err = x86sim_dataless_fault_fd(ret, flags);
		if (err != 0)
		{
			LINUX_SYSCALL(__NR_close, ret);
			ret = err;
		}
		if (err == 1)
		{
			ret = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path, linux_flags & ~(LINUX_O_CREAT | LINUX_O_EXCL | LINUX_O_TRUNC), mode);
			if (ret < 0)
				ret = errno_linux_to_bsd(ret);
			else if (linux_flags & LINUX_O_PATH)
				ret = reopen_non_symlink(ret, linux_flags);
		}
	}

	return nofile_limit_check_new(ret);
}
