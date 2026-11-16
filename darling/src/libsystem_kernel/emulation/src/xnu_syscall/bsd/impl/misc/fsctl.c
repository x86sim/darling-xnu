#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsctl.h>

#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/access.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/fstat.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/bsdflags.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>


/*
 * x86Sim: fsctl (242) and ffsctl (245) were missing (ENOSYS). XNU passes them to the file system's VNOP_IOCTL, and
 * a request the file system doesn't know fails with ENOTTY. The ones the iOS simulator needs from APFS (it only runs
 * on APFS) are answered as APFS answers for a plain directory tree:
 * - _IOR('J', 74, uint64_t) (0x40084a4a): the id of the File Provider sync root enclosing the object, 0 for none.
 *   FileProvider's fpfs_fget_parent_syncroot() treats any error as fatal: the On My iPhone extension
 *   (LocalStorageFileProvider) then could not make an item for any file ("can't obtain VFSItem ... [78: Function not
 *   implemented]"), so Files could open no document. A directory is a sync root when the simulator's host made it
 *   one (sim2host sim_setSyncRoot: host/fpsim2host keeps the mark in the "com.apple.x86sim.syncroot" xattr); the id is
 *   its inode number (its file id). A replicated domain's root is one: without its id, fileproviderd ignored the
 *   items an app created in the domain (a new file never reached the extension's createItem).
 * - _IOR('J', 72, uint32_t) (0x40044a48): whether the directory itself is a sync root (FileProvider's
 *   fpfs_fget_syncroot).
 * - _IOW('J', 2, uint64_t) (0x80084a02): have APFS keep directory statistics for a directory (FileProvider's
 *   fpfs_pkg_enable_dirstat(), from fpfs_track_document() for every tracked item: the extension failed "can't obtain
 *   VFSItem ... [25: Inappropriate ioctl for device]"). Accepted and ignored.
 * - _IOWR('J', 32, 40 bytes) (0xc0284a20): read a directory's statistics: { u64 flags (in); then APFS's
 *   j_dir_stats_val_t: u64 num_children, total_size, chained_key, gen_count }, all recursive (FileProvider's
 *   fpfs_get_dirstat, fileproviderd's wharf and dataless-directory propagation: a replicated domain's dataless
 *   subdirectory failed create-item "Inappropriate ioctl for device" and never appeared in its parent). Computed by
 *   walking the tree (bounded): entries, the files' sizes, the directory's inode as key, and as generation a value
 *   that changes whenever anything below does (the newest ctime).
 * - FSIOC_CAS_BSDFLAGS (_IOWR('A', 20, struct fsioc_cas_bsdflags)): compare-and-swap of the chflags flags, kept in an
 *   extended attribute (helper/misc/bsdflags.h). As XNU: the actual flags are returned, and the new ones set only if
 *   they were the expected ones; it succeeds either way. FileProvider's libfssync sets UF_TRACKED with it.
 */
#define FSIOC_CAS_BSDFLAGS 0xc00c4114ul
struct fsioc_cas_bsdflags { uint32_t expected_flags, new_flags, actual_flags; };
#define APFSIOC_GET_PARENT_SYNCROOT 0x40084a4aul   // names ours; 'J' is APFS's ioctl group
#define APFSIOC_GET_SYNCROOT        0x40044a48ul
#define SYNCROOT_XATTR "user.com.apple.x86sim.syncroot"

// the Linux path of lpath (resolving /proc/self/fd/N), in buf
static int syncroot_realpath(const char* lpath, char* buf, int size)
{
	static const char procfd[] = "/proc/self/fd/";
	int isproc = 1;
	for (int i = 0; procfd[i]; i++)
		if (lpath[i] != procfd[i]) { isproc = 0; break; }
	if (lpath[0] == '/' && !isproc)
	{
		int n = __simple_strlen(lpath);
		if (n >= size)
			return -1;
		for (int i = 0; i <= n; i++)
			buf[i] = lpath[i];
		return n;
	}
	long n = LINUX_SYSCALL(__NR_readlink, lpath, buf, size - 1);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	return (int) n;
}

static int is_syncroot(const char* lpath)
{
	int32_t v = 0;
	return LINUX_SYSCALL(__NR_getxattr, lpath, SYNCROOT_XATTR, &v, sizeof(v)) > 0;
}

// the inode of the closest sync root above lpath (not lpath itself), 0 for none
static uint64_t parent_syncroot(const char* lpath)
{
	char buf[1100];
	int n = syncroot_realpath(lpath, buf, sizeof(buf));
	if (n <= 0 || buf[0] != '/')
		return 0;
	for (;;)
	{
		while (n > 1 && buf[n - 1] == '/')
			buf[--n] = 0;
		while (n > 0 && buf[n - 1] != '/')
			n--;
		if (n == 0)
			return 0;
		buf[n > 1 ? n - 1 : 1] = 0;
		n = n > 1 ? n - 1 : 1;
		if (is_syncroot(buf))
		{
			unsigned long st[18];
			return LINUX_SYSCALL(__NR_newfstatat, -100, buf, st, 0) == 0 ? st[1] : 0;
		}
		if (n == 1)
			return 0;
	}
}
#define APFSIOC_MAINTAIN_DIR_STATS  0x80084a02ul
#define APFSIOC_GET_DIR_STATS       0xc0284a20ul
struct apfs_dir_stats_req { uint64_t flags, num_children, total_size, chained_key, gen_count; };

#define DIRSTAT_MAX_DEPTH 32
#define DIRSTAT_MAX_ENTRIES 50000

// Linux struct stat (x86_64): st_ino at 8, st_mode at 24, st_size at 48, st_ctim at 104
static int dirstat_lstat(int dfd, const char* name, uint64_t* ino, uint32_t* mode, uint64_t* size, uint64_t* ctime_ns)
{
	unsigned long st[18];
	// the directory itself is often /proc/self/fd/N (ffsctl): followed; entries below it are not
	if (LINUX_SYSCALL(__NR_newfstatat, dfd, name, st, dfd == -100 ? 0 : 0x100 /* AT_SYMLINK_NOFOLLOW */) < 0)
		return -1;
	*ino = st[1];
	*mode = ((unsigned int*) st)[6];
	*size = st[6];
	*ctime_ns = st[13] * 1000000000ull + st[14];
	return 0;
}

static long dirstat_get(const char* lpath, struct apfs_dir_stats_req* req)
{
	uint64_t ino, size, ct;
	uint32_t mode;
	if (dirstat_lstat(-100, lpath, &ino, &mode, &size, &ct) < 0)
		return -ENOENT;
	if ((mode & 0170000) != 0040000)
		return -ENOTDIR;
	uint64_t children = 0, total = 0, newest = ct;
	int fds[DIRSTAT_MAX_DEPTH];
	int depth = 0;
	fds[0] = LINUX_SYSCALL(__NR_openat, -100, lpath, 0200000 /* O_DIRECTORY */ | 02000000 /* O_CLOEXEC */, 0);
	if (fds[0] < 0)
		return -EACCES;
	char buf[2048];
	while (depth >= 0)
	{
		long n = LINUX_SYSCALL(__NR_getdents64, fds[depth], buf, sizeof(buf));
		if (n <= 0)
		{
			LINUX_SYSCALL(__NR_close, fds[depth]);
			depth--;
			continue;
		}
		for (long off = 0; off < n;)
		{
			struct { uint64_t ino; int64_t off; unsigned short reclen; unsigned char type; char name[]; }* d = (void*) (buf + off);
			off += d->reclen;
			if (d->name[0] == '.' && (d->name[1] == 0 || (d->name[1] == '.' && d->name[2] == 0)))
				continue;
			if (dirstat_lstat(fds[depth], d->name, &ino, &mode, &size, &ct) < 0)
				continue;
			children++;
			if (ct > newest)
				newest = ct;
			if ((mode & 0170000) == 0100000)
				total += size;
			else if ((mode & 0170000) == 0040000 && depth + 1 < DIRSTAT_MAX_DEPTH && children < DIRSTAT_MAX_ENTRIES)
			{
				int sub = LINUX_SYSCALL(__NR_openat, fds[depth], d->name, 0200000 | 02000000 | 0400000 /* O_NOFOLLOW */, 0);
				if (sub >= 0)
				{
					// the rest of this buffer is read again later: rewind the parent to the next entry
					LINUX_SYSCALL(__NR_lseek, fds[depth], d->off, 0 /* SEEK_SET */);
					fds[++depth] = sub;
					break;
				}
			}
		}
	}
	req->num_children = children;
	req->total_size = total;
	req->chained_key = ino;
	if (dirstat_lstat(-100, lpath, &req->chained_key, &mode, &size, &ct) < 0)
		req->chained_key = 0;
	req->gen_count = newest ? newest : 1;
	return 0;
}

static long fsctl_common(unsigned long cmd, void* data, const char* lpath)
{
	switch (cmd & 0xffffffffu)
	{
		case APFSIOC_MAINTAIN_DIR_STATS:
			return 0;
		case APFSIOC_GET_DIR_STATS:
			if (!data)
				return -EFAULT;
			return dirstat_get(lpath, data);
		case FSIOC_CAS_BSDFLAGS:
		{
			struct fsioc_cas_bsdflags* cas = data;
			if (!cas)
				return -EFAULT;
			uint32_t cur = x86sim_bsdflags_get(lpath, 0);
			if (cur == cas->expected_flags && cur != cas->new_flags)
			{
				long r = x86sim_bsdflags_set(lpath, cas->new_flags);
				if (r < 0)
					return errno_linux_to_bsd(r);
			}
			cas->actual_flags = cur;
			return 0;
		}
		case APFSIOC_GET_PARENT_SYNCROOT:
			if (!data)
				return -EFAULT;
			*(uint64_t*) data = parent_syncroot(lpath);
			return 0;
		case APFSIOC_GET_SYNCROOT:
			if (!data)
				return -EFAULT;
			*(uint32_t*) data = is_syncroot(lpath);
			return 0;
		default:
		{
			// log each unknown request once (to stderr), as unsupported proc_info flavors are
			static unsigned long seen[16];
			unsigned int i;
			for (i = 0; i < 16 && seen[i] && seen[i] != cmd; i++);
			if (i < 16 && !seen[i])
			{
				seen[i] = cmd;
				__simple_printf("fsctl: unsupported request 0x%lx ('%c' %lu, %lu bytes)\n", cmd,
					(int) ((cmd >> 8) & 0xff), cmd & 0xff, (cmd >> 16) & 0x1fff);
			}
			return -ENOTTY;
		}
	}
}

long sys_fsctl(const char* path, unsigned long cmd, void* data, unsigned int options)
{
	long rv = sys_access(path, 0 /* F_OK */);
	if (rv < 0)
		return rv;
	struct vchroot_expand_args vc;
	vc.flags = VCHROOT_FOLLOW;
	vc.dfd = get_perthread_wd();
	strcpy(vc.path, path);
	rv = vchroot_expand(&vc);
	if (rv < 0)
		return errno_linux_to_bsd(rv);
	char buf[1100];
	const char* p = vc.path;
	if (vc.path[0] != '/' && vc.dfd != -100)
	{
		__simple_snprintf(buf, sizeof(buf), "/proc/self/fd/%d/%s", vc.dfd, vc.path);
		p = buf;
	}
	return fsctl_common(cmd, data, p);
}

long sys_ffsctl(int fd, unsigned long cmd, void* data, unsigned int options)
{
	uint64_t st[32];   // a Darwin struct stat64 (144 bytes); only whether fd is valid matters
	long rv = sys_fstat64(fd, (struct stat64*) st);
	if (rv < 0)
		return rv;
	char buf[32];
	return fsctl_common(cmd, data, x86sim_fd_path(fd, buf));
}
