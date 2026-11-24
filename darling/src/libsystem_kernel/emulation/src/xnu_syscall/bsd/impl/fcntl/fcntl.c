#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>
#include <darling/emulation/common/dc_image_snapshot.h>

#include <sys/errno.h>
#include <sys/fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/fcntl/fcntl.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>
#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/socktables.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/nofile_limit.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bpf/bpf_device.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/nosigpipe.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/csops.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/fstat.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/pread.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>

#include <darlingserver/rpc.h>

#ifndef O_NOFOLLOW
#   define O_NOFOLLOW 0x0100
#endif
#ifndef O_DIRECTORY
#   define O_DIRECTORY 0x100000
#endif
#ifndef MAXPATHLEN
#	define MAXPATHLEN 1024
#endif

int oflags_bsd_to_linux(int flags);
int oflags_linux_to_bsd(int flags);

extern int sprintf(char *str, const char *format, ...);
long sys_readlink(const char* path, char* buf, unsigned long bsize);

static short int flock_type_linux_to_bsd(short int linux) {
	switch (linux) {
		case LINUX_F_RDLCK: return F_RDLCK;
		case LINUX_F_WRLCK: return F_WRLCK;
		case LINUX_F_UNLCK: return F_UNLCK;
		default:            return -1;
	};
};

static short int flock_type_bsd_to_linux(short int bsd) {
	switch (bsd) {
		case F_RDLCK: return LINUX_F_RDLCK;
		case F_WRLCK: return LINUX_F_WRLCK;
		case F_UNLCK: return LINUX_F_UNLCK;
		default:      return -1;
	};
};

static int cmd_bsd_to_linux(int bsd) {
	switch (bsd) {
		case F_DUPFD:  return LINUX_F_DUPFD;
		case F_GETFD:  return LINUX_F_GETFD;
		case F_SETFD:  return LINUX_F_SETFD;
		case F_GETFL:  return LINUX_F_GETFL;
		case F_SETFL:  return LINUX_F_SETFL;
		case F_GETOWN: return LINUX_F_GETOWN;
		case F_SETOWN: return LINUX_F_SETOWN;
		case F_SETLK:  return LINUX_F_SETLK;
		case F_SETLKW: return LINUX_F_SETLKW;
		case F_GETLK:  return LINUX_F_GETLK;
		case F_DUPFD_CLOEXEC: return LINUX_F_DUPFD_CLOEXEC;
		// x86Sim: open file description locks. Apple's SQLite probes F_OFD_GETLK to pick its
		// locking style; EINVAL made it fall back to dot-file locking (a <db>.lock directory),
		// which goes stale when a process dies and then reports "database is locked" forever.
		case 90: return 37; // F_OFD_SETLK  -> LINUX_F_OFD_SETLK
		case 91: return 38; // F_OFD_SETLKW -> LINUX_F_OFD_SETLKW
		case 92: return 36; // F_OFD_GETLK  -> LINUX_F_OFD_GETLK
		default:       return -1;
	};
};

// x86Sim: F_SETLKWTIMEOUT (10) / F_OFD_SETLKWTIMEOUT (93): F_SETLKW / F_OFD_SETLKW that give up
// with ETIMEDOUT after a timeout (XNU lf_setlock). Linux has no timed locks: retry the
// non-blocking F_SETLK / F_OFD_SETLK until the lock is granted or the timeout passes.
// Apple's SQLite uses these whenever a busy timeout is set (unixFileLock, for the database
// and -shm locks); the EINVAL we returned became SQLITE_BUSY ("database is locked") at once,
// without any lock contention (SpringBoard: applicationState.db, ATX stores -> _exit(3)).
struct bsd_flocktimeout {
	struct bsd_flock fl;
	struct { long tv_sec; long tv_nsec; } timeout;
};

static long fcntl_lock_timeout(int fd, int cmd, struct bsd_flocktimeout* ft)
{
	struct linux_flock lf;
	struct { long tv_sec; long tv_nsec; } now, end, nap;
	int linux_cmd = (cmd == 93) ? 37 /* LINUX_F_OFD_SETLK */ : LINUX_F_SETLK;
	long ret, wait_ns = 1000000;

	lf.l_type = flock_type_bsd_to_linux(ft->fl.l_type);
	lf.l_whence = ft->fl.l_whence;
	lf.l_start = ft->fl.l_start;
	lf.l_len = ft->fl.l_len;
	lf.l_pid = 0;

	LINUX_SYSCALL(__NR_clock_gettime, 1 /* CLOCK_MONOTONIC */, &end);
	end.tv_sec += ft->timeout.tv_sec;
	end.tv_nsec += ft->timeout.tv_nsec;
	while (end.tv_nsec >= 1000000000) { end.tv_sec++; end.tv_nsec -= 1000000000; }

	for (;;)
	{
#ifdef __NR_fcntl64
		ret = LINUX_SYSCALL(__NR_fcntl64, fd, linux_cmd, &lf);
#else
		ret = LINUX_SYSCALL(__NR_fcntl, fd, linux_cmd, &lf);
#endif
		if (ret >= 0)
			return ret;
		if (ret != -LINUX_EAGAIN && ret != -LINUX_EACCES)
			return errno_linux_to_bsd(ret);

		LINUX_SYSCALL(__NR_clock_gettime, 1, &now);
		long left = (end.tv_sec - now.tv_sec) * 1000000000L + (end.tv_nsec - now.tv_nsec);
		if (left <= 0)
			return -ETIMEDOUT;

		if (wait_ns > left)
			wait_ns = left;
		nap.tv_sec = wait_ns / 1000000000L;
		nap.tv_nsec = wait_ns % 1000000000L;
		LINUX_SYSCALL(__NR_nanosleep, &nap, 0);
		if (wait_ns < 10000000)
			wait_ns *= 2;
	}
}

// F_ADDFILESIGS, F_ADDFILESIGS_RETURN: darlingserver reads the signature of
// the Mach-O image at `fs_file_start` itself. Only a policy that enforces
// code signing refuses an image whose signature is not valid; otherwise
// nothing is refused, and an image without a valid signature covers nothing.
__attribute__((unused)) static long add_file_signatures(int fd, int cmd, fsignatures_t* signatures)
{
	uint32_t status = 0, flags = 0, page_size_log2 = 0;
	uint64_t code_limit = 0;
	bool library_validation_ok = false;
	off_t end = 0;
	int ret;

	if (signatures == NULL)
		return -EFAULT;

	ret = dserver_rpc_cs_verify_image(fd, (uint64_t)signatures->fs_file_start,
		&status, &flags, &code_limit, &page_size_log2, &library_validation_ok);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if (status == dserver_cs_status_valid) {
		// the signed range ends at the code limit, rounded up to a hash page
		uint64_t page_mask = (page_size_log2 > 0 && page_size_log2 < 32) ? (1ull << page_size_log2) - 1 : 0;
		end = (off_t)((code_limit + page_mask) & ~page_mask);
	} else if (cs_own_policy() == dserver_code_signing_policy_enforce) {
		return -EBADEXEC;
	}

	if (cmd == F_ADDFILESIGS_RETURN)
		signatures->fs_file_start = end;

	return 0;
}

// F_CHECK_LV: whether the calling process's library validation accepts the
// image. Library validation refuses nothing unless the policy enforces code
// signing, so only then is darlingserver asked.
static long check_library_validation(int fd, fchecklv_t* check)
{
	static const char message[] = "library validation refused the image: it is neither a platform binary nor signed by the same team";
	uint32_t status = 0, flags = 0, page_size_log2 = 0;
	uint64_t code_limit = 0;
	bool library_validation_ok = false;
	int ret;

	if (check == NULL)
		return -EFAULT;
	if (cs_own_policy() != dserver_code_signing_policy_enforce)
		return 0;

	ret = dserver_rpc_cs_verify_image(fd, (uint64_t)check->lv_file_start,
		&status, &flags, &code_limit, &page_size_log2, &library_validation_ok);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	if (library_validation_ok)
		return 0;

	if (check->lv_error_message != NULL && check->lv_error_message_size > 0) {
		size_t length = sizeof(message) - 1;
		if (length >= check->lv_error_message_size)
			length = check->lv_error_message_size - 1;
		memcpy(check->lv_error_message, message, length);
		((char*)check->lv_error_message)[length] = '\0';
	}
	return -EPERM;
}

// QUIRK: F_GETPROTECTIONCLASS and F_SETPROTECTIONCLASS. Linux files have
// no data protection class, so report what macOS reports for a file whose
// class was never set: class C (3) for a regular file
// and 0 for a directory; ENOTSUP for a device and EBADF for a descriptor
// that is not a vnode (pipe, socket). F_SETPROTECTIONCLASS accepts classes
// 1 to 4 and fails with EPERM for 6 and 7 and EINVAL for anything else;
// the class is not stored. Not documented. Evidence: black-box observation
// on macOS 27.0.1, arm64 and x86_64 under Rosetta (tier 2). Test:
// the protection class checks in syscall-small-fixes.c (guest test).
static long protection_class(int fd, int cmd, int pclass)
{
	darling_stat64_t st;
	long ret;

	ret = sys_fstat64(fd, &st);
	if (ret < 0)
		return ret;

	switch (st.st_mode & S_IFMT)
	{
		case S_IFREG:
		case S_IFDIR:
			break;
		case S_IFCHR:
		case S_IFBLK:
			return -ENOTSUP;
		default:
			return -EBADF;
	}

	if (cmd == F_GETPROTECTIONCLASS)
		return ((st.st_mode & S_IFMT) == S_IFDIR) ? 0 : 3;

	if (pclass >= 1 && pclass <= 4)
		return 0;
	if (pclass == 6 || pclass == 7)
		return -EPERM;
	return -EINVAL;
}

// DC_F_SNAPSHOT_IMAGE (see dc_image_snapshot.h)
static long snapshot_image(int fd)
{
	static const char name[] = "darling-image-snapshot";
	char buffer[16384];
	// sys_fstat fills the legacy (32-bit inode) layout of the fstat system call,
	// which is not the struct stat this file is compiled with; stat64 is unambiguous
	darling_stat64_t st;
	long snapshot, ret;
	unsigned long long offset = 0;

	ret = sys_fstat64(fd, &st);
	if (ret < 0)
		return ret;
	if ((st.st_mode & S_IFMT) != S_IFREG || st.st_size <= 0)
		return -EINVAL;
	if ((unsigned long long)st.st_size > DC_SNAPSHOT_IMAGE_MAX)
		return -EFBIG;

	snapshot = LINUX_SYSCALL(__NR_memfd_create, name, LINUX_MFD_CLOEXEC | LINUX_MFD_ALLOW_SEALING);
	if (snapshot < 0)
		return errno_linux_to_bsd(snapshot);
	snapshot = nofile_limit_check_new(snapshot);
	if (snapshot < 0)
		return snapshot;

	while (offset < (unsigned long long)st.st_size) {
		unsigned long long left = (unsigned long long)st.st_size - offset;
		long got, written = 0;

		got = sys_pread_nocancel(fd, buffer, left < sizeof(buffer) ? (int)left : (int)sizeof(buffer), (long long)offset);
		if (got == -EINTR)
			continue;
		if (got <= 0) {
			// the file became shorter while it was copied
			ret = (got < 0) ? got : -EIO;
			goto fail;
		}

		while (written < got) {
			long put = sys_write_nocancel(snapshot, buffer + written, (int)(got - written));
			if (put == -EINTR)
				continue;
			if (put <= 0) {
				ret = (put < 0) ? put : -EIO;
				goto fail;
			}
			written += put;
		}

		offset += (unsigned long long)got;
	}

#ifdef __NR_fcntl64
	ret = LINUX_SYSCALL(__NR_fcntl64, snapshot, LINUX_F_ADD_SEALS,
#else
	ret = LINUX_SYSCALL(__NR_fcntl, snapshot, LINUX_F_ADD_SEALS,
#endif
		LINUX_F_SEAL_SEAL | LINUX_F_SEAL_SHRINK | LINUX_F_SEAL_GROW | LINUX_F_SEAL_WRITE);
	if (ret < 0) {
		ret = errno_linux_to_bsd(ret);
		goto fail;
	}

	return snapshot;

fail:
	sys_close_nocancel(snapshot);
	return ret;
}

static long sys_fcntl_common(int fd, int cmd, long arg, bool cancelable);

long sys_fcntl(int fd, int cmd, long arg)
{
	CANCELATION_POINT();
	return sys_fcntl_common(fd, cmd, arg, true);
}

long sys_fcntl_nocancel(int fd, int cmd, long arg)
{
	return sys_fcntl_common(fd, cmd, arg, false);
}

static long sys_fcntl_common(int fd, int cmd, long arg, bool cancelable)
{
	int ret, linux_cmd = cmd_bsd_to_linux(cmd);
	long original_arg = arg;

	switch (cmd)
	{
		// x86Sim: F_ADDFILESIGS / F_ADDFILESIGS_RETURN are answered below without asking darlingserver (upstream's
		// add_file_signatures() verifies every image dyld registers, an RPC and a signature parse per image load)
		case F_CHECK_LV:
			return check_library_validation(fd, (fchecklv_t*)arg);
		case DC_F_SNAPSHOT_IMAGE:
			return snapshot_image(fd);
		case 10: // x86Sim: F_SETLKWTIMEOUT
		case 93: // x86Sim: F_OFD_SETLKWTIMEOUT
			return fcntl_lock_timeout(fd, cmd, (struct bsd_flocktimeout*) arg);
		// No code signing enforcement: accept signature registration (dyld_sim needs F_ADDFILESIGS_FOR_DYLD_SIM)
		case F_ADDFILESIGS:
		case F_ADDFILESIGS_RETURN:
		case F_ADDFILESIGS_FOR_DYLD_SIM:
		{
			// Like XNU, report the end of the signed range in fs_file_start;
			// claim everything up to the signature blob itself is covered
			fsignatures_t* sigs = (fsignatures_t*) arg;
			sigs->fs_file_start += (off_t)(uintptr_t) sigs->fs_blob_start;
			return 0;
		}
		case F_SETFD:
			if (arg & ~FD_CLOEXEC)
				return -EINVAL;
			break;
		case F_SETFL:
			arg = oflags_bsd_to_linux(arg);
			break;
		case F_DUPFD:
		case F_DUPFD_CLOEXEC:
			// fcntl(2): EINVAL for a minimum beyond the descriptor limit
			if (arg >= 0 && arg <= INT_MAX && nofile_limit_exceeded((int)arg))
				return -EINVAL;
			break;
		case F_GETPATH:
		{
			ret = fdpath(fd, arg, MAXPATHLEN);
			if (ret < 0)
				return errno_linux_to_bsd(ret);

			return 0;
		}
		case F_SETLK:
		case F_SETLKW:
		case F_GETLK:
		case 90: case 91: case 92: { // x86Sim: F_OFD_SETLK/SETLKW/GETLK
			struct bsd_flock* bsd_struct = arg;
			struct linux_flock* linux_struct = __builtin_alloca(sizeof(struct linux_flock));
			linux_struct->l_type = flock_type_bsd_to_linux(bsd_struct->l_type);
			linux_struct->l_whence = bsd_struct->l_whence;
			linux_struct->l_start = bsd_struct->l_start;
			linux_struct->l_len = bsd_struct->l_len;
			// x86Sim: Linux rejects OFD lock requests with a nonzero l_pid
			linux_struct->l_pid = (cmd >= 90) ? 0 : bsd_struct->l_pid;
			arg = linux_struct;
		} break;
		// x86Sim (Speed 27): F_PREALLOCATE (struct fstore): reserve space without changing the file's size, as
		// Linux's fallocate(FALLOC_FL_KEEP_SIZE). It was EINVAL: Core ML's BNNS graph compiler ("failed to preallocate
		// file") failed, so Spotlight's query parser couldn't load its model in time and Spotlight crashed on typing.
		// A file system without fallocate gets XNU's answer for space it doesn't have to reserve: all of it.
		case 42: {
			struct bsd_fstore {
				unsigned int fst_flags;
				int fst_posmode;
				long long fst_offset;
				long long fst_length;
				long long fst_bytesalloc;
			}* fst = (struct bsd_fstore*) arg;
			long long off;
			if (fst == NULL || fst->fst_length < 0)
				return -EINVAL;
			fst->fst_bytesalloc = 0;
			if (fst->fst_posmode == 3) { // F_PEOFPOSMODE: from the end of the file
				long long end = LINUX_SYSCALL(__NR_lseek, fd, 0, 2 /* SEEK_END */);
				if (end < 0)
					return errno_linux_to_bsd(end);
				off = end + fst->fst_offset;
			} else if (fst->fst_posmode == 4) { // F_VOLPOSMODE
				off = fst->fst_offset;
			} else {
				return -EINVAL;
			}
			if (off < 0)
				return -EINVAL;
			if (fst->fst_length == 0)
				return 0;
			ret = LINUX_SYSCALL(__NR_fallocate, fd, 1 /* FALLOC_FL_KEEP_SIZE */, off, fst->fst_length);
			if (ret < 0 && ret != -LINUX_EOPNOTSUPP && ret != -LINUX_ENOSYS)
				return errno_linux_to_bsd(ret);
			fst->fst_bytesalloc = fst->fst_length;
			return 0;
		}
		// x86Sim (Speed 27): read-ahead and caching hints (XNU: per-file flags): Linux's page cache advice
		case 45: // F_RDAHEAD
			LINUX_SYSCALL(__NR_fadvise64, fd, 0, 0, arg ? 2 /* POSIX_FADV_SEQUENTIAL */ : 0 /* NORMAL */);
			return 0;
		case 44: { // F_RDADVISE (struct radvisory: offset, count): read the range ahead
			struct { long long ra_offset; int ra_count; }* ra = (void*) arg;
			if (ra == NULL || ra->ra_offset < 0 || ra->ra_count < 0)
				return -EINVAL;
			LINUX_SYSCALL(__NR_fadvise64, fd, ra->ra_offset, ra->ra_count, 3 /* POSIX_FADV_WILLNEED */);
			return 0;
		}
		// F_SETCONFINED / F_GETCONFINED (95, 96): a confined descriptor may not be sent to another process (SQLite
		// sets it on its database files). Nothing sends descriptors behind a program's back here: accepted, never set.
		case 95:
			return 0;
		case 96:
			return 0;
		// x86Sim: F_SINGLE_WRITER (76): a hint for the I/O throttle that one process writes the file. Spotlight's
		// journal (searchd) sets it and took the EINVAL as a failed journal write ("TOC update FAILED err=22").
		case 76:
			return 0;
		// F_BARRIERFSYNC: the writes before it reach the disk before those after: fdatasync gives at least that
		case 85:
			ret = LINUX_SYSCALL1(__NR_fdatasync, fd);
			return ret < 0 ? errno_linux_to_bsd(ret) : 0;
		// F_PUNCHHOLE (struct fpunchhole: flags, reserved, offset, length): deallocate, keeping the size
		case 99: {
			struct { unsigned int fp_flags; unsigned int reserved; long long fp_offset; long long fp_length; }* ph = (void*) arg;
			if (ph == NULL || ph->fp_flags != 0 || ph->fp_offset < 0 || ph->fp_length < 0)
				return -EINVAL;
			ret = LINUX_SYSCALL(__NR_fallocate, fd, 3 /* FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE */,
				ph->fp_offset, ph->fp_length);
			return ret < 0 ? errno_linux_to_bsd(ret) : 0;
		}
		// F_GETPATH_NOFIRMLINK: there are no firmlinks here
		case 102:
			ret = fdpath(fd, arg, MAXPATHLEN);
			return ret < 0 ? errno_linux_to_bsd(ret) : 0;
		case F_FULLFSYNC: {
			ret = LINUX_SYSCALL1(__NR_fsync, fd);
			if (ret < 0)
				ret = errno_linux_to_bsd(ret);
			return 0;
		};
		case F_NOCACHE:
		{
			// Only a caching hint; Linux has no per-descriptor equivalent
			// (O_DIRECT has alignment requirements that F_NOCACHE does
			// not), so accept it on any valid descriptor.
#ifdef __NR_fcntl64
			ret = LINUX_SYSCALL(__NR_fcntl64, fd, LINUX_F_GETFD, 0);
#else
			ret = LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_GETFD, 0);
#endif
			if (ret < 0)
				return errno_linux_to_bsd(ret);
			// x86Sim: drop what is cached so far
			if (arg)
				LINUX_SYSCALL(__NR_fadvise64, fd, 0, 0, 4 /* POSIX_FADV_DONTNEED */);
			return 0;
		}
		case F_GETPROTECTIONCLASS:
		case F_SETPROTECTIONCLASS:
			return protection_class(fd, cmd, (int) arg);
		// TODO: implement remaining commands
		default:
			if (linux_cmd == -1)
				return -EINVAL;
	}

#ifdef __NR_fcntl64
	ret = LINUX_SYSCALL_C(cancelable && cmd == F_SETLKW, __NR_fcntl64, fd, linux_cmd, arg);
#else
	ret = LINUX_SYSCALL_C(cancelable && cmd == F_SETLKW, __NR_fcntl, fd, linux_cmd, arg);
#endif
	if (ret < 0)
	{
		ret = errno_linux_to_bsd(ret);
		return ret;
	}

	switch (cmd)
	{
		case F_GETFL:
			ret = oflags_linux_to_bsd(ret);
			break;
		case F_SETLK:
		case F_SETLKW:
		case F_GETLK:
		case 90: case 91: case 92: { // x86Sim: F_OFD_SETLK/SETLKW/GETLK
			struct bsd_flock* bsd_struct = original_arg;
			struct linux_flock* linux_struct = arg;
			bsd_struct->l_type = flock_type_linux_to_bsd(linux_struct->l_type);
			bsd_struct->l_whence = linux_struct->l_whence;
			bsd_struct->l_start = linux_struct->l_start;
			bsd_struct->l_len = linux_struct->l_len;
			bsd_struct->l_pid = linux_struct->l_pid;
		} break;
		case F_DUPFD:
		case F_DUPFD_CLOEXEC:
			ret = nofile_limit_check_new(ret);
			if (ret >= 0) {
				kqueue_dup(fd, ret);
				bpf_device_dup(fd, ret);
				socket_tables_dup(fd, ret); // x86Sim
			}
			break;
	}

	return ret;
}
