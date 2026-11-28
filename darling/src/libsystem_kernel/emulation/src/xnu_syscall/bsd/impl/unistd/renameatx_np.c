#include <darling/emulation/xnu_syscall/bsd/impl/unistd/renameatx_np.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsgetpath.h>

extern char* strcpy(char* dst, const char* src);

// bsd/sys/stdio.h and bsd/man/man2/rename.2.
#define DARWIN_RENAME_SECLUDE 0x00000001
#define DARWIN_RENAME_SWAP    0x00000002
#define DARWIN_RENAME_EXCL    0x00000004
// x86Sim Speed 26: newer flags; searchd renames its index state with them and got ENOTSUP (Files: "Content
// Unavailable"). No symlink in the paths is followed (NOFOLLOW_ANY: the last component isn't, as rename never does);
// RESOLVE_BENEATH and SECLUDE (a hint) don't change a rename inside the prefix.
#define DARWIN_RENAME_NOFOLLOW_ANY    0x00000010
#define DARWIN_RENAME_RESOLVE_BENEATH 0x00000020

// linux/fs.h.
#define LINUX_RENAME_NOREPLACE 0x00000001
#define LINUX_RENAME_EXCHANGE  0x00000002

long sys_renameatx_np(int fromfd, const char* from, int tofd, const char* to, unsigned int flags)
{
	struct vchroot_expand_args vc, vc2;
	unsigned int linux_flags = 0;
	long ret;

	if (from == NULL || to == NULL)
		return -EFAULT;

	if (flags & ~(DARWIN_RENAME_SECLUDE | DARWIN_RENAME_SWAP | DARWIN_RENAME_EXCL | DARWIN_RENAME_NOFOLLOW_ANY |
			DARWIN_RENAME_RESOLVE_BENEATH))
		return -ENOTSUP;
	if ((flags & DARWIN_RENAME_SWAP) && (flags & DARWIN_RENAME_EXCL))
		return -EINVAL;

	if (flags & DARWIN_RENAME_SWAP)
		linux_flags = LINUX_RENAME_EXCHANGE;
	else if (flags & DARWIN_RENAME_EXCL)
		linux_flags = LINUX_RENAME_NOREPLACE;

	vc.flags = 0;
	vc.dfd = atfd(fromfd);
	strcpy(vc.path, from);
	vc2.flags = 0;
	vc2.dfd = atfd(tofd);
	strcpy(vc2.path, to);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = vchroot_expand(&vc2);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	// x86Sim: IDs handed out follow the objects (both of them for a swap)
	struct fsgp_rename fr, fr2;
	fsgetpath_rename_prepare(vc.dfd, vc.path, &fr);
	fr2.known = fr2.isdir = 0;
	fr2.oldpath[0] = 0;
	if (linux_flags == LINUX_RENAME_EXCHANGE)
		fsgetpath_rename_prepare(vc2.dfd, vc2.path, &fr2);

	// x86Sim: document ids and tracking stay with the paths, as APFS keeps them (checked on a Mac): a rename over a
	// tracked item, or a swap, gives the item now at a path the id the path's item had
	struct fsgp_docid d1, d2;
	d1.docid = 0;
	fsgetpath_docid_prepare(vc2.dfd, vc2.path, &d2);
	if (linux_flags == LINUX_RENAME_EXCHANGE)
		fsgetpath_docid_prepare(vc.dfd, vc.path, &d1);

	if (linux_flags == 0)
	{
		// Behave like renameat() on hosts without renameat2() support too.
		ret = LINUX_SYSCALL(__NR_renameat, vc.dfd, vc.path, vc2.dfd, vc2.path);
	}
	else
	{
		ret = LINUX_SYSCALL(__NR_renameat2, vc.dfd, vc.path, vc2.dfd, vc2.path, linux_flags);
		if (ret == -LINUX_EOPNOTSUPP || ret == -LINUX_ENOSYS)
			return -ENOTSUP;
	}
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if (linux_flags == LINUX_RENAME_EXCHANGE)
	{
		fsgetpath_rename_swap_done(vc2.dfd, vc2.path, &fr, vc.dfd, vc.path, &fr2);
		fsgetpath_docid_drop(vc.dfd, vc.path, &d2, &d1);
		fsgetpath_docid_drop(vc2.dfd, vc2.path, &d1, &d2);
		fsgetpath_docid_done(vc.dfd, vc.path, &d1);
	}
	else
		fsgetpath_rename_done(vc2.dfd, vc2.path, &fr);
	fsgetpath_docid_done(vc2.dfd, vc2.path, &d2);
	return 0;
}
