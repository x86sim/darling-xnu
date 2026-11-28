#include <darling/emulation/xnu_syscall/bsd/impl/unistd/renameat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsgetpath.h>

extern char* strcpy(char* dst, const char* src);

long sys_renameat(int oldfd, const char* oldpath, int newfd, const char* newpath)
{
	int ret;
	struct vchroot_expand_args vc, vc2;

	vc.flags = 0;
	vc.dfd = atfd(oldfd);
	
	strcpy(vc.path, oldpath);

	vc2.flags = 0;
	vc2.dfd = atfd(newfd);

	strcpy(vc2.path, newpath);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = vchroot_expand(&vc2);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	// x86Sim: IDs handed out for the object (fsgetpath, bookmarks) follow it to its new path
	struct fsgp_rename fr;
	fsgetpath_rename_prepare(vc.dfd, vc.path, &fr);
	// x86Sim: and a tracked item replaced by the rename hands its document id (and tracking) to the one taking its path
	struct fsgp_docid dd;
	fsgetpath_docid_prepare(vc2.dfd, vc2.path, &dd);

	ret = LINUX_SYSCALL(__NR_renameat, vc.dfd, vc.path, vc2.dfd, vc2.path);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	fsgetpath_rename_done(vc2.dfd, vc2.path, &fr);
	fsgetpath_docid_done(vc2.dfd, vc2.path, &dd);
	return 0;
}
