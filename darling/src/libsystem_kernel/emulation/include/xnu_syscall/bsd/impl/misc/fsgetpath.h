#ifndef LINUX_FSGETPATH_H
#define LINUX_FSGETPATH_H
#include <stdint.h>

long sys_fsgetpath(const char* buf, unsigned long size, void* fsid, unsigned long long objid);
long sys_fsgetpath_ext(const char* buf, unsigned long size, void* fsid, unsigned long long objid, unsigned int options);

// x86Sim: getattrlist remembers (fsid, file ID) -> path for the IDs it hands out, so fsgetpath can
// resolve them (Linux has no inode -> path lookup); volumes then advertise VOL_CAP_FMT_PATH_FROM_ID
void fsgetpath_remember(unsigned int dev, unsigned long long ino, const char* path);

// x86Sim: a rename moves the remembered path of the renamed object (and of everything under a renamed directory),
// as XNU's fsgetpath follows the object: prepare before the Linux rename (Linux dfd + path), done after it succeeded
struct fsgp_rename
{
	unsigned int dev;
	unsigned long long ino;
	int known, isdir;
	char oldpath[1024];
};
void fsgetpath_rename_prepare(int ldfd, const char* lpath, struct fsgp_rename* r);
void fsgetpath_rename_done(int ldfd, const char* lpath, const struct fsgp_rename* r);
// renameatx_np RENAME_SWAP: r1's object is now at (ldfd1, lpath1) and r2's at (ldfd2, lpath2), rewritten in one pass
void fsgetpath_rename_swap_done(int ldfd1, const char* lpath1, const struct fsgp_rename* r1, int ldfd2, const char* lpath2,
		const struct fsgp_rename* r2);

// x86Sim: document ids follow the document across a rename over it / RENAME_SWAP (helper/misc/bsdflags.h
// x86sim_docid_get): the id of the item at the destination (0: none) before the rename, handed to the item there after
struct fsgp_docid
{
	unsigned int dev;
	uint32_t docid;
};
void fsgetpath_docid_prepare(int ldfd, const char* lpath, struct fsgp_docid* d);
void fsgetpath_docid_done(int ldfd, const char* lpath, const struct fsgp_docid* d);
void fsgetpath_docid_drop(int ldfd, const char* lpath, const struct fsgp_docid* gone, const struct fsgp_docid* kept);
// x86Sim: openbyid_np (479), see fsgetpath.c
long sys_openbyid_np(void* fsid, void* objid, int oflags);

#endif // LINUX_FSGETPATH_H
