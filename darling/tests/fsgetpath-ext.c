// fsgetpath_ext(2) resolves a file system object id on a volume just like fsgetpath(2), accepts
// FSOPT_NOFIRMLINKPATH (0x80) and FSOPT_ISREALFSID (0x200), and rejects unknown option bits with EINVAL.
// Also passes on macOS against Apple's kernel.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

extern ssize_t fsgetpath_ext(char* buf, size_t bufsize, fsid_t* fsid, uint64_t objid, uint32_t options);

#ifndef FSOPT_NOFIRMLINKPATH
#define FSOPT_NOFIRMLINKPATH 0x00000080U
#endif
#ifndef FSOPT_ISREALFSID
#define FSOPT_ISREALFSID 0x00000200U
#endif

static int failures;

#define CHECK(c) do { \
	if (!(c)) { \
		printf("FAIL: %s (line %d, errno %d)\n", #c, __LINE__, errno); \
		failures++; \
	} \
} while (0)

int main(void)
{
	char tmpl[] = "/tmp/fsgetpath-ext-XXXXXX";
	char* dir = mkdtemp(tmpl);
	CHECK(dir != NULL);
	if (!dir)
		return 1;

	char path[1024];
	snprintf(path, sizeof(path), "%s/sample.txt", dir);
	int fd = open(path, O_CREAT | O_RDWR, 0644);
	CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);

	struct stat st;
	struct statfs sfs;
	CHECK(lstat(path, &st) == 0);
	CHECK(statfs(path, &sfs) == 0);

	// Resolve IDs through getattrlist as FileProvider / CoreServices does (registers ID -> path in Darling).
	struct {
		uint32_t length;
		fsid_t fsid;
		fsobj_id_t objid;
	} __attribute__((packed)) attrs;
	struct attrlist alist;
	memset(&alist, 0, sizeof(alist));
	alist.bitmapcount = ATTR_BIT_MAP_COUNT;
	alist.commonattr = ATTR_CMN_FSID | ATTR_CMN_OBJID;
	memset(&attrs, 0, sizeof(attrs));
	CHECK(getattrlist(path, &alist, &attrs, sizeof(attrs), 0) == 0);

	fsid_t fsid = sfs.f_fsid;
	uint64_t objid = (uint64_t) attrs.objid.fid_objno;
	char ref[1024] = { 0 };
	ssize_t ref_len = fsgetpath(ref, sizeof(ref), &fsid, objid);
	CHECK(ref_len > 0 && (size_t) ref_len == strlen(ref) + 1);

	const uint32_t valid_opts[] = {
		0,
		FSOPT_NOFIRMLINKPATH,
		FSOPT_ISREALFSID,
		FSOPT_NOFIRMLINKPATH | FSOPT_ISREALFSID,
	};
	for (size_t i = 0; i < sizeof(valid_opts) / sizeof(valid_opts[0]); i++) {
		char out[1024] = { 0 };
		struct stat out_st;
		errno = 0;
		ssize_t n = fsgetpath_ext(out, sizeof(out), &fsid, objid, valid_opts[i]);
		CHECK(n > 0 && (size_t) n == strlen(out) + 1);
		CHECK(lstat(out, &out_st) == 0 && out_st.st_ino == st.st_ino && out_st.st_dev == st.st_dev);
		if (!(valid_opts[i] & FSOPT_NOFIRMLINKPATH)) {
			CHECK(n == ref_len);
			CHECK(strcmp(out, ref) == 0);
		}
	}

	// Reject unknown option flags with EINVAL (matching XNU vfs_syscalls.c fsgetpath_ext).
	{
		char out[1024] = { 0 };
		errno = 0;
		CHECK(fsgetpath_ext(out, sizeof(out), &fsid, objid, 0x1U) == -1 && errno == EINVAL);
		errno = 0;
		CHECK(fsgetpath_ext(out, sizeof(out), &fsid, objid, 0x400U) == -1 && errno == EINVAL);
	}

	// Small buffer fails with ENOSPC.
	{
		char tiny[2] = { 0 };
		errno = 0;
		CHECK(fsgetpath_ext(tiny, sizeof(tiny), &fsid, objid, FSOPT_ISREALFSID) == -1 && errno == ENOSPC);
	}

	// Unlinked file resolves to ENOENT.
	CHECK(unlink(path) == 0);
	{
		char out[1024] = { 0 };
		errno = 0;
		CHECK(fsgetpath_ext(out, sizeof(out), &fsid, objid, FSOPT_ISREALFSID) == -1 && errno == ENOENT);
	}
	rmdir(dir);

	printf("%s\n", failures == 0 ? "PASS" : "FAIL");
	return failures != 0;
}
