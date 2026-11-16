// symlinkat.c (and common_at.c's atfd()) on Linux: the link is created relative to the directory fd the caller
// passed, and relative to the thread's working directory only for AT_FDCWD. Built with Darling's headers.
#include <darling/emulation/conversion/common_at.h>
#include "check.h"

long sys_symlinkat(const char* path, int fd, const char* link);
int host_mkdirs(const char* base, int* wd_fd, int* dir_fd);
const char* host_readlink(const char* base, const char* sub, const char* name);
extern int shim_perthread_wd;
int strcmp(const char*, const char*);

int main(int argc, char** argv)
{
	int wd, dir;
	if (argc < 2 || host_mkdirs(argv[1], &wd, &dir) < 0)
		return 2;
	shim_perthread_wd = wd;

	long ret = sys_symlinkat("target-1", dir, "link-1");
	CHECK(ret == 0, "symlinkat(dirfd) returned %ld", ret);
	CHECK(strcmp(host_readlink(argv[1], "dirfd", "link-1"), "target-1") == 0, "link-1 is in the dirfd directory");
	CHECK(host_readlink(argv[1], "wd", "link-1")[0] == 0, "link-1 is not in the working directory");

	ret = sys_symlinkat("target-2", BSD_AT_FDCWD, "link-2");
	CHECK(ret == 0 && strcmp(host_readlink(argv[1], "wd", "link-2"), "target-2") == 0,
		"symlinkat(AT_FDCWD) creates link-2 in the working directory");
	DONE();
}
