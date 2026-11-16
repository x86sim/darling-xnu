// getrlimit.c / setrlimit.c against a fake prlimit64 (shim.c): Darwin's RLIM_INFINITY is 2^63 - 1
// (bsd/sys/resource.h), Linux's ~0. Built with Darling's headers.
#include <darling/emulation/conversion/misc/getrlimit.h>
#include "check.h"

long sys_getrlimit(unsigned int which, struct xnu_rlimit* rlp);
long sys_setrlimit(unsigned int which, const struct xnu_rlimit* rlp);

extern int fake_prlimit, fake_prlimit_sets;
extern unsigned long long fake_limits[16][2];

#define DARWIN_INF 0x7fffffffffffffffULL
#define LINUX_INF (~0ULL)

int main(void)
{
	struct xnu_rlimit r;
	long ret;

	fake_prlimit = 1;
	fake_limits[LINUX_RLIMIT_STACK][0] = 8 << 20;
	fake_limits[LINUX_RLIMIT_STACK][1] = LINUX_INF;
	fake_limits[LINUX_RLIMIT_CPU][0] = LINUX_INF;
	fake_limits[LINUX_RLIMIT_CPU][1] = LINUX_INF;
	fake_limits[LINUX_RLIMIT_NOFILE][0] = 1024;
	fake_limits[LINUX_RLIMIT_NOFILE][1] = 524288;
	fake_limits[LINUX_RLIMIT_CORE][0] = 0;
	fake_limits[LINUX_RLIMIT_CORE][1] = LINUX_INF;

	ret = sys_getrlimit(BSD_RLIMIT_STACK, &r);
	CHECK(ret == 0 && r.rlim_cur == 8 << 20 && r.rlim_max == DARWIN_INF,
		"getrlimit(STACK) {8M, unlimited} -> {%#llx, %#llx}", r.rlim_cur, r.rlim_max);
	ret = sys_getrlimit(BSD_RLIMIT_CPU | BSD_RLIMIT_POSIX, &r);
	CHECK(ret == 0 && r.rlim_cur == DARWIN_INF && r.rlim_max == DARWIN_INF,
		"getrlimit(CPU|POSIX) unlimited -> {%#llx, %#llx}", r.rlim_cur, r.rlim_max);
	CHECK((long long) r.rlim_cur > 0, "unlimited is positive as int64_t (%lld)", (long long) r.rlim_cur);

	struct xnu_rlimit set = { 4 << 20, DARWIN_INF };
	ret = sys_setrlimit(BSD_RLIMIT_STACK, &set);
	CHECK(ret == 0 && fake_limits[LINUX_RLIMIT_STACK][0] == 4 << 20 && fake_limits[LINUX_RLIMIT_STACK][1] == LINUX_INF,
		"setrlimit(STACK, {4M, RLIM_INFINITY}) -> Linux {%#llx, %#llx}",
		fake_limits[LINUX_RLIMIT_STACK][0], fake_limits[LINUX_RLIMIT_STACK][1]);

	// what getrlimit said, handed back, changes nothing
	sys_getrlimit(BSD_RLIMIT_CORE, &r);
	sys_setrlimit(BSD_RLIMIT_CORE, &r);
	CHECK(fake_limits[LINUX_RLIMIT_CORE][0] == 0 && fake_limits[LINUX_RLIMIT_CORE][1] == LINUX_INF,
		"getrlimit/setrlimit round trip (CORE) keeps Linux {0, unlimited}: {%#llx, %#llx}",
		fake_limits[LINUX_RLIMIT_CORE][0], fake_limits[LINUX_RLIMIT_CORE][1]);

	// RLIMIT_NOFILE keeps x86Sim's one-descriptor reserve, and unlimited doesn't wrap
	ret = sys_getrlimit(BSD_RLIMIT_NOFILE, &r);
	CHECK(ret == 0 && r.rlim_cur == 1023 && r.rlim_max == 524287,
		"getrlimit(NOFILE) {1024, 524288} -> {%llu, %llu}", r.rlim_cur, r.rlim_max);
	set.rlim_cur = 2000;
	set.rlim_max = DARWIN_INF;
	ret = sys_setrlimit(BSD_RLIMIT_NOFILE, &set);
	CHECK(fake_limits[LINUX_RLIMIT_NOFILE][0] == 2001 && fake_limits[LINUX_RLIMIT_NOFILE][1] == LINUX_INF,
		"setrlimit(NOFILE, {2000, RLIM_INFINITY}) -> Linux {%llu, %#llx}",
		fake_limits[LINUX_RLIMIT_NOFILE][0], fake_limits[LINUX_RLIMIT_NOFILE][1]);

	int sets = fake_prlimit_sets;
	set.rlim_cur = 100;
	set.rlim_max = 200;
	ret = sys_setrlimit(BSD_RLIMIT_NOFILE, &set);
	CHECK(ret == 0 && fake_prlimit_sets == sets, "setrlimit(NOFILE) below the current limit: accepted, not applied");

	set.rlim_cur = 1000;
	set.rlim_max = 5000;
	ret = sys_setrlimit(BSD_RLIMIT_DATA, &set);
	CHECK(fake_limits[LINUX_RLIMIT_DATA][0] == 1000 && fake_limits[LINUX_RLIMIT_DATA][1] == 5000,
		"finite limits pass through unchanged");
	DONE();
}
