// Linux-side stand-ins for what the emulation sources call outside the files under test, plus host helpers the
// tests (built with Darling's headers) can't write themselves. Built with the host's own headers.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

// prlimit64 answered from a table instead of the kernel, when a test turns it on
int fake_prlimit;
unsigned long long fake_limits[16][2];
int fake_prlimit_sets;

long linux_syscall(long a1, long a2, long a3, long a4, long a5, long a6, int nr)
{
	if (fake_prlimit && nr == SYS_prlimit64) {
		unsigned int which = a2;
		unsigned long long* new = (void*) a3;
		unsigned long long* old = (void*) a4;
		if (which >= 16)
			return -EINVAL;
		if (old) {
			old[0] = fake_limits[which][0];
			old[1] = fake_limits[which][1];
		}
		if (new) {
			fake_limits[which][0] = new[0];
			fake_limits[which][1] = new[1];
			fake_prlimit_sets++;
		}
		return 0;
	}
	long ret = syscall(nr, a1, a2, a3, a4, a5, a6);
	return ret < 0 ? -errno : ret;
}

// common/bsdthread/per_thread_wd.h (see shim-include)
int shim_perthread_wd = AT_FDCWD;
int get_perthread_wd(void) { return shim_perthread_wd; }

// vchroot_expand: there's no prefix here; the path and its base directory stay as given
int vchroot_expand(void* args) { (void) args; return 0; }

// bsdthread/pthread_canceled: never canceled
long sys_pthread_canceled(int action) { (void) action; return -EINVAL; }

// route.h (sysctl_net.c's NET_RT_DUMP): not under test
int route_dump(int af, void* old, unsigned long* oldlen) { (void) af; (void) old; (void) oldlen; return -ENOSYS; }

// ---- host helpers

int host_mkdirs(const char* base, int* wd_fd, int* dir_fd)
{
	char a[4096], b[4096];
	snprintf(a, sizeof(a), "%s/wd", base);
	snprintf(b, sizeof(b), "%s/dirfd", base);
	mkdir(base, 0755);
	mkdir(a, 0755);
	mkdir(b, 0755);
	*wd_fd = open(a, O_RDONLY | O_DIRECTORY);
	*dir_fd = open(b, O_RDONLY | O_DIRECTORY);
	return *wd_fd >= 0 && *dir_fd >= 0 ? 0 : -1;
}

// the symlink's target, or "" if there's no symlink at base/sub/name
const char* host_readlink(const char* base, const char* sub, const char* name)
{
	static char target[4096];
	char path[4096];
	snprintf(path, sizeof(path), "%s/%s/%s", base, sub, name);
	ssize_t n = readlink(path, target, sizeof(target) - 1);
	target[n > 0 ? n : 0] = 0;
	return target;
}

// a child that exits 42 once gate is closed
int host_spawn_gated(int* gate)
{
	int p[2];
	if (pipe(p))
		return -1;
	pid_t pid = fork();
	if (pid == 0) {
		char c;
		close(p[1]);
		read(p[0], &c, 1);
		_exit(42);
	}
	close(p[0]);
	*gate = p[1];
	return pid;
}

void host_release(int gate) { close(gate); }

int host_sigchld(void) { return SIGCHLD; }

unsigned long long host_sysfs(const char* ifname, const char* file)
{
	char path[256];
	unsigned long long v = 0;
	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifname, file);
	FILE* f = fopen(path, "r");
	if (!f)
		return ~0ULL;
	if (fscanf(f, "%llu", &v) != 1)
		v = ~0ULL;
	fclose(f);
	return v;
}

unsigned int host_if_index(const char* ifname) { return if_nametoindex(ifname); }

// some packets over the loopback, so its counters aren't all zero
void host_lo_traffic(int count)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t len = sizeof(sin);
	bind(s, (void*) &sin, sizeof(sin));
	getsockname(s, (void*) &sin, &len);
	for (int i = 0; i < count; i++)
		sendto(s, "x", 1, 0, (void*) &sin, sizeof(sin));
	close(s);
}
