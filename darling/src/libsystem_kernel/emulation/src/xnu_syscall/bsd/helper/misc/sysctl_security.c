// x86Sim: the "security" sysctl node (XNU's MAC framework, security/mac_*.c and the Sandbox kext).
#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_security.h>

#include <sys/errno.h>

#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

static sysctl_handler(handle_sandbox_sentinel);

enum {
	_SECURITY_MAC = 1,
};
enum {
	_MAC_SANDBOX = 1,
};
enum {
	_SANDBOX_SENTINEL = 1,
};

static const struct known_sysctl sysctls_security_mac_sandbox[] = {
	{ .oid = _SANDBOX_SENTINEL, .type = CTLTYPE_STRING, .exttype = "S", .name = "sentinel", .handler = handle_sandbox_sentinel },
	{ .oid = -1 },
};

static const struct known_sysctl sysctls_security_mac[] = {
	{ .oid = _MAC_SANDBOX, .type = CTLTYPE_NODE, .exttype = "", .name = "sandbox", .subctls = sysctls_security_mac_sandbox },
	{ .oid = -1 },
};

const struct known_sysctl sysctls_security[] = {
	{ .oid = _SECURITY_MAC, .type = CTLTYPE_NODE, .exttype = "", .name = "mac", .subctls = sysctls_security_mac },
	{ .oid = -1 },
};

// security.mac.sandbox.sentinel: the Sandbox kext's per-boot name tag (".sb-" and 8 hex digits, e.g. ".sb-f8d4cc27"),
// the same for every process until the next boot. libsystem_sandbox's _amkrtemp() makes its temp file names from it
// and returns NULL without it: MediaToolbox's remaker (AVAssetWriter with performsMultiPassEncodingIfSupported) then
// failed startWriting with -12148 "Cannot create file". Ours: a hash of Linux's boot_id.
static sysctl_handler(handle_sandbox_sentinel)
{
	static char sentinel[16];
	if (!sentinel[0])
	{
		char buf[40] = {0};
		int n = 0;
		int fd = sys_open("/proc/sys/kernel/random/boot_id", BSD_O_RDONLY, 0);
		if (fd >= 0)
		{
			n = sys_read(fd, buf, 36);
			close_internal(fd);
		}
		unsigned int h = 2166136261u;  // FNV-1a
		for (int i = 0; i < n; i++)
			h = (h ^ (unsigned char) buf[i]) * 16777619u;
		char s[16] = ".sb-";
		for (int i = 0; i < 8; i++)
			s[4 + i] = "0123456789abcdef"[(h >> (28 - 4 * i)) & 0xf];
		s[12] = 0;
		for (int i = 0; i <= 12; i++)
			sentinel[i] = s[i];
	}
	return copyout_string(sentinel, (char*) old, oldlen);
}
