#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_kern.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_vm.h>

#include <sys/errno.h>
#include <sys/syslimits.h>

#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_proc.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/getrlimit.h>
#include <darling/emulation/linux_premigration/ext/sysinfo.h>
#include <darling/emulation/linux_premigration/ext/syslog.h>
#include <darling/emulation/linux_premigration/ext/sys/utsname.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/impl/time/gettimeofday.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>

#include <darling/emulation/xnu_syscall/bsd/helper/misc/readline.h>
#include <darling/emulation/common/string.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/host_platform.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/platform_identity.h>
#include "proc_boottime.h"

#include <darling-config.h>

enum {
	_KERN_MSGBUF = 1000,
	_KERN_OSPRODUCTVERSION,
	_KERN_BOOTARGS,
	_KERN_BOOTSESSIONUUID, // x86Sim
	_KERN_SECURE_KERNEL,
	_KERN_MEMORYSTATUS_LEVEL,
	_KERN_NUM_FILES,
	_KERN_HV_VMM_PRESENT,
	_KERN_OSVARIANT_STATUS,
	_KERN_OSRELEASETYPE,

	_KERN_SEMMNS = 1000,
};

static sysctl_handler(handle_msgbuf);
static sysctl_handler(handle_proc);
static sysctl_handler(handle_procargs32);
static sysctl_handler(handle_argmax);
static sysctl_handler(handle_boottime);
static sysctl_handler(handle_ostype);
static sysctl_handler(handle_hostname);
static sysctl_handler(handle_domainname);
static sysctl_handler(handle_osrelease);
static sysctl_handler(handle_version);
static sysctl_handler(handle_osversion);
static sysctl_handler(handle_maxproc);
static sysctl_handler(handle_memorystatus_level);
static sysctl_handler(handle_maxfiles);
static sysctl_handler(handle_maxfilesperproc);
static sysctl_handler(handle_num_files);
static sysctl_handler(handle_netboot);
static sysctl_handler(handle_safeboot);
static sysctl_handler(handle_usrstack32);
static sysctl_handler(handle_usrstack64);
static sysctl_handler(handle_sysv_semmns);
static sysctl_handler(handle_osproductversion);
static sysctl_handler(handle_osrevision);
static sysctl_handler(handle_bootargs);
static sysctl_handler(handle_bootsessionuuid);
static sysctl_handler(handle_hv_vmm_present);
static sysctl_handler(handle_osvariant_status);
static sysctl_handler(handle_osreleasetype);
static sysctl_handler(handle_secure_kernel);

extern int _sysctl_proc(int what, int flag, struct kinfo_proc* out, unsigned long* buflen);
extern int _sysctl_procargs(int pid, char* buf, unsigned long* buflen);
extern int strlcpy(char* dst, const char* src, __SIZE_TYPE__ dst_size);
extern __SIZE_TYPE__ strlen(const char* str);

const struct known_sysctl sysctls_kern_sysv[] = {
	{ .oid = _KERN_SEMMNS, .type = CTLTYPE_INT, .exttype = "I", .name = "semmns", .handler = handle_sysv_semmns },
	{ .oid = -1 }
};

const struct known_sysctl sysctls_kern[] = {
	{ .oid = _KERN_MEMORYSTATUS_LEVEL, .type = CTLTYPE_INT, .exttype = "I", .name = "memorystatus_level", .handler = handle_memorystatus_level },
	{ .oid = _KERN_MSGBUF, .type = CTLTYPE_STRING, .exttype = "S", .name = "msgbuf", .handler = handle_msgbuf },
	{ .oid = KERN_PROC, .type = CTLTYPE_STRUCT, .exttype = "", .name = "proc", .handler = handle_proc },
	{ .oid = KERN_PROCARGS2, .type = CTLTYPE_STRUCT, .exttype = "", .name = "procargs2", .handler = handle_procargs32 },
	{ .oid = KERN_ARGMAX, .type = CTLTYPE_INT, .exttype = "I", .name = "argmax", .handler = handle_argmax },
	{ .oid = KERN_MAXPROC, .type = CTLTYPE_INT, .exttype = "I", .name = "maxproc", .handler = handle_maxproc },
	{ .oid = KERN_MAXFILES, .type = CTLTYPE_INT, .exttype = "I", .name = "maxfiles", .handler = handle_maxfiles },
	{ .oid = KERN_MAXFILESPERPROC, .type = CTLTYPE_INT, .exttype = "I", .name = "maxfilesperproc", .handler = handle_maxfilesperproc },
	{ .oid = _KERN_NUM_FILES, .type = CTLTYPE_INT, .exttype = "I", .name = "num_files", .handler = handle_num_files },
	{ .oid = KERN_NETBOOT, .type = CTLTYPE_INT, .exttype = "I", .name = "netboot", .handler = handle_netboot },
	{ .oid = KERN_SAFEBOOT, .type = CTLTYPE_INT, .exttype = "I", .name = "safeboot", .handler = handle_safeboot },
	{ .oid = KERN_BOOTTIME, .type = CTLTYPE_STRUCT, .exttype = "S,timeval", .name = "boottime", .handler = handle_boottime },
	{ .oid = KERN_OSTYPE, .type = CTLTYPE_STRING, .exttype = "S", .name = "ostype", .handler = handle_ostype },
	{ .oid = KERN_HOSTNAME, .type = CTLTYPE_STRING, .exttype = "S", .name = "hostname", .handler = handle_hostname },
	{ .oid = KERN_DOMAINNAME, .type = CTLTYPE_STRING, .exttype = "S", .name = "domainname", .handler = handle_domainname },
	{ .oid = KERN_OSRELEASE, .type = CTLTYPE_STRING, .exttype = "S", .name = "osrelease", .handler = handle_osrelease },
	{ .oid = KERN_VERSION, .type = CTLTYPE_STRING, .exttype = "S", .name = "version", .handler = handle_version },
	{ .oid = KERN_OSVERSION, .type = CTLTYPE_STRING, .exttype = "S", .name = "osversion", .handler = handle_osversion },
	{ .oid = KERN_USRSTACK32, .type = CTLTYPE_INT, .exttype = "I", .name = "usrstack", .handler = handle_usrstack32 },
	{ .oid = KERN_USRSTACK64, .type = CTLTYPE_QUAD, .exttype = "Q", .name = "usrstack64", .handler = handle_usrstack64 },
	{ .oid = _KERN_OSPRODUCTVERSION, .type = CTLTYPE_STRING, .exttype = "S", .name = "osproductversion", .handler = handle_osproductversion },
	{ .oid = _KERN_BOOTARGS, .type = CTLTYPE_STRING, .exttype = "S", .name = "bootargs", .handler = handle_bootargs },
	{ .oid = _KERN_BOOTSESSIONUUID, .type = CTLTYPE_STRING, .exttype = "S", .name = "bootsessionuuid", .handler = handle_bootsessionuuid },
	{ .oid = KERN_OSREV, .type = CTLTYPE_INT, .exttype = "I", .name = "osrevision", .handler = handle_osrevision },
	{ .oid = _KERN_HV_VMM_PRESENT, .type = CTLTYPE_INT, .exttype = "I", .name = "hv_vmm_present", .handler = handle_hv_vmm_present },
	{ .oid = _KERN_OSVARIANT_STATUS, .type = CTLTYPE_QUAD, .exttype = "Q", .name = "osvariant_status", .handler = handle_osvariant_status },
	{ .oid = _KERN_OSRELEASETYPE, .type = CTLTYPE_STRING, .exttype = "S", .name = "osreleasetype", .handler = handle_osreleasetype },
	{ .oid = _KERN_SECURE_KERNEL, .type = CTLTYPE_INT, .exttype = "I", .name = "secure_kernel", .handler = handle_secure_kernel },
	{ .oid = KERN_SYSV, .type = CTLTYPE_NODE, .exttype = "", .name = "sysv", .subctls = sysctls_kern_sysv },
	{ .oid = -1 }
};

sysctl_handler(handle_msgbuf)
{
	if (*oldlen <= 8)
	{
		// Caller is asking for buffer size
		if (*oldlen < sizeof(int))
			return -EINVAL;

		*((int*) old) = __linux_syslog(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);
	}
	else
	{
		// Caller is asking for buffer contents
		int ret;

		ret = __linux_syslog(SYSLOG_ACTION_READ_ALL, (char*) old, *oldlen);
		if (ret < 0)
			return errno_linux_to_bsd(ret);

		*oldlen = ret;
	}
	return 0;
}

sysctl_handler(handle_proc)
{
	// KERN_PROC_ALL takes no argument, so its name has three components.
	if (nlen == 3 && name[2] == KERN_PROC_ALL)
		return _sysctl_proc(KERN_PROC_ALL, 0, (struct kinfo_proc*) old, oldlen);
	if (nlen < 4)
		return -ENOENT;
	return _sysctl_proc(name[2], name[3], (struct kinfo_proc*) old, oldlen);
}

sysctl_handler(handle_procargs32)
{
	if (nlen < 3)
		return -ENOENT;
	return _sysctl_procargs(name[2], (char*) old, oldlen);
}

sysctl_handler(handle_argmax)
{
	struct xnu_rlimit lim;
	unsigned long long argmax;
	int r;
	int* ovalue = (int*) old;

	r = sys_getrlimit(BSD_RLIMIT_STACK, &lim);
	if (r < 0)
		return r;

	// macOS reports the fixed ARG_MAX whatever the stack limit is. Linux
	// lets exec() take a quarter of the stack limit, so report that when it
	// is lower; an unlimited stack must not overflow the int.
	argmax = lim.rlim_cur / 4;
	if (argmax > ARG_MAX)
		argmax = ARG_MAX;

	if (ovalue != NULL)
		*ovalue = (int) argmax;
	*oldlen = sizeof(int);
	return 0;
}

sysctl_handler(handle_boottime)
{
	// x86Sim: the boot time to the microsecond, as realtime minus the monotonic clock mach_absolute_time() counts
	// (Linux CLOCK_MONOTONIC), computed once per process so it doesn't jump around (libc's _mach_boottime_usec loops
	// until two reads agree). It was the realtime minus sysinfo's whole-second uptime with the microseconds set to 0:
	// libc's clock_gettime(CLOCK_MONOTONIC) (realtime minus boot time) then disagreed with mach_absolute_time() by the
	// lost fraction, and its seconds stepped back and forth by 1 s within every second.
	static long long boottime_usec = -1;
	struct bsd_timeval* tv;

	if (boottime_usec < 0)
	{
		struct { long tv_sec; long tv_nsec; } rt, mt;
		if (LINUX_SYSCALL(__NR_clock_gettime, 0 /* CLOCK_REALTIME */, &rt) < 0
				|| LINUX_SYSCALL(__NR_clock_gettime, 1 /* CLOCK_MONOTONIC */, &mt) < 0)
			return -EINVAL;
		long long ns = (rt.tv_sec - mt.tv_sec) * 1000000000LL + (rt.tv_nsec - mt.tv_nsec);
		boottime_usec = ns / 1000;
	}

	tv = (struct bsd_timeval*) old;
	if (tv != NULL)
	{
		if (*oldlen < sizeof(*tv))
			return -EINVAL;
		tv->tv_sec = boottime_usec / 1000000;
		tv->tv_usec = boottime_usec % 1000000;
	}
	*oldlen = sizeof(*tv);
	
	return 0;
}

sysctl_handler(handle_ostype)
{
	const char* s = EMULATED_SYSNAME;

	return copyout_string(s, (char*) old, oldlen);
}

// The iOS simulator runtime refuses to start on hosts older than macOS 14
// (Darwin 23). Report a macOS 26 kernel to processes on a foreign libSystem.
// x86Sim sdkcov P9: the 27.2 runtimes' reference host, macOS 27.0, reports kern.osrelease 27.0.0 (with
// kern.osversion 26A428 and kern.osproductversion 27.0 below).
#define FOREIGN_LIBSYSTEM_RELEASE "27.0.0"

#ifndef VARIANT_DYLD
extern bool darling_foreign_libsystem(void);
#endif

sysctl_handler(handle_osrelease)
{
	const char* s = EMULATED_RELEASE;
	const dserver_platform_identity_t* identity = platform_identity();
	if (identity != NULL && identity->os_release[0] != '\0')
		s = identity->os_release;

#ifndef VARIANT_DYLD
	if (darling_foreign_libsystem())
		s = FOREIGN_LIBSYSTEM_RELEASE;
#endif

	copyout_string(s, (char*) old, oldlen);
	return 0;
}

// No boot arguments (launchd_sim requires the sysctl to exist)
sysctl_handler(handle_bootargs)
{
	copyout_string("", (char*) old, oldlen);
	return 0;
}

// x86Sim: kern.bootsessionuuid from Linux's boot_id (upper case, as on Darwin). Missing, PosterBoard's
// pbf_bootInstanceIdentifier was nil, its transient-info URL too, and it crashed (no wallpaper).
sysctl_handler(handle_bootsessionuuid)
{
	static char uuid[40];
	if (!uuid[0])
	{
		char buf[40] = {0};
		int fd = sys_open("/proc/sys/kernel/random/boot_id", BSD_O_RDONLY, 0);
		if (fd >= 0)
		{
			int n = sys_read(fd, buf, 36);
			close_internal(fd);
			if (n == 36)
			{
				for (int i = 0; i < 36; i++)
					buf[i] = (buf[i] >= 'a' && buf[i] <= 'f') ? buf[i] - 'a' + 'A' : buf[i];
				buf[36] = 0;
				for (int i = 0; i <= 36; i++)
					uuid[i] = buf[i];
			}
		}
	}
	if (!uuid[0])
		return -ENOENT;
	copyout_string(uuid, (char*) old, oldlen);
	return 0;
}

sysctl_handler(handle_version)
{
	const char* rel = EMULATED_RELEASE;
	const dserver_platform_identity_t* identity = platform_identity();
	if (identity != NULL && identity->os_release[0] != '\0')
		rel = identity->os_release;

	// A 128-byte buffer is plenty for "Darwin Kernel Version " (22 bytes) plus
	// the release string, which is capped at DSERVER_PLATFORM_IDENTITY_STRING_MAX (64 bytes).
	char buf[128];
	__simple_sprintf(buf, "Darwin Kernel Version %s", rel);
	return copyout_string(buf, (char*) old, oldlen);
}

// x86Sim: kern.osversion of a simulator process is the host's build too, as kern.osproductversion below (26A428:
// macOS 27.0, the reference Mac's). FoundationModels' minimumMacOSVersionForSimulatorSupport reads it: with Darling's
// "20G1120" (macOS 11) a watchOS LanguageModelSession on the Private Cloud Compute model failed "Host is not running
// macOS 27." where Apple's watchOS 27.2 simulator answers "This device does not support Apple Intelligence."
#define X86SIM_SIM_HOST_OSVERSION "26A428"
static int x86sim_simulator_process(void);
sysctl_handler(handle_osversion)
{
	const char* s = EMULATED_OSVERSION;
	const dserver_platform_identity_t* identity = platform_identity();
	if (identity != NULL && identity->os_version[0] != '\0')
		s = identity->os_version;
	if (x86sim_simulator_process())
		s = X86SIM_SIM_HOST_OSVERSION;

	return copyout_string(s, (char*) old, oldlen);
}


static struct linux_utsname lu;
struct linux_utsname* need_uname(void)
{
#ifndef VARIANT_DYLD
	// Cache __linux_uname results
	if (!lu.sysname[0])
	{
		__linux_uname(&lu);
	}
#endif
	return &lu;
}

sysctl_handler(handle_hostname)
{
	int rv = 0;
	
	need_uname();
	copyout_string_truncated(lu.nodename, (char*) old, oldlen);
	
	if (_new && newlen > 0)
	{
		// QUIRK: on Android the host name is not settable and the call
		// fails with EPERM, as for an unprivileged caller on macOS (setting
		// the host name needs privilege there). The call is not forwarded:
		// on the Android kernels observed, issuing it raises SIGSYS and ends
		// the process. Evidence: contributor observation on Android (tier 2,
		// not reproduced by us; Android's app seccomp policy is not public
		// API).
		// Only active when host_platform_is_android(); other hosts forward
		// the call and get the kernel's own answer.
		// Test: sethostname-unprivileged-eperm.c (pins the unchanged result
		// for an unprivileged caller on a normal host; the Android branch
		// itself cannot be exercised off Android).
		if (host_platform_is_android())
			rv = -EPERM;
		else
		{
			rv = LINUX_SYSCALL(__NR_sethostname, _new, newlen);
			if (rv < 0)
				rv = errno_linux_to_bsd(rv);
		}
	}
	
	return rv;
}

sysctl_handler(handle_domainname)
{
	int rv = 0;
	
	need_uname();
	copyout_string_truncated(lu.domainname, (char*) old, oldlen);
	
	if (_new && newlen > 0)
	{
		// QUIRK: as for handle_hostname above: EPERM on Android without
		// calling setdomainname, which raises SIGSYS there as well. Evidence:
		// tier 2, same observation. Not active on other hosts.
		if (host_platform_is_android())
			rv = -EPERM;
		else
		{
			rv = LINUX_SYSCALL(__NR_setdomainname, _new, newlen);
			if (rv < 0)
				rv = errno_linux_to_bsd(rv);
		}
	}
	
	return rv;
}

sysctl_handler(handle_maxproc)
{
	char buf[16];
	int fd = sys_open_nocancel("/proc/sys/kernel/pid_max", BSD_O_RDONLY, 0);
	int value = 1024;
	int* ovalue = (int*) old;
	
	if (!oldlen)
		return -EINVAL;
	
	if (fd >= 0)
	{
		int rd = sys_read_nocancel(fd, buf, sizeof(buf) - 1);
		close_internal(fd);
		
		if (rd > 0)
		{
			buf[rd] = '\0';
			value = __simple_atoi(buf, NULL);
		}
	}
	
	if (ovalue != NULL)
		*ovalue = value;
	*oldlen = sizeof(int);
	
	return 0;
}

sysctl_handler(handle_netboot)
{
	int* ovalue = (int*) old;
	if (!oldlen)
		return -EINVAL;

	if (*oldlen >= sizeof(int))
		*ovalue = 0;
	*oldlen = sizeof(int);

	return 0;
}

sysctl_handler(handle_safeboot)
{
	int* ovalue = (int*) old;
	if (!oldlen)
		return -EINVAL;

	if (*oldlen >= sizeof(int))
		*ovalue = 0;
	*oldlen = sizeof(int);

	return 0;
}

sysctl_handler(handle_sysv_semmns)
{
	int* ovalue = (int*) old;
	if (!oldlen)
		return -EINVAL;
	if (*oldlen >= sizeof(int))
		*ovalue = -1;
	*oldlen = sizeof(int);
	return 0;
}

sysctl_handler(handle_usrstack32)
{
	unsigned int* ovalue = (unsigned int*) old;
	if (ovalue)
		*ovalue = __darling_thread_get_stack();
	*oldlen = sizeof(*ovalue);
	return 0;
}

sysctl_handler(handle_usrstack64)
{
	unsigned long long* ovalue = (unsigned long long*) old;
	if (ovalue)
		*ovalue = __darling_thread_get_stack();
	*oldlen = sizeof(*ovalue);
	return 0;
}

// x86Sim: in an iOS simulator process, kern.osproductversion is the *host's* macOS version (the simulator's own
// version comes from its SystemVersion.plist). Simulator frameworks decide what the host offers from it: FileProvider
// uses its host service (com.apple.FileProvider.sim2host: open by id, mkdirat, ...) only for a host of macOS 15 or
// later, and failed every such call with ENOSYS for our "11.7.4" (Files could not open a document). iOS 26.5
// simulators run on macOS 26; spike3/fpsim2host stands in for that host service. Other processes keep Darling's.
// 27.0 (sdkcov P9): the 27.2 simulator runtimes' reference host (Xcode 27.2's Mac) runs macOS 27.0 (build 26A428,
// kern.osversion above).
#define X86SIM_SIM_HOST_OSPRODUCTVERSION "27.0"
uint32_t _proc_platform(int32_t pid);
extern long sys_getpid(void);
static int x86sim_simulator_process(void) {
	static int simulator = -1;
	if (simulator < 0) {
		// x86Sim Platforms 1: tvOS and watchOS simulator processes too (PLATFORM_TVOSSIMULATOR 8, WATCHOSSIMULATOR 9);
		// Platforms 2: visionOS (PLATFORM_VISIONOSSIMULATOR 12)
		uint32_t p = _proc_platform(sys_getpid());
		simulator = p == 7 /* PLATFORM_IOSSIMULATOR */ || p == 8 || p == 9 || p == 12;
	}
	return simulator;
}
static sysctl_handler(handle_osproductversion) {
	const char* s = EMULATED_OSPRODUCTVERSION;
	const dserver_platform_identity_t* identity = platform_identity();
	if (identity != NULL && identity->os_product_version[0] != '\0')
		s = identity->os_product_version;
	if (x86sim_simulator_process())
		s = X86SIM_SIM_HOST_OSPRODUCTVERSION;

	copyout_string(s, (char*)old, oldlen);
	return 0;
};

// Apple no longer changes this value
// https://lists.apple.com/archives/darwin-dev/2005/Jul/msg00029.html
#define EMULATED_OSREVISION 199506

static sysctl_handler(handle_osrevision) {
	int* ovalue = (int*)old;
	if (ovalue)
		*ovalue = EMULATED_OSREVISION;
	*oldlen = sizeof(*ovalue);
	return 0;
}

// Whether the kernel runs in the secure (restricted) mode; 0 on a normal
// Mac, and read-only. Libc's opendir() reads it to decide how to handle
// union mounts.
static sysctl_handler(handle_secure_kernel)
{
	if (_new)
		return -EPERM;
	if (!oldlen)
		return -EINVAL;
	if (old == NULL)
	{
		*oldlen = sizeof(int);
		return 0;
	}
	if (*oldlen < sizeof(int))
		return -ENOMEM;

	*(int*) old = 0;
	*oldlen = sizeof(int);
  
  return 0;
}

// Whether the system runs under a hypervisor: 1 if so, 0 on bare metal (and
// on architectures without a way to tell); read-only. On x86 this is the
// hypervisor-present bit (CPUID leaf 1, ECX bit 31).
static sysctl_handler(handle_hv_vmm_present)
{
	int present = 0;

	if (_new)
		return -EPERM;
	if (!oldlen)
		return -EINVAL;
	if (old == NULL)
	{
		*oldlen = sizeof(int);
		return 0;
	}
	if (*oldlen < sizeof(int))
		return -ENOMEM;

#if defined(__i386__) || defined(__x86_64__)
	unsigned int eax = 1, ebx, ecx = 0, edx;
	__asm__ volatile ("cpuid" : "+a" (eax), "=b" (ebx), "+c" (ecx), "=d" (edx));
	present = (ecx >> 31) & 1;
#endif

	*(int*) old = present;
	*oldlen = sizeof(int);
	return 0;
}

static sysctl_handler(handle_memorystatus_level) {
	if (_new != NULL || newlen != 0)
		return -EPERM;
	if (!oldlen)
		return -EINVAL;
	sysctl_handle_size(sizeof(int));
	return _sysctl_memorystatus_level((int*)old);
}
// Linux's fs.file-max does not fit in an int and is no useful limit for
// a guest; report macOS's value for a machine with little memory.
static sysctl_handler(handle_maxfiles) {
	sysctl_handle_size(sizeof(int));
	*((int*) old) = 49152;
	return 0;
}

// The most a guest's RLIMIT_NOFILE can be raised to (see nofile_limit.c).
static sysctl_handler(handle_maxfilesperproc) {
	sysctl_handle_size(sizeof(int));
	*((int*) old) = DARWIN_OPEN_MAX;
	return 0;
}

// Open files in the system: the first field of /proc/sys/fs/file-nr.
static sysctl_handler(handle_num_files) {
	char buf[64];

	sysctl_handle_size(sizeof(int));
	if (!read_string("/proc/sys/fs/file-nr", buf, sizeof(buf)))
		return -ENOENT;
	*((int*) old) = (int) __simple_atoi(buf, NULL);
	return 0;
}

// QUIRK: kern.osvariant_status and kern.osreleasetype are not documented. Observed by black-box
// reads (tier 2): on macOS 26.7.3 (25G342, x86_64) osvariant_status is the 8-byte quad
// 0x70010000f388828a and osreleasetype is the string "User"; on macOS 10.14.4 osvariant_status is
// 0x70000000f000028a. We report the macOS 26.7.3 value, whose two-bit slots libdarwin reads with
// status2bool().
// Test: guest test sysctl_osvariant_procs (expects exactly 0x70010000f388828a and "User").
static sysctl_handler(handle_osvariant_status)
{
	sysctl_handle_size(sizeof(unsigned long long));
	*((unsigned long long*) old) = 0x70010000f388828aULL;
	return 0;
}

static sysctl_handler(handle_osreleasetype)
{
	copyout_string("User", (char*) old, oldlen);
	return 0;
}
