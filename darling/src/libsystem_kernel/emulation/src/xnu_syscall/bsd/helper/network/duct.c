#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>

#include <sys/socket.h>

#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

#include <stddef.h>

unsigned long sockaddr_fixup_size_from_bsd(const void* bsd_sockaddr, int bsd_sockaddr_len) {
	unsigned long size = bsd_sockaddr_len;

	/* A PF_LOCAL sockaddr is rewritten in place, so the buffer has to hold the
	 * host's struct sockaddr_un on top of whatever the guest passed, and
	 * sockaddr_fixup_from_bsd() copies all bsd_sockaddr_len bytes into it. The
	 * callers accept a socklen of up to 512, so without this floor a guest
	 * asking for a long AF_LOCAL address would write past the allocation. */
	if (((const struct sockaddr_fixup*) bsd_sockaddr)->bsd_family == PF_LOCAL && size < sizeof(struct sockaddr_fixup))
		size = sizeof(struct sockaddr_fixup);

	return size;
}

/* Copies a path out of a fixed-up sockaddr into a NUL-terminated buffer, reading
 * no further than the address actually covers. The guest need not NUL-terminate
 * sun_path within socklen (Darwin's SUN_LEN is offsetof(sun_path) + strlen,
 * with no terminator) and the tail of the buffer past that is uninitialised
 * stack, so a plain strcpy() both overruns the source and turns a short address
 * into a garbage path. */
static void copy_path(char* dest, __SIZE_TYPE__ dest_size, const struct sockaddr_fixup* in, int in_len) {
	const int path_off = (int) offsetof(struct sockaddr_fixup, sun_path);
	__SIZE_TYPE__ max;

	if (in_len <= path_off) {
		/* An address that does not even reach the path carries no path. */
		dest[0] = '\0';
		return;
	}

	/* Never read past sun_path itself, whatever the destination allows. */
	max = sizeof(in->sun_path);
	if (max > dest_size - 1)
		max = dest_size - 1;
	if (in_len < (int) sizeof(*in) && (in_len - path_off) < (int) max)
		max = in_len - path_off;

	strncpy(dest, in->sun_path, max);
	dest[max] = '\0';
}

int sockaddr_fixup_from_bsd(struct sockaddr_fixup* out, const void* bsd_sockaddr, int bsd_sockaddr_len) {
	int ret = bsd_sockaddr_len;

	memcpy(out, bsd_sockaddr, bsd_sockaddr_len);

	out->linux_family = sfamily_bsd_to_linux(out->bsd_family);

	if (out->linux_family == LINUX_PF_LOCAL) {
		struct vchroot_expand_args vc;
		vc.flags = VCHROOT_FOLLOW;
		vc.dfd = get_perthread_wd();

		copy_path(vc.path, sizeof(vc.path), out, bsd_sockaddr_len);

		ret = vchroot_expand(&vc);
		if (ret < 0)
			return errno_linux_to_bsd(ret);

		strncpy(out->sun_path, vc.path, sizeof(out->sun_path) - 1);
		out->sun_path[sizeof(out->sun_path) - 1] = '\0';
		/* + 1 for the NUL terminator: a sockaddr length is the offset of the
		 * path plus the path plus its terminator, and Linux's connect() reads
		 * exactly that many bytes, so omitting it truncates the path by one and
		 * the call fails on a socket that exists. The reverse direction,
		 * sockaddr_fixup_from_linux, has always had the + 1; this one did not. */
		ret = (int) (offsetof(struct sockaddr_fixup, sun_path) + strlen(out->sun_path) + 1);
	}

	return ret;
}

// x86Sim: converted in a local copy and written back bounded by cap, the size of the caller's buffer (the kernel's
// length can exceed it: the address was truncated). The in-place version wrote a whole sun_path (strncpy pads all 104
// bytes) into whatever buffer the caller had, and strcpy'd a path an unnamed socket (a socketpair end: length 2) never
// had: RealityKit's getsockname on a socketpair into a small sockaddr smashed its stack (__stack_chk_fail).
// Returns the BSD length written (as XNU: min(address length, cap)), or a BSD errno.
int sockaddr_fixup_from_linux(struct sockaddr_fixup* out, const void* linux_sockaddr, int linux_sockaddr_len, int cap) {
	struct {
		struct sockaddr_fixup sa;
		char extra[16];  // Linux's sun_path is 108 bytes, BSD's 104
	} tmp;
	int ret, n = linux_sockaddr_len;

	if (cap < 0) cap = 0;
	if (n > cap) n = cap;
	if (n > (int)sizeof(tmp)) n = sizeof(tmp);
	if (n < 0) n = 0;
	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp, linux_sockaddr, n);
	ret = linux_sockaddr_len;

	tmp.sa.bsd_family = sfamily_linux_to_bsd(tmp.sa.linux_family);

	if (tmp.sa.bsd_family == PF_LOCAL) {
		int plen = n - (int)(sizeof(tmp.sa) - sizeof(tmp.sa.sun_path));
		if (plen > 0 && tmp.sa.sun_path[0] != '\0') {
			struct vchroot_unexpand_args vc;
			if (plen >= (int)sizeof(vc.path)) plen = sizeof(vc.path) - 1;
			memcpy(vc.path, tmp.sa.sun_path, plen);
			vc.path[plen] = '\0';

			ret = vchroot_unexpand(&vc);
			if (ret < 0)
				return errno_linux_to_bsd(ret);

			memset(tmp.sa.sun_path, 0, sizeof(tmp.sa.sun_path));
			strncpy(tmp.sa.sun_path, vc.path, sizeof(tmp.sa.sun_path) - 1);
			ret = sizeof(tmp.sa) - sizeof(tmp.sa.sun_path) + strlen(tmp.sa.sun_path) + 1;
		} else if (plen > 0) {
			ret = linux_sockaddr_len;  // abstract name: kept as is
		} else {
			ret = sizeof(tmp.sa) - sizeof(tmp.sa.sun_path);  // unnamed
		}
	}

	if (ret > (int)sizeof(tmp.sa)) ret = sizeof(tmp.sa);
	tmp.sa.bsd_length = ret;
	if (ret > cap) ret = cap;
	memcpy(out, &tmp, ret);
	return ret;
}
