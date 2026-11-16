// x86Sim: see sockextra.h
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockextra.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/tcpinfo.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/getsockname.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/getpeername.h>

extern void* memset(void* dest, int c, __SIZE_TYPE__ n);
extern int memcmp(const void* a, const void* b, __SIZE_TYPE__ n);

#define L_AF_INET 2
#define L_AF_INET6 10
#define L_SOL_SOCKET 1
#define L_SO_ERROR 4
#define L_SO_DOMAIN 39
#define L_SO_BINDTOIFINDEX 62
#define L_SIOCGIFCONF 0x8912
#define L_SIOCGIFINDEX 0x8933

static long l_getsockopt(int fd, int level, int name, void* val, unsigned int* len)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT, ((long[6]) { fd, level, name, val, len, 0 }));
#else
	return LINUX_SYSCALL(__NR_getsockopt, fd, level, name, val, len);
#endif
}

static long l_name(int fd, int peer, void* sa, unsigned int* len)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, peer ? LINUX_SYS_GETPEERNAME : LINUX_SYS_GETSOCKNAME, ((long[6]) { fd, sa, len }));
#else
	return LINUX_SYSCALL(peer ? __NR_getpeername : __NR_getsockname, fd, sa, len);
#endif
}

static int l_domain(int fd)
{
	int d = 0;
	unsigned int len = sizeof(d);
	return l_getsockopt(fd, L_SOL_SOCKET, L_SO_DOMAIN, &d, &len) < 0 ? -1 : d;
}

int sockextra_unix_dgram(int fd)
{
	int t = 0;
	unsigned int len = sizeof(t);
	if (l_getsockopt(fd, L_SOL_SOCKET, 3 /* SO_TYPE */, &t, &len) < 0 || t != 2 /* SOCK_DGRAM */)
		return 0;
	return l_domain(fd) == 1 /* AF_UNIX */;
}

struct l_ifreq { char name[16]; union { struct { uint16_t family, port; uint32_t addr; } in; int index; char pad[24]; }; };
struct l_ifconf { int len; int pad; void* buf; };

static int hexval(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; }

int sockextra_out_ifindex(int fd)
{
	int bound = 0;
	unsigned int len = sizeof(bound);
	if (l_getsockopt(fd, L_SOL_SOCKET, L_SO_BINDTOIFINDEX, &bound, &len) >= 0 && bound > 0)
		return bound;

	unsigned char sa[128];
	len = sizeof(sa);
	if (l_name(fd, 0, sa, &len) < 0)
		return 0;
	uint16_t family = *(uint16_t*) sa;

	if (family == L_AF_INET) {
		uint32_t addr = *(uint32_t*) (sa + 4);
		if (addr == 0)
			return 0; // not bound: no traffic yet
		struct l_ifreq reqs[32];
		struct l_ifconf conf = { sizeof(reqs), 0, reqs };
		int s = fd;
		if (LINUX_SYSCALL(__NR_ioctl, s, L_SIOCGIFCONF, &conf) < 0)
			return 0;
		for (int i = 0; i < conf.len / (int) sizeof(struct l_ifreq); i++) {
			if (reqs[i].in.family == L_AF_INET && reqs[i].in.addr == addr) {
				struct l_ifreq q;
				memset(&q, 0, sizeof(q));
				for (int k = 0; k < 16; k++) q.name[k] = reqs[i].name[k];
				if (LINUX_SYSCALL(__NR_ioctl, s, L_SIOCGIFINDEX, &q) < 0)
					return 0;
				return q.index;
			}
		}
		return 0;
	}
	if (family == L_AF_INET6) {
		const unsigned char* a6 = sa + 8;
		static const unsigned char zero[16];
		if (!memcmp(a6, zero, 16))
			return 0;
		// IPv4-mapped: the IPv4 interface is not in if_inet6; leave it to the caller (0)
		// /proc/net/if_inet6: "<32 hex addr> <ifindex hex> <plen> <scope> <flags> <name>"
		int f = LINUX_SYSCALL(__NR_openat, -100, "/proc/net/if_inet6", 0, 0);
		if (f < 0)
			return 0;
		static char buf[8192];
		long n = LINUX_SYSCALL(__NR_read, f, buf, sizeof(buf) - 1);
		LINUX_SYSCALL(__NR_close, f);
		if (n <= 0)
			return 0;
		buf[n] = 0;
		for (char* line = buf; *line; ) {
			unsigned char addr[16];
			int ok = 1;
			for (int k = 0; k < 16; k++) {
				int h = hexval(line[2 * k]), l = hexval(line[2 * k + 1]);
				if (h < 0 || l < 0) { ok = 0; break; }
				addr[k] = (unsigned char) (h * 16 + l);
			}
			if (ok && !memcmp(addr, a6, 16)) {
				int idx = 0;
				char* p = line + 33;
				while (hexval(*p) >= 0) idx = idx * 16 + hexval(*p++);
				return idx;
			}
			while (*line && *line != '\n') line++;
			if (*line) line++;
		}
	}
	return 0;
}

// XNU keeps the flag in the inpcb (INP2_CONNECTION_IDLE); here per descriptor, cleared when it is closed
#define IDLE_FDS 8192
static unsigned char idle_flags[IDLE_FDS / 8];

long sockextra_set_idle(int fd, const void* optval, int optlen)
{
	int d = l_domain(fd);
	if (d < 0)
		return -ENOTSOCK;
	if (d != L_AF_INET && d != L_AF_INET6)
		return -EINVAL;
	if (optval == NULL || optlen < (int) sizeof(int))
		return -EINVAL;
	if (fd >= 0 && fd < IDLE_FDS) {
		if (*(const int*) optval)
			idle_flags[fd / 8] |= (unsigned char) (1 << (fd % 8));
		else
			idle_flags[fd / 8] &= (unsigned char) ~(1 << (fd % 8));
	}
	return 0;
}

long sockextra_get_idle(int fd, void* optval, int* optlen)
{
	int d = l_domain(fd);
	if (d < 0)
		return -ENOTSOCK;
	if (d != L_AF_INET && d != L_AF_INET6)
		return -EINVAL;
	if (optlen == NULL)
		return -EFAULT;
	int v = (fd >= 0 && fd < IDLE_FDS) ? !!(idle_flags[fd / 8] & (1 << (fd % 8))) : 0;
	if (optval == NULL) { *optlen = 0; return 0; }
	int n = *optlen < (int) sizeof(v) ? *optlen : (int) sizeof(v);
	if (n < 0)
		return -EINVAL;
	for (int i = 0; i < n; i++) ((char*) optval)[i] = ((char*) &v)[i];
	*optlen = n;
	return 0;
}

// traffic class state per descriptor: the class (SO_TC_*, 0 = SO_TC_BE, XNU's default), the network service type it
// came from (-1: none, SO_NET_SERVICE_TYPE reads NET_SERVICE_TYPE_BE then) and the SO_RECV_TRAFFIC_CLASS flag
#define SO_TC_NET_SERVICE_OFFSET 10000
#define NET_SERVICE_TYPE_RD 8
static short tc_class[IDLE_FDS];
static signed char tc_svc[IDLE_FDS];
static unsigned char tc_recv[IDLE_FDS / 8];
static unsigned char tc_svc_set[IDLE_FDS / 8];
// XNU's sotc_by_netservicetype[] (uipc_socket.c): NET_SERVICE_TYPE_BE..RD -> SO_TC_*
static const short tc_by_svc[NET_SERVICE_TYPE_RD + 1] = { 0, 200, 600, 700, 700, 800, 500, 400, 300 };

static int tc_sock(int fd)
{
	int d = l_domain(fd);
	return d < 0 ? -ENOTSOCK : 0;
}

long sockextra_set_tc(int fd, int optname, const void* optval, int optlen)
{
	int r = tc_sock(fd);
	if (r < 0)
		return r;
	if (optval == NULL || optlen < (int) sizeof(int))
		return -EINVAL;
	int v = *(const int*) optval;
	if (fd < 0 || fd >= IDLE_FDS)
		return 0;
	if (optname == BSD_SO_RECV_TRAFFIC_CLASS) {
		if (v) tc_recv[fd / 8] |= (unsigned char) (1 << (fd % 8));
		else tc_recv[fd / 8] &= (unsigned char) ~(1 << (fd % 8));
		return 0;
	}
	int svc = -1;
	if (optname == BSD_SO_NET_SERVICE_TYPE)
		svc = v;
	else if (v >= SO_TC_NET_SERVICE_OFFSET)
		svc = v - SO_TC_NET_SERVICE_OFFSET;
	if (svc >= 0 || optname == BSD_SO_NET_SERVICE_TYPE) {
		if (svc < 0 || svc > NET_SERVICE_TYPE_RD)
			return -EINVAL;
		tc_class[fd] = tc_by_svc[svc];
		tc_svc[fd] = (signed char) svc;
		tc_svc_set[fd / 8] |= (unsigned char) (1 << (fd % 8));
		return 0;
	}
	// so_set_traffic_class(): SO_TC_BE (0) .. SO_TC_CTL (900); in-between values round to their class (so_tc2msc)
	if (v < 0 || v > 900)
		return -EINVAL;
	tc_class[fd] = (short) (v / 100 * 100);
	tc_svc_set[fd / 8] &= (unsigned char) ~(1 << (fd % 8));
	return 0;
}

long sockextra_get_tc(int fd, int optname, void* optval, int* optlen)
{
	int r = tc_sock(fd);
	if (r < 0)
		return r;
	if (optlen == NULL)
		return -EFAULT;
	int v = 0;
	if (fd >= 0 && fd < IDLE_FDS) {
		if (optname == BSD_SO_RECV_TRAFFIC_CLASS)
			v = !!(tc_recv[fd / 8] & (1 << (fd % 8)));
		else if (optname == BSD_SO_NET_SERVICE_TYPE)
			v = (tc_svc_set[fd / 8] & (1 << (fd % 8))) ? tc_svc[fd] : 0;
		else
			v = tc_class[fd];
	}
	if (optval == NULL) { *optlen = 0; return 0; }
	int n = *optlen < (int) sizeof(v) ? *optlen : (int) sizeof(v);
	if (n < 0)
		return -EINVAL;
	for (int i = 0; i < n; i++) ((char*) optval)[i] = ((char*) &v)[i];
	*optlen = n;
	return 0;
}

static unsigned char anyif_flags[IDLE_FDS / 8], recvif_flags[IDLE_FDS / 8], recvdst_flags[IDLE_FDS / 8], pktinfo_user[IDLE_FDS / 8];
#define BIT(a, fd) ((fd) >= 0 && (fd) < IDLE_FDS && ((a)[(fd) / 8] & (1 << ((fd) % 8))))
static void setbit_(unsigned char* a, int fd, int on)
{
	if (fd < 0 || fd >= IDLE_FDS) return;
	if (on) a[fd / 8] |= (unsigned char) (1 << (fd % 8));
	else a[fd / 8] &= (unsigned char) ~(1 << (fd % 8));
}

void sockextra_note_pktinfo(int fd, int on) { setbit_(pktinfo_user, fd, on); }
int sockextra_recvif(int fd) { return BIT(recvif_flags, fd) ? 1 : 0; }
int sockextra_pktinfo_user(int fd) { return BIT(pktinfo_user, fd) ? 1 : 0; }
int sockextra_recvdst(int fd) { return BIT(recvdst_flags, fd) ? 1 : 0; }

long sockextra_set_flag(int fd, int level, int optname, const void* optval, int optlen)
{
	int d = l_domain(fd);
	if (d < 0)
		return -ENOTSOCK;
	if (optval == NULL || optlen < (int) sizeof(int))
		return -EINVAL;
	int on = *(const int*) optval != 0;
	if (level == 0 && (optname == BSD_IP_RECVIF || optname == BSD_IP_RECVDSTADDR_OPT)) {
		if (d != L_AF_INET && d != L_AF_INET6)
			return -EINVAL;
		// Linux IP_PKTINFO (8) carries the index and the destination; on while any of the three options is
		int other = optname == BSD_IP_RECVIF ? BIT(recvdst_flags, fd) : BIT(recvif_flags, fd);
		int v = on || other || BIT(pktinfo_user, fd);
#ifdef __NR_socketcall
		long r = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SETSOCKOPT, ((long[6]) { fd, 0, 8, &v, sizeof(v), 0 }));
#else
		long r = LINUX_SYSCALL(__NR_setsockopt, fd, 0, 8, &v, sizeof(v));
#endif
		if (r < 0)
			return errno_linux_to_bsd(r);
		setbit_(optname == BSD_IP_RECVIF ? recvif_flags : recvdst_flags, fd, on);
		return 0;
	}
	setbit_(anyif_flags, fd, on); // SO_RECV_ANYIF
	return 0;
}

long sockextra_get_flag(int fd, int level, int optname, void* optval, int* optlen)
{
	if (l_domain(fd) < 0)
		return -ENOTSOCK;
	if (optlen == NULL)
		return -EFAULT;
	int v = (level == 0 && optname == BSD_IP_RECVIF) ? sockextra_recvif(fd)
		: (level == 0 && optname == BSD_IP_RECVDSTADDR_OPT) ? sockextra_recvdst(fd) : (BIT(anyif_flags, fd) ? 1 : 0);
	if (optval == NULL) { *optlen = 0; return 0; }
	int n = *optlen < (int) sizeof(v) ? *optlen : (int) sizeof(v);
	if (n < 0)
		return -EINVAL;
	for (int i = 0; i < n; i++) ((char*) optval)[i] = ((char*) &v)[i];
	*optlen = n;
	return 0;
}

void sockextra_closed(int fd)
{
	setbit_(anyif_flags, fd, 0); setbit_(recvif_flags, fd, 0); setbit_(recvdst_flags, fd, 0); setbit_(pktinfo_user, fd, 0);
	if (fd >= 0 && fd < IDLE_FDS) {
		idle_flags[fd / 8] &= (unsigned char) ~(1 << (fd % 8));
		tc_class[fd] = 0;
		tc_recv[fd / 8] &= (unsigned char) ~(1 << (fd % 8));
		tc_svc_set[fd / 8] &= (unsigned char) ~(1 << (fd % 8));
	}
}

// XNU's struct so_cinforeq (64-bit user), bsd/sys/socket_private.h
struct xnu_so_cinforeq {
	uint32_t scir_cid;
	uint32_t scir_flags;
	uint32_t scir_ifindex;
	int32_t scir_error;
	void* scir_src;
	uint32_t scir_src_len;
	void* scir_dst __attribute__((aligned(8)));
	uint32_t scir_dst_len;
	uint32_t scir_aux_type;
	void* scir_aux_data;
	uint32_t scir_aux_len;
};
_Static_assert(sizeof(struct xnu_so_cinforeq) == 64, "so_cinforeq is 64 bytes");
#define CIF_CONNECTED 0x2
#define CIF_BOUND_IF 0x10
#define CIF_BOUND_IP 0x20
#define CIAUX_TCP 0x1
#define SAE_CONNID_ANY 0
#define SAE_CONNID_ALL ((uint32_t) -1)

long sockextra_conninfo(int fd, void* arg)
{
	struct xnu_so_cinforeq* r = arg;
	int d = l_domain(fd);
	if (d < 0)
		return -ENOTSOCK;
	if (d != L_AF_INET && d != L_AF_INET6)
		return -EINVAL; // as XNU: in_getconninfo is the INET protocols'
	// XNU (in_getconninfo): only SAE_CONNID_ANY/ALL or the socket's one connection (1)
	if (r->scir_cid != SAE_CONNID_ANY && r->scir_cid != SAE_CONNID_ALL && r->scir_cid != 1)
		return -EINVAL;

	uint32_t flags = 0;
	unsigned char sa[128];
	unsigned int len = sizeof(sa);
	if (l_name(fd, 1, sa, &len) >= 0)
		flags |= CIF_CONNECTED;
	int bound = 0;
	len = sizeof(bound);
	if (l_getsockopt(fd, L_SOL_SOCKET, L_SO_BINDTOIFINDEX, &bound, &len) >= 0 && bound > 0)
		flags |= CIF_BOUND_IF;
	int err = 0;
	len = sizeof(err);
	l_getsockopt(fd, L_SOL_SOCKET, L_SO_ERROR, &err, &len);

	r->scir_flags = flags;
	r->scir_ifindex = sockextra_out_ifindex(fd);
	r->scir_error = err ? errno_linux_to_bsd(-err) * -1 : 0;

	// addresses: copied out up to the length given (XNU copies min(len, sa_len) and returns the full length)
	if (r->scir_src && r->scir_src_len > 0) {
		unsigned char tmp[128];
		int l = sizeof(tmp);
		if (sys_getsockname(fd, tmp, &l) == 0) {
			int n = (int) r->scir_src_len < l ? (int) r->scir_src_len : l;
			for (int i = 0; i < n; i++) ((unsigned char*) r->scir_src)[i] = tmp[i];
			r->scir_src_len = l;
		} else r->scir_src_len = 0;
	}
	if (r->scir_dst && r->scir_dst_len > 0) {
		unsigned char tmp[128];
		int l = sizeof(tmp);
		if (sys_getpeername(fd, tmp, &l) == 0) {
			int n = (int) r->scir_dst_len < l ? (int) r->scir_dst_len : l;
			for (int i = 0; i < n; i++) ((unsigned char*) r->scir_dst)[i] = tmp[i];
			r->scir_dst_len = l;
		} else r->scir_dst_len = 0;
	}

	// aux: a TCP socket's tcp_connection_info (CIAUX_TCP), as XNU's tcp_getconninfo()
	int type = 0;
	len = sizeof(type);
	l_getsockopt(fd, L_SOL_SOCKET, 3 /* SO_TYPE */, &type, &len);
	if (type == 1 /* SOCK_STREAM */) {
		r->scir_aux_type = CIAUX_TCP;
		if (r->scir_aux_data && r->scir_aux_len >= sizeof(struct xnu_tcp_connection_info)) {
			int l = sizeof(struct xnu_tcp_connection_info);
			if (tcp_info_option(fd, BSD_TCP_CONNECTION_INFO, r->scir_aux_data, &l) == 0)
				r->scir_aux_len = l;
		} else {
			r->scir_aux_len = sizeof(struct xnu_tcp_connection_info);
		}
	} else {
		r->scir_aux_type = 0;
		r->scir_aux_len = 0;
	}
	return 0;
}

// XNU's IFRTYPE_FUNCTIONAL_* (net/if.h)
#define IFRTYPE_FUNCTIONAL_UNKNOWN 0
#define IFRTYPE_FUNCTIONAL_LOOPBACK 1
#define IFRTYPE_FUNCTIONAL_WIRED 2
#define IFRTYPE_FUNCTIONAL_WIFI_INFRA 3
#define L_SIOCGIFHWADDR 0x8927
#define L_SIOCGIWNAME 0x8b01
#define L_ARPHRD_ETHER 1
#define L_ARPHRD_LOOPBACK 772

// The interface's functional type from Linux's link type: loopback, Wi-Fi (a wireless extension answers SIOCGIWNAME),
// other Ethernet as wired, anything else unknown. Network.framework's nw_path interface type comes from this (it was
// passed through to Linux and failed): GeoServices' GEONetworkObserver counts a satisfied path as reachable only over
// Wi-Fi, cellular or wired, so Maps showed "No Internet Connection" over an "other" interface.
#define L_SIOCGIFMTU 0x8921

long sockextra_mtu(int fd, void* arg)
{
	struct { char name[16]; int mtu; char pad[20]; } q;
	char* ifr = arg;
	memset(&q, 0, sizeof(q));
	for (int i = 0; i < 15 && ifr[i]; i++) q.name[i] = ifr[i];
	long r = LINUX_SYSCALL(__NR_ioctl, fd, L_SIOCGIFMTU, &q);
	if (r < 0)
		return errno_linux_to_bsd(r);
	*(int*) (ifr + 16) = q.mtu;
	return 0;
}

#define L_SIOCGIFFLAGS 0x8913
long sockextra_ifflags(int fd, void* arg)
{
	struct { char name[16]; union { short flags; struct { uint16_t family; char data[14]; } hw; char pad[24]; }; } q;
	char* ifr = arg;
	memset(&q, 0, sizeof(q));
	for (int i = 0; i < 15 && ifr[i]; i++) q.name[i] = ifr[i];
	long r = LINUX_SYSCALL(__NR_ioctl, fd, L_SIOCGIFFLAGS, &q);
	if (r < 0)
		return errno_linux_to_bsd(r);
	unsigned int lf = (unsigned short) q.flags;
	// the low ten bits are Darwin's too except 0x400 (Linux IFF_MASTER, Darwin IFF_OACTIVE); IFF_MULTICAST 0x1000 -> 0x8000
	unsigned int f = lf & 0x3ff;
	if (lf & 0x1000)
		f |= 0x8000;
	memset(&q, 0, sizeof(q));
	for (int i = 0; i < 15 && ifr[i]; i++) q.name[i] = ifr[i];
	if (LINUX_SYSCALL(__NR_ioctl, fd, L_SIOCGIFHWADDR, &q) >= 0 && q.hw.family == L_ARPHRD_ETHER)
		f |= 0x800; // IFF_SIMPLEX: an Ethernet interface can't hear its own transmissions, as Darwin's say
	*(short*) (ifr + 16) = (short) f;
	return 0;
}

long sockextra_functional_type(int fd, void* arg)
{
	struct { char name[16]; union { struct { uint16_t family; char data[14]; } hw; uint32_t ftype; char pad[16]; }; } q;
	char* ifr = arg;
	memset(&q, 0, sizeof(q));
	for (int i = 0; i < 15 && ifr[i]; i++) q.name[i] = ifr[i];
	long r = LINUX_SYSCALL(__NR_ioctl, fd, L_SIOCGIFHWADDR, &q);
	if (r < 0)
		return errno_linux_to_bsd(r); // ENXIO for an unknown interface, as XNU
	uint32_t type = IFRTYPE_FUNCTIONAL_UNKNOWN;
	if (q.hw.family == L_ARPHRD_LOOPBACK)
		type = IFRTYPE_FUNCTIONAL_LOOPBACK;
	else if (q.hw.family == L_ARPHRD_ETHER) {
		char w[32];
		memset(w, 0, sizeof(w));
		for (int i = 0; i < 15 && ifr[i]; i++) w[i] = ifr[i];
		type = LINUX_SYSCALL(__NR_ioctl, fd, L_SIOCGIWNAME, w) >= 0 ? IFRTYPE_FUNCTIONAL_WIFI_INFRA : IFRTYPE_FUNCTIONAL_WIRED;
	}
	*(uint32_t*) (ifr + 16) = type;
	return 0;
}
