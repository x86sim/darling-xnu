// sysctl net.route.0.<af>.NET_RT_IFLIST2.<index> through sysctl_net.c and ifinfo.c, against Linux's rtnetlink:
// RTM_IFINFO2 (if_msghdr2 + sockaddr_dl) per interface with if_data64 counters, then its RTM_NEWADDRs, as XNU's
// sysctl_iflist2(). Built with Darling's headers.
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_net.h>
#include "check.h"

void* malloc(unsigned long);
int memcmp(const void*, const void*, unsigned long);
unsigned long long host_sysfs(const char* ifname, const char* file);
unsigned int host_if_index(const char* ifname);
void host_lo_traffic(int count);

#define ROUNDUP32(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

static long route_sysctl(int op, int index, void* old, unsigned long* len)
{
	int name[6] = { CTL_NET, PF_ROUTE, 0, 0, op, index };
	return sysctls_net[0].handler(name, 6, old, len, 0, 0);
}

struct walk {
	int links, addrs, other, bad_len, bad_sdl;
	struct if_msghdr2* lo;
};

static void walk(char* buf, unsigned long len, int v2, struct walk* w)
{
	for (char* p = buf; p < buf + len; ) {
		struct if_msghdr* ifm = (void*) p;
		if (ifm->ifm_msglen == 0)
			break;
		if (ifm->ifm_type == (v2 ? RTM_IFINFO2 : RTM_IFINFO)) {
			unsigned long hdr = v2 ? sizeof(struct if_msghdr2) : sizeof(struct if_msghdr);
			struct sockaddr_dl* sdl = (void*) (p + hdr);
			w->links++;
			if (ifm->ifm_msglen != hdr + ROUNDUP32(sdl->sdl_len) || ifm->ifm_version != RTM_VERSION)
				w->bad_len++;
			if (sdl->sdl_family != AF_LINK || sdl->sdl_index != ifm->ifm_index || !(ifm->ifm_addrs & RTA_IFP))
				w->bad_sdl++;
			if (v2 && sdl->sdl_nlen == 2 && memcmp(sdl->sdl_data, "lo", 2) == 0)
				w->lo = (void*) p;
		} else if (ifm->ifm_type == RTM_NEWADDR) {
			w->addrs++;
		} else {
			w->other++;
		}
		p += ifm->ifm_msglen;
	}
}

int main(void)
{
	unsigned long len = 0, len1 = 0;
	long ret;

	printf("sizeof(struct if_msghdr) %lu, sizeof(struct if_msghdr2) %lu\n",
		(unsigned long) sizeof(struct if_msghdr), (unsigned long) sizeof(struct if_msghdr2));

	ret = route_sysctl(NET_RT_IFLIST2, 0, 0, &len);
	CHECK(ret == 0 && len > 0, "NET_RT_IFLIST2 size query: %ld, %lu bytes", ret, len);
	if (ret != 0)
		DONE();

	unsigned long short_len = len - 1;
	char* buf = malloc(len + 4096);
	ret = route_sysctl(NET_RT_IFLIST2, 0, buf, &short_len);
	CHECK(ret == -ENOMEM, "a buffer one byte short: -ENOMEM (%ld)", ret);

	host_lo_traffic(8);
	unsigned long long rx0 = host_sysfs("lo", "statistics/rx_packets"), rxb0 = host_sysfs("lo", "statistics/rx_bytes");
	len += 4096;
	ret = route_sysctl(NET_RT_IFLIST2, 0, buf, &len);
	unsigned long long rx1 = host_sysfs("lo", "statistics/rx_packets"), rxb1 = host_sysfs("lo", "statistics/rx_bytes");
	CHECK(ret == 0, "NET_RT_IFLIST2: %ld, %lu bytes", ret, len);

	struct walk w = { 0 };
	walk(buf, len, 1, &w);
	CHECK(w.links > 0 && w.bad_len == 0 && w.bad_sdl == 0 && w.other == 0,
		"%d RTM_IFINFO2 (%d bad length, %d bad sockaddr_dl), %d RTM_NEWADDR, %d other",
		w.links, w.bad_len, w.bad_sdl, w.addrs, w.other);
	CHECK(w.lo != 0, "lo is listed");
	if (!w.lo)
		DONE();

	struct if_msghdr2* lo = w.lo;
	CHECK(lo->ifm_index == host_if_index("lo"), "lo index %u (Linux %u)", lo->ifm_index, host_if_index("lo"));
	CHECK(lo->ifm_data.ifi_type == IFT_LOOP && (lo->ifm_flags & IFF_LOOPBACK), "lo: IFT_LOOP, IFF_LOOPBACK");
	CHECK(lo->ifm_data.ifi_mtu == host_sysfs("lo", "mtu"), "lo mtu %u", lo->ifm_data.ifi_mtu);
	CHECK(lo->ifm_snd_maxlen == (int) host_sysfs("lo", "tx_queue_len"), "lo ifm_snd_maxlen %d = tx_queue_len",
		lo->ifm_snd_maxlen);
	CHECK(lo->ifm_data.ifi_ipackets > 0 && lo->ifm_data.ifi_ipackets >= rx0 && lo->ifm_data.ifi_ipackets <= rx1,
		"lo ipackets %llu, Linux %llu..%llu", lo->ifm_data.ifi_ipackets, rx0, rx1);
	CHECK(lo->ifm_data.ifi_ibytes >= rxb0 && lo->ifm_data.ifi_ibytes <= rxb1,
		"lo ibytes %llu, Linux %llu..%llu", lo->ifm_data.ifi_ibytes, rxb0, rxb1);

	// NET_RT_IFLIST lists the same, with the shorter header
	ret = route_sysctl(NET_RT_IFLIST, 0, 0, &len1);
	char* buf1 = malloc(len1 + 4096);
	len1 += 4096;
	ret = route_sysctl(NET_RT_IFLIST, 0, buf1, &len1);
	struct walk w1 = { 0 };
	walk(buf1, len1, 0, &w1);
	CHECK(ret == 0 && w1.links == w.links && w1.addrs == w.addrs && w1.bad_len == 0
		&& len - len1 == w.links * (sizeof(struct if_msghdr2) - sizeof(struct if_msghdr)),
		"NET_RT_IFLIST: %d RTM_IFINFO, %d RTM_NEWADDR, %lu bytes", w1.links, w1.addrs, len1);

	// one interface
	len = 0;
	route_sysctl(NET_RT_IFLIST2, lo->ifm_index, 0, &len);
	char* one = malloc(len);
	ret = route_sysctl(NET_RT_IFLIST2, lo->ifm_index, one, &len);
	struct walk w2 = { 0 };
	walk(one, len, 1, &w2);
	CHECK(ret == 0 && w2.links == 1 && w2.lo != 0, "index %u: just lo (%d RTM_IFINFO2, %d RTM_NEWADDR)",
		lo->ifm_index, w2.links, w2.addrs);
	DONE();
}
