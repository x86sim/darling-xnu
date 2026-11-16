#include <darling/emulation/xnu_syscall/bsd/impl/network/recvmsg.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <sys/errno.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/conversion/network/getsockopt.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/getsockopt.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockextra.h>

extern void *malloc(__SIZE_TYPE__ size);
extern void free(void* ptr);
extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ len);

#define ALIGN(what, how) ( ((what) + (how) - 1) & ~((how) - 1) )

long sys_recvmsg(int socket, struct bsd_msghdr* msg, int flags)
{
	CANCELATION_POINT();
	return sys_recvmsg_nocancel(socket, msg, flags);
}

long sys_recvmsg_nocancel(int socket, struct bsd_msghdr* msg, int flags)
{
	int ret, linux_flags;
	struct linux_msghdr lmsg;
	struct linux_cmsghdr* lchdr = NULL;

	lmsg.msg_name = msg->msg_name;
	lmsg.msg_namelen = msg->msg_namelen;
	lmsg.msg_iov = msg->msg_iov;
	lmsg.msg_iovlen = msg->msg_iovlen;

	if (sizeof(unsigned long) == 4)
	{
		lmsg.msg_control = msg->msg_control;
		lmsg.msg_controllen = msg->msg_controllen;
	}
	else if (msg->msg_control != NULL && msg->msg_controllen > 0)
	{
		// __simple_printf("controllen=%d\n", msg->msg_controllen);
		lmsg.msg_controllen = LINUX_CMSG_ALIGN(msg->msg_controllen + LINUX_BSD_CMSGHDR_SIZE_DIFFERENCE); // FIXME: there could be multiple control messages in a message
		lchdr = (struct linux_cmsghdr*) malloc(lmsg.msg_controllen);
		if (lchdr == NULL)
		{
			return -ENOMEM;
		}

		lmsg.msg_control = lchdr;
	}
	else
	{
		lmsg.msg_control = NULL;
		lmsg.msg_controllen = 0;
	}

	lmsg.msg_flags = 0; // set on return

	linux_flags = msgflags_bsd_to_linux(flags);

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_RECVMSG,
			((long[6]) { socket, &lmsg, linux_flags }));
#else
	ret = LINUX_SYSCALL(__NR_recvmsg, socket, &lmsg, linux_flags);
#endif

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else
	{
		struct bsd_cmsghdr* bchdr;
		msg->msg_flags = msgflags_linux_to_bsd(lmsg.msg_flags);

		bchdr = (struct bsd_cmsghdr*) msg->msg_control;

		if (bchdr != NULL)
		{
			if (sizeof(unsigned long) != 4)
			{
				int lpos = 0, bpos = 0;
				struct linux_cmsghdr* lnext;
				struct bsd_cmsghdr* bnext;
				// x86Sim: IP_RECVIF (sockextra.h) from Linux's IP_PKTINFO; the IP_PKTINFO message itself only if
				// the program asked for it
				int recvif = sockextra_recvif(socket), recvdst = sockextra_recvdst(socket), pktuser = sockextra_pktinfo_user(socket);
				unsigned int bcap = msg->msg_controllen;

				msg->msg_controllen = lmsg.msg_controllen;

				// __simple_printf("Processing %d bytes of control data\n", msg->msg_controllen);
				while (lpos < lmsg.msg_controllen)
				{
					lnext = (struct linux_cmsghdr*) (((char*) lmsg.msg_control) + lpos);
					bnext = (struct bsd_cmsghdr*) (((char*) msg->msg_control) + bpos);

					if ((recvif || recvdst) && lnext->cmsg_level == 0 && lnext->cmsg_type == LINUX_IP_PKTINFO
					    && lnext->cmsg_len >= sizeof(struct linux_cmsghdr) + 12) {
						// XNU's ip_savecontrol() order: IP_RECVDSTADDR, then IP_RECVIF
						if (recvdst && bpos + BSD_CMSG_SPACE(4) <= bcap) {
							bnext->cmsg_len = BSD_CMSG_LEN(4);
							bnext->cmsg_level = 0;
							bnext->cmsg_type = BSD_IP_RECVDSTADDR_OPT;
							memcpy(bnext->cmsg_data, lnext->cmsg_data + 8, 4); // in_pktinfo.ipi_addr: the header's destination
							bpos += BSD_CMSG_SPACE(4);
							bnext = (struct bsd_cmsghdr*) (((char*) msg->msg_control) + bpos);
						}
						int ifindex = *(const int*) lnext->cmsg_data; // struct in_pktinfo: ipi_ifindex first
						// XNU's ip_savecontrol(): a struct sockaddr_dl (20 bytes) of the interface; only its index
						// here (sdl_nlen / sdl_alen 0, as XNU sends when the interface has no link address)
						unsigned char sdl[20] = { 20, 18 /* AF_LINK */ };
						sdl[2] = (unsigned char) ifindex; sdl[3] = (unsigned char) (ifindex >> 8);
						if (recvif && bpos + BSD_CMSG_SPACE(sizeof(sdl)) <= bcap) {
							struct bsd_cmsghdr* r = bnext;
							r->cmsg_len = BSD_CMSG_LEN(sizeof(sdl));
							r->cmsg_level = 0;
							r->cmsg_type = BSD_IP_RECVIF;
							memcpy(r->cmsg_data, sdl, sizeof(sdl));
							bpos += BSD_CMSG_SPACE(sizeof(sdl));
						}
						if (!pktuser) {
							lpos += ALIGN(lnext->cmsg_len, sizeof(unsigned long));
							continue;
						}
						bnext = (struct bsd_cmsghdr*) (((char*) msg->msg_control) + bpos);
						if (bpos + BSD_CMSG_SPACE(lnext->cmsg_len - sizeof(struct linux_cmsghdr)) > bcap)
							break;
					}

					// __simple_printf("Linux msg at %d -> BSD at %d\n", lpos, bpos);

					bnext->cmsg_len = lnext->cmsg_len - LINUX_BSD_CMSGHDR_SIZE_DIFFERENCE;
					bnext->cmsg_level = socket_level_linux_to_bsd(lnext->cmsg_level);
					bnext->cmsg_type = cmsg_type_linux_to_bsd(bnext->cmsg_level, lnext->cmsg_type);

					// __simple_printf("About to copy %d bytes\n", lnext->cmsg_len - sizeof(struct linux_cmsghdr));

					size_t actual_data_size = lnext->cmsg_len - sizeof(struct linux_cmsghdr);
					memcpy(bnext->cmsg_data, lnext->cmsg_data, actual_data_size);
					msg->msg_controllen -= LINUX_CMSG_SPACE(actual_data_size) - BSD_CMSG_SPACE(actual_data_size);

					lpos += ALIGN(lnext->cmsg_len, sizeof(unsigned long));
					bpos += ALIGN(bnext->cmsg_len, 4);
				}
				if (recvif || recvdst)
					msg->msg_controllen = bpos; // the messages as written (the size arithmetic above assumes 1:1)
			}
			else
			{
				msg->msg_controllen = lmsg.msg_controllen;
			}
		}

		// x86Sim: the sender's address as recvfrom gives it (sockaddr_fixup_from_linux: sa_len set, bounded by the
		// caller's buffer). Only the family byte was patched here, so sa_len kept the low byte of Linux's family
		// (AF_INET6 10): Network.framework's UDP listener connect()ed its per-flow socket to the sender with that
		// length (EINVAL) and NWListener over UDP never delivered a datagram.
		if (lmsg.msg_name != NULL && lmsg.msg_namelen > 0)
		{
			int n = sockaddr_fixup_from_linux((struct sockaddr_fixup*) msg->msg_name, lmsg.msg_name, lmsg.msg_namelen, msg->msg_namelen);
			if (n < 0)
				ret = n;
			else
				msg->msg_namelen = n;
		}
		else
			msg->msg_namelen = lmsg.msg_namelen;
	}

	if (lchdr != NULL)
		free(lchdr);

	// the error XNU's soreceive() would return (sostate.h)
	if (ret <= 0 && SOCKET_RECV_HOOKED(ret))
		ret = socket_error_read(socket, ret, flags & BSD_MSG_PEEK, 1);

	// __simple_printf("Returning %d\n", ret);
	return ret;
}
