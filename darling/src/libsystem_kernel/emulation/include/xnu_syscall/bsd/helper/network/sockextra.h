#ifndef NETWORK_SOCKEXTRA_H
#define NETWORK_SOCKEXTRA_H
// x86Sim: socket options and ioctls Network.framework asks for that Linux has no direct counterpart of, answered as
// XNU does (see FINDINGS.md "Spike 3.10"): IP_OUT_IF/IPV6_OUT_IF, SO_CONNECTION_IDLE, TCP_NOTSENT_LOWAT, SIOCGCONNINFO.

#define BSD_IP_OUT_IF 9696          // netinet/in_private.h (IPPROTO_IP), get only
#define BSD_IPV6_OUT_IF 9696        // netinet6/in6_private.h (IPPROTO_IPV6), get only
#define BSD_SO_CONNECTION_IDLE 0x1137 // sys/socket_private.h (SOL_SOCKET), int
#define BSD_SO_DEFUNCTOK 0x1100     // sys/socket_private.h (SOL_SOCKET), int: may be defuncted (default 1)
#define BSD_TCP_NOTSENT_LOWAT 0x201 // netinet/tcp.h
#define LINUX_TCP_NOTSENT_LOWAT 25
#define BSD_SIOCGCONNINFO 0xc0407398U // _IOWR('s', 152, struct so_cinforeq), 64 bytes on 64-bit

// the interface index the socket's traffic leaves through (0 if none yet), as XNU's inp_last_outifp
int sockextra_out_ifindex(int fd);
// SO_CONNECTION_IDLE, kept per descriptor: 0 or a negative BSD errno
long sockextra_set_idle(int fd, const void* optval, int optlen);
long sockextra_get_idle(int fd, void* optval, int* optlen);
// x86Sim: XNU's traffic class options (sys/socket.h): SO_TRAFFIC_CLASS (int: SO_TC_BE 0 ... SO_TC_CTL 900, or
// SO_TC_NET_SERVICE_OFFSET + a network service type), SO_RECV_TRAFFIC_CLASS (int flag), SO_NET_SERVICE_TYPE (int,
// NET_SERVICE_TYPE_BE 0 ... NET_SERVICE_TYPE_RD 8). Linux has no counterpart (SO_PRIORITY is not the same scale): kept
// per descriptor, validated as XNU's sosetoptlock() does. nsurlsessiond puts every background session's socket in
// SO_TC_BK; EINVAL there made Network.framework's nw_socket_add_input_handler fail the flow ("Failed to initialize
// socket"): a background URLSession download never connected and timed out (-1001) forever.
#define BSD_SO_TRAFFIC_CLASS 0x1086
#define BSD_SO_RECV_TRAFFIC_CLASS 0x1087
#define BSD_SO_NET_SERVICE_TYPE 0x1116
long sockextra_set_tc(int fd, int optname, const void* optval, int optlen);
// x86Sim: SO_RECV_ANYIF (sys/socket_private.h, int): XNU's "receive on any interface, even a restricted one"; there are
// no restricted interfaces here: kept and read back. Its EINVAL failed every NSNetService listening socket
// (tcp_listener_socket_create): MCNearbyServiceAdvertiser reported NSNetServicesErrorDomain 22 and advertised nothing.
#define BSD_SO_RECV_ANYIF 0x1104
// IP_RECVIF (netinet/in.h 20, int): each datagram's receiving interface as an IP_RECVIF control message holding a
// struct sockaddr_dl. Linux's IP_PKTINFO carries the interface index: turned on underneath and converted in
// recvmsg() (sockextra_recvif_cmsg). ENOTSUP failed Network.framework's multicast inbox (NWConnectionGroup).
#define BSD_IP_RECVIF 20
// IP_RECVDSTADDR (netinet/in.h 7, int): each datagram's destination address as an IP_RECVDSTADDR control message (a
// struct in_addr), from IP_PKTINFO's ipi_addr the same way (Network.framework's multicast inbox asks for it too)
#define BSD_IP_RECVDSTADDR_OPT 7
long sockextra_set_flag(int fd, int level, int optname, const void* optval, int optlen);
long sockextra_get_flag(int fd, int level, int optname, void* optval, int* optlen);
// IP_PKTINFO as the program asked for it (so IP_RECVIF's own use of it stays invisible)
void sockextra_note_pktinfo(int fd, int on);
int sockextra_recvif(int fd);          // IP_RECVIF on
int sockextra_recvdst(int fd);         // IP_RECVDSTADDR on
int sockextra_pktinfo_user(int fd);    // IP_PKTINFO asked for by the program
long sockextra_get_tc(int fd, int optname, void* optval, int* optlen);
// forget a closed descriptor's state
void sockextra_closed(int fd);
// SIOCGIFFUNCTIONALTYPE (XNU's ifnet_functional_type()): ifr is a struct ifreq; returns 0 or a negative BSD errno
#define BSD_SIOCGIFFUNCTIONALTYPE 0xc02069adU // _IOWR('i', 173, struct ifreq)
long sockextra_functional_type(int fd, void* ifr);
// x86Sim: XNU never blocks a send on a local datagram socket: a full receiver fails it with ENOBUFS (uipc_send()'s
// sbappendaddr()), where Linux sleeps until there is room. launchd_sim's dispatch workers log (os_log_simple_send())
// into launchd_sim's own CoreSimulator log socket; on a first boot they filled it, slept in sendto() with no worker
// left to drain it (Darling has no workqueue to add threads), and launchd_sim stopped answering bootstrap check-ins:
// every process hung in libxpc's initializer. 1 for an AF_UNIX SOCK_DGRAM socket: send it MSG_DONTWAIT, EAGAIN
// becomes ENOBUFS (sendto.c, sendmsg.c).
int sockextra_unix_dgram(int fd);
// x86Sim: SIOCGIFFLAGS (Linux's, with its flags in Darwin's numbers as NET_RT_IFLIST gives them, ifinfo.c bsd_flags()):
// 0 or a negative BSD errno. Network.framework's multicast listener (NWConnectionGroup) checks IFF_MULTICAST this way;
// ENOTSUP made it log "Interface ... doesn't support multicast" and fail the group with EINVAL.
long sockextra_ifflags(int fd, void* ifr);
// SIOCGIFMTU (Linux SIOCGIFMTU on the same ifreq layout: name[16], int at +16): 0 or a negative BSD errno
long sockextra_mtu(int fd, void* ifr);
// SIOCGCONNINFO (XNU's in_getconninfo()/in6_getconninfo())
long sockextra_conninfo(int fd, void* arg);
#endif
