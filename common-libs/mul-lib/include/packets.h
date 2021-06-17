/**
 * packets.h - Different protocol header definitions
 * Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef __PACKETS_H__
#define __PACKETS_H__ 1

#include <stdint.h>
#include <string.h>
#include "c_util.h"

#define ETH_ADDR_LEN           6

static const uint8_t eth_addr_broadcast[ETH_ADDR_LEN] UNUSED
    = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static inline bool eth_addr_is_broadcast(const uint8_t ea[6])
{
    return (ea[0] & ea[1] & ea[2] & ea[3] & ea[4] & ea[5]) == 0xff;
}
static inline bool eth_addr_is_multicast(const uint8_t ea[6])
{
    return ea[0] & 1;
}
static inline bool eth_addr_is_local(const uint8_t ea[6]) 
{
    return ea[0] & 2;
}
static inline bool eth_addr_is_zero(const uint8_t ea[6]) 
{
    return !(ea[0] | ea[1] | ea[2] | ea[3] | ea[4] | ea[5]);
}
static inline bool eth_addr_equals(const uint8_t a[ETH_ADDR_LEN],
                                   const uint8_t b[ETH_ADDR_LEN]) 
{
    return !memcmp(a, b, ETH_ADDR_LEN);
}
static inline uint64_t eth_addr_to_uint64(const uint8_t ea[ETH_ADDR_LEN])
{
    return (((uint64_t) ea[0] << 40)
            | ((uint64_t) ea[1] << 32)
            | ((uint64_t) ea[2] << 24)
            | ((uint64_t) ea[3] << 16)
            | ((uint64_t) ea[4] << 8)
            | ea[5]);
}
static inline void eth_addr_from_uint64(uint64_t x, uint8_t ea[ETH_ADDR_LEN])
{
    ea[0] = x >> 40;
    ea[1] = x >> 32;
    ea[2] = x >> 24;
    ea[3] = x >> 16;
    ea[4] = x >> 8;
    ea[5] = x;
}
static inline bool ipv4_is_multicast(uint32_t addr)
{
    return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
}
static inline bool ipv4_is_zero(uint32_t addr)
{
    return addr == 0x0;
}
#if 0
static inline void eth_addr_random(uint8_t ea[ETH_ADDR_LEN])
{
    random_bytes(ea, ETH_ADDR_LEN);
    ea[0] &= ~1;                /* Unicast. */
    ea[0] |= 2;                 /* Private. */
}
#endif

/* Returns true if 'ea' is a reserved multicast address, that a bridge must
 * never forward, false otherwise. */
static inline bool eth_addr_is_reserved(const uint8_t ea[ETH_ADDR_LEN])
{
    return (ea[0] == 0x01
            && ea[1] == 0x80
            && ea[2] == 0xc2
            && ea[3] == 0x00
            && ea[4] == 0x00
            && (ea[5] & 0xf0) == 0x00);
}

#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_ARGS(ea)                                   \
    (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]

#define ETH_TYPE_IP            0x0800
#define ETH_TYPE_IPV6          0x86dd
#define ETH_TYPE_ARP           0x0806
#define ETH_TYPE_VLAN          0x8100
#define ETH_TYPE_SVLAN         0x88a8
#define ETH_TYPE_LLDP          0x88cc
#define ETH_TYPE_IPV6          0x86dd
#define ETH_TYPE_LACP          0x8809
#define ETH_TYPE_RARP          0x8035
#define ETH_TYPE_MPLS          0x8847
#define ETH_TYPE_MPLS_MCAST    0x8848
#define ETH_TYPE_PBB           0x88E7

/* Standard well-defined IP protocols.  */
enum {
  IP_TYPE_IP = 0,       /* Dummy protocol for TCP */
  IP_TYPE_ICMP = 1,     /* Internet Control Message Protocol */
  IP_TYPE_IGMP = 2,     /* Internet Group Management Protocol */
  IP_TYPE_IPIP = 4,     /* IPIP tunnels (older KA9Q tunnels use 94) */
  IP_TYPE_TCP = 6,      /* Transmission Control Protocol */
  IP_TYPE_EGP = 8,      /* Exterior Gateway Protocol */
  IP_TYPE_PUP = 12,     /* PUP protocol */
  IP_TYPE_UDP = 17,     /* User Datagram Protocol */
  IP_TYPE_IDP = 22,     /* XNS IDP protocol */
  IP_TYPE_DCCP = 33,    /* Datagram Congestion Control Protocol */
  IP_TYPE_RSVP = 46,    /* RSVP protocol */
  IP_TYPE_GRE = 47,     /* Cisco GRE tunnels (rfc 1701,1702) */

  IP_TYPE_IPV6 = 41,    /* IPv6-in-IPv4 tunnelling */

  IP_TYPE_ESP = 50,     /* Encapsulation Security Payload protocol */
  IP_TYPE_AH = 51,      /* Authentication Header protocol */
  IP_TYPE_BEETPH = 94,  /* IP option pseudo header for BEET */
  IP_TYPE_PIM = 103,    /* Protocol Independent Multicast */

  IP_TYPE_COMP = 108,   /* Compression Header protocol */
  IP_TYPE_SCTP = 132,   /* Stream Control Transport Protocol */
  IP_TYPE_UDPLITE = 136,/* UDP-Lite (RFC 3828) */

  IP_TYPE_RAW = 255,    /* Raw IP packets */
  IP_TYPE_MAX
};

#define ETH_HEADER_LEN 14
#define ETH_PAYLOAD_MIN 46
#define ETH_PAYLOAD_MAX 1500
#define ETH_TOTAL_MIN (ETH_HEADER_LEN + ETH_PAYLOAD_MIN)
#define ETH_TOTAL_MAX (ETH_HEADER_LEN + ETH_PAYLOAD_MAX)
#define ETH_VLAN_TOTAL_MAX (ETH_HEADER_LEN + VLAN_HEADER_LEN + ETH_PAYLOAD_MAX)

struct eth_header {
    uint8_t eth_dst[ETH_ADDR_LEN];
    uint8_t eth_src[ETH_ADDR_LEN];
    uint16_t eth_type;
} __attribute__((packed));

#define LLC_DSAP_SNAP 0xaa
#define LLC_SSAP_SNAP 0xaa
#define LLC_CNTL_SNAP 3

#define LLC_HEADER_LEN 3
struct llc_header {
    uint8_t llc_dsap;
    uint8_t llc_ssap;
    uint8_t llc_cntl;
} __attribute__((packed));

#define SNAP_ORG_ETHERNET "\0\0" /* The compiler adds a null byte, so
                                    sizeof(SNAP_ORG_ETHERNET) == 3. */
#define SNAP_HEADER_LEN 5
struct snap_header {
    uint8_t snap_org[3];
    uint16_t snap_type;
} __attribute__((packed));

#define LLC_SNAP_HEADER_LEN (LLC_HEADER_LEN + SNAP_HEADER_LEN)
struct llc_snap_header {
    struct llc_header llc;
    struct snap_header snap;
} __attribute__((packed));

#define VLAN_VID_MASK 0x0fff
#define VLAN_PCP_MASK 0xe000
#define VLAN_PCP_SHIFT 13
#define VLAN_PCP_BITMASK 0x0007 /* the least 3-bit is valid */

#define VLAN_HEADER_LEN 4
struct vlan_header {
    uint16_t vlan_tci;          /* Lowest 12 bits are VLAN ID. */
    uint16_t vlan_next_type;
};

#define VLAN_ETH_HEADER_LEN (ETH_HEADER_LEN + VLAN_HEADER_LEN)
struct vlan_eth_header {
    uint8_t veth_dst[ETH_ADDR_LEN];
    uint8_t veth_src[ETH_ADDR_LEN];
    uint16_t veth_type;         /* Always htons(ETH_TYPE_VLAN). */
    uint16_t veth_tci;          /* Lowest 12 bits are VLAN ID. */
    uint16_t veth_next_type;
} __attribute__((packed));

/* The "(void) (ip)[0]" below has no effect on the value, since it's the first
 * argument of a comma expression, but it makes sure that 'ip' is a pointer.
 * This is useful since a common mistake is to pass an integer instead of a
 * pointer to IP_ARGS. */
#define IP_FMT "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8
#define IP_ARGS(ip)                             \
        ((void) (ip)[0], ((uint8_t *) ip)[0]),  \
        ((uint8_t *) ip)[1],                    \
        ((uint8_t *) ip)[2],                    \
        ((uint8_t *) ip)[3]

#define IP_VER(ip_ihl_ver) ((ip_ihl_ver) >> 4)
#define IP_IHL(ip_ihl_ver) ((ip_ihl_ver) & 15)
#define IP_IHL_VER(ihl, ver) (((ver) << 4) | (ihl))

#define IP_VERSION 4

#define IP_DONT_FRAGMENT  0x4000 /* Don't fragment. */
#define IP_MORE_FRAGMENTS 0x2000 /* More fragments. */
#define IP_FRAG_OFF_MASK  0x1fff /* Fragment offset. */
#define IP_IS_FRAGMENT(ip_frag_off) \
        ((ip_frag_off) & htons(IP_MORE_FRAGMENTS | IP_FRAG_OFF_MASK))

#define IP_ADDR_LEN 4
#define IP_HEADER_LEN 20
struct ip_header {
    uint8_t ip_ihl_ver;
    uint8_t ip_tos;
    uint16_t ip_tot_len;
    uint16_t ip_id;
    uint16_t ip_frag_off;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    uint16_t ip_csum;
    uint32_t ip_src;
    uint32_t ip_dst;
};

struct ipv6_addr {
    union {
        uint8_t     u6_addr8[16];
        uint16_t    u6_addr16[8];
        uint32_t    u6_addr32[4];
    } __in6_u;
};
#define ip6_addr        __in6_u.u6_addr8
#define ip6_addr16      __in6_u.u6_addr16
#define ip6_addr32      __in6_u.u6_addr32

struct ipv6_header {
    uint32_t ver_tc_label;
    uint16_t len;
    uint8_t next_header;
    uint8_t hop_limit;
    struct ipv6_addr src;
    struct ipv6_addr dest;
} __attribute__ (( packed ));

struct icmp6_header
{
    unsigned int icmp6_type;
    unsigned int icmp6_code;
    uint16_t icmp6_cksum;

    union {
        uint32_t un_data32[1];
        uint16_t un_data16[2];
        unsigned int un_data8[4];

        struct icmpv6_echo {
            uint16_t identifier;
            uint16_t sequence;
        }u_echo;

        struct icmpv6_nd_advt {
            uint32_t nd_advt;
        }u_nd_advt;

        struct icmpv6_nd_ra {
            unsigned int hop_limit;
            unsigned int ra_prop;
            uint16_t rt_lifetime;
        }u_nd_ra;
    }icmp6_dataun;
};

#define NEXTHDR_HOP      0   /* Hop-by-hop option header. */
#define NEXTHDR_TCP      6   /* TCP segment. */
#define NEXTHDR_UDP      17  /* UDP message. */
#define NEXTHDR_IPV6     41  /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING  43  /* Routing header. */
#define NEXTHDR_FRAGMENT 44  /* Fragmentation/reassembly header. */
#define NEXTHDR_ESP      50  /* Encapsulating security payload. */
#define NEXTHDR_AUTH     51  /* Authentication header. */
#define NEXTHDR_ICMP     58  /* ICMP for IPv6. */
#define NEXTHDR_NONE     59  /* No next header */
#define NEXTHDR_DEST     60  /* Destination options header. */
#define NEXTHDR_MOBILITY 135 /* Mobility header. */
#define NEXTHDR_MAX      255

static inline bool
ipv6_addr_equal(const struct ipv6_addr *a1,
                const struct ipv6_addr *a2)
{
    return ((a1->ip6_addr32[0] ^ a2->ip6_addr32[0]) |
            (a1->ip6_addr32[1] ^ a2->ip6_addr32[1]) |
            (a1->ip6_addr32[2] ^ a2->ip6_addr32[2]) |
            (a1->ip6_addr32[3] ^ a2->ip6_addr32[3])) == 0;
}

static inline bool 
ipv6_addr_nonzero(const struct ipv6_addr *a1)
{
    return (a1->ip6_addr32[0] | a1->ip6_addr32[1] |
            a1->ip6_addr32[2] | a1->ip6_addr32[3]); 
}

static inline bool 
ipv6_addr_mask_equal(const struct ipv6_addr *a1, const struct ipv6_addr *m1,
                     const struct ipv6_addr *a2)
{
    struct ipv6_addr x;
    
    x.ip6_addr32[0]  = a1->ip6_addr32[0] & m1->ip6_addr32[0];
    x.ip6_addr32[1]  = a1->ip6_addr32[1] & m1->ip6_addr32[1];
    x.ip6_addr32[2]  = a1->ip6_addr32[2] & m1->ip6_addr32[2];
    x.ip6_addr32[3]  = a1->ip6_addr32[3] & m1->ip6_addr32[3];

    return ipv6_addr_equal(&x, a2); 
}

static inline void
__ipv6_addr_set_half(uint32_t *addr,
                     uint32_t wh,
                     uint32_t wl)
{
    addr[0] = wh;
    addr[1] = wl;
}
 
static inline void ipv6_addr_set(struct ipv6_addr *addr, 
                                 uint32_t w1, uint32_t w2,
                                 uint32_t w3, uint32_t w4)
{
    __ipv6_addr_set_half(&addr->ip6_addr32[0], w1, w2);
    __ipv6_addr_set_half(&addr->ip6_addr32[2], w3, w4);
}

static inline void ipv6_addr_prefix(struct ipv6_addr *pfx, 
                                    const struct ipv6_addr *addr,
                                    int plen)
{
    int o = plen >> 3,

    b = plen & 0x7;

    memset(pfx->ip6_addr, 0, sizeof(pfx->ip6_addr));
    memcpy(pfx->ip6_addr, addr, o);
    if (b != 0)
        pfx->ip6_addr[o] = addr->ip6_addr[o] & (0xff00 >> b);
}

#define RBRIDGE_INNER_ETH_HEADER 16
struct rbridge_inner_eth_header{
	uint8_t eth_dst[ETH_ADDR_LEN];
	uint8_t eth_src[ETH_ADDR_LEN];
	uint16_t eth_type;
	uint16_t vlan;
};

#define RBRIDGE_TRILL_HEADER 8
struct rbridge_trill_header{
	uint16_t eth_type;
	uint16_t hop_count;
	uint16_t egress_nickname;
	uint16_t ingress_nickname;
};

#define RBRIDGE_OUTER_ETH_HEADER 16
struct rbridge_outer_eth_header{
	uint8_t eth_dst[ETH_ADDR_LEN];
	uint8_t eth_src[ETH_ADDR_LEN];
	uint16_t eth_type;
	uint16_t vlan;
};

#define ICMP_HEADER_LEN 4
struct icmp_header {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_csum;
};

#define UDP_HEADER_LEN 8
struct udp_header {
    uint16_t udp_src;
    uint16_t udp_dst;
    uint16_t udp_len;
    uint16_t udp_csum;
};

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#define TCP_FLAGS(tcp_ctl) (htons(tcp_ctl) & 0x003f)
#define TCP_OFFSET(tcp_ctl) (htons(tcp_ctl) >> 12)

#define TCP_HEADER_LEN 20
struct tcp_header {
    uint16_t tcp_src;
    uint16_t tcp_dst;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_ctl;
    uint16_t tcp_winsz;
    uint16_t tcp_csum;
    uint16_t tcp_urg;
};

#define ARP_HRD_ETHERNET 1
#define ARP_PRO_IP 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_ETH_HEADER_LEN 28
struct arp_eth_header {
    /* Generic members. */
    uint16_t ar_hrd;           /* Hardware type. */
    uint16_t ar_pro;           /* Protocol type. */
    uint8_t ar_hln;            /* Hardware address length. */
    uint8_t ar_pln;            /* Protocol address length. */
    uint16_t ar_op;            /* Opcode. */

    /* Ethernet+IPv4 specific members. */
    uint8_t ar_sha[ETH_ADDR_LEN]; /* Sender hardware address. */
    uint32_t ar_spa;           /* Sender protocol address. */
    uint8_t ar_tha[ETH_ADDR_LEN]; /* Target hardware address. */
    uint32_t ar_tpa;           /* Target protocol address. */
} __attribute__((packed));

#define MPLS_LABEL_MASK ((1<<20)-1)
#define MPLS_TC_MASK ((1<<4)-1)
#define MPLS_BOS_MASK (1)
#define MPLS_TTL_MASK (255)
#define MPLS_HDR_GET_LABEL(m) (ntohl((m)) & MPLS_LABEL_MASK)
#define MPLS_HDR_GET_TC(m) ((ntohl((m))>>20) & MPLS_TC_MASK)
#define MPLS_HDR_GET_BOS(m) ((ntohl((m))>>23) & MPLS_BOS_MASK)
#define MPLS_HDR_GET_TTL(m) ((ntohl((m))>>24) & MPLS_TTL_MASK)

#define MPLS_HEADER_LEN 4
struct mpls_header {
    uint32_t mpls_tag;
};

#endif /* packets.h */
