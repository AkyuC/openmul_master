/*
 *  prism_agent_netlink.c: PRISM agent application for MUL Controller 
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#include "config.h"
#include "mul_common.h"
#include <netinet/in.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <linux/if_tun.h>
#include "mul_vty.h"
#include "prism_agent.h"
#include "prism_common.h"

extern struct prism_agent_ctx *CTX;

static inline int
addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
          int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        app_rlog_err("addattr_l ERROR: message exceeded bound of %d\n", maxlen);
        return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

static inline int
addattr(struct nlmsghdr *n, int maxlen, int type)
{
    return addattr_l(n, maxlen, type, NULL, 0);
}

static inline int
addattr8(struct nlmsghdr *n, int maxlen, int type, __u8 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u8));
}

static inline int
addattr16(struct nlmsghdr *n, int maxlen, int type, __u16 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u16));
}

static inline int
addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u32));
}

static inline int
addattr64(struct nlmsghdr *n, int maxlen, int type, __u64 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u64));
}

static inline int
addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *str)
{
    return addattr_l(n, maxlen, type, str, strlen(str)+1);
}

static int
calc_host_len(const struct rtmsg *r)
{
    if (r->rtm_family == AF_INET6)
        return 128;
    else if (r->rtm_family == AF_INET)
        return 32;
    else if (r->rtm_family == AF_DECnet)
        return 16;
    else if (r->rtm_family == AF_IPX)
        return 80;
    else
        return -1;
}

static inline uint32_t
nl_mgrp(uint32_t group)
{
    if (group > 31) {
        return -1;
    }
    return group ? (1 << (group - 1)) : 0;
}

static int
parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
                   int len, unsigned short flags)
{
    unsigned short type;

    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        type = rta->rta_type & ~flags;
        if ((type <= max) && (!tb[type]))
            tb[type] = rta;
        rta = RTA_NEXT(rta,len);
    }
    if (len)
        app_rlog_err("!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
    return 0;
}

static int
parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    return parse_rtattr_flags(tb, max, rta, len, 0);
}

static void
prism_nl_proc_route(struct prism_nl *nl UNUSED, struct nlmsghdr *n)
{
    struct rtmsg *r = NLMSG_DATA(n);
    int len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*r));
    struct rtattr * tb[RTA_MAX+1];
    struct cbuf *b;
    struct prism_ipv4_rt_cmd *rt_msg;
    int err = 0;
    int host_len = 0;

    if (len < 0) {
        app_rlog_err("%s: wrong nlmsg len %d\n", FN, len);
        return;
    }

    if (r->rtm_family != AF_INET) {
        app_rlog_err("%s: Unsupported family", FN);
        return;
    }

    if (r->rtm_family == RTNL_FAMILY_IPMR ||
        r->rtm_family == RTNL_FAMILY_IP6MR) {
        app_rlog_err("%s: Mroute not supported now", FN);
        return;
    }

    if (r->rtm_type != RTN_UNICAST &&
        r->rtm_type != RTN_LOCAL) {
        return;
    }

    host_len = calc_host_len(r);

    parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

    b = zalloc_cbuf(sizeof(*rt_msg));

    rt_msg = cbuf_put(b, sizeof(*rt_msg));

    rt_msg->hdr.cmd = (n->nlmsg_type == RTM_NEWROUTE ? PRISM_LEGACY_RT_ADD :
                                             PRISM_LEGACY_RT_DEL);

    rt_msg->hdr.len = htons(sizeof(*rt_msg));
    rt_msg->hdr.version = OFP_VERSION;

    if (tb[RTA_DST]) {
        rt_msg->dst_nw = (*(uint32_t *)(RTA_DATA(tb[RTA_DST])));
        rt_msg->dst_nm = (make_inet_mask(r->rtm_dst_len));
    }

    if(ipv4_is_multicast(rt_msg->dst_nw)) {
        /*Filtering out multicast routes*/
        app_log_info("%s: Filtered out 0x%x", FN, rt_msg->dst_nw);
        free_cbuf(b);
        return;
    }
    if (tb[RTA_GATEWAY] && host_len == IPV4_HOST_LEN) {
        rt_msg->nh = (*(uint32_t *)RTA_DATA(tb[RTA_GATEWAY]));
    }

    if (tb[RTA_OIF]) {
        int ifindex = *(int*)RTA_DATA(tb[RTA_OIF]);

        if (prism_vif_idx_to_dp_attr(ifindex, &rt_msg->dpid, &rt_msg->oif)) {
            free_cbuf(b);
            return;
        }
    }

    rt_msg->rt_flags = htonl(r->rtm_type);

    if (1) {
        char dstr[INET_ADDRSTRLEN];
        char nhstr[INET_ADDRSTRLEN];
        uint32_t dst = rt_msg->dst_nw;
        uint32_t nh  = rt_msg->nh;
        app_log_debug("%s: %s Dest %s/%d Next-hop %s 0x%llx:%lu %s", FN,
                n->nlmsg_type == RTM_NEWROUTE ? "Route-add":"Route-del",
                inet_ntop(AF_INET, &dst, dstr, INET_ADDRSTRLEN),
                r->rtm_dst_len,
                inet_ntop(AF_INET, &nh, nhstr, INET_ADDRSTRLEN),
                U642ULL(ntohll(rt_msg->dpid)), U322UL(ntohl(rt_msg->oif)),
                r->rtm_type == RTN_LOCAL ? "Local" :"Non-local");
    }

    if (CTX->prism_app_service) {
        err = prism_service_send(CTX->prism_app_service, b, true,
                                 PRISM_SERVICE_SUCCESS); 
        if (err) {
            app_rlog_err("%s: RT update Err failed", FN);
        }
    }

    return;
}

static void
prism_nl_proc_neigh(struct prism_nl *nl UNUSED, struct nlmsghdr *n)
{
    struct ndmsg *r = NLMSG_DATA(n);
    int len = n->nlmsg_len;
    struct rtattr * tb[NDA_MAX+1];
    int alen = 0;
    int err = 0;
    struct cbuf *b;
    struct prism_ipv4_nh_cmd *nh_msg;

    if (n->nlmsg_type != RTM_NEWNEIGH &&
        n->nlmsg_type != RTM_DELNEIGH) {
        return;
    }

    if (r->ndm_family != AF_INET) {
        return;
    }

    len -= NLMSG_LENGTH(sizeof(*r));
    if (len < 0) {
        app_rlog_err("%s: wrong nlmsg len %d\n", FN, len);
        return;
    }

    parse_rtattr(tb, NDA_MAX, NDA_RTA(r),
                 n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

    if (!tb[NDA_DST]) {
        return; 
    } 

    b = zalloc_cbuf(sizeof(*nh_msg));
    nh_msg = cbuf_put(b, sizeof(*nh_msg));
    nh_msg->hdr.len = htons(sizeof(*nh_msg));
    nh_msg->hdr.version = OFP_VERSION;

    nh_msg->hdr.cmd = n->nlmsg_type == RTM_DELNEIGH ? 
                            PRISM_LEGACY_NH_DEL : PRISM_LEGACY_NH_ADD;

    if (r->ndm_state) {
        int nud = r->ndm_state;
        if (nud & NUD_FAILED)
            nh_msg->hdr.cmd = PRISM_LEGACY_NH_DEL;
        nh_msg->nh_flags = htonl(nud); 
    }

    if (tb[NDA_DST]) {
        nh_msg->nh = *(uint32_t *)(RTA_DATA(tb[NDA_DST]));
    }

    if(ipv4_is_multicast(nh_msg->nh)) {
        /*Filtering out multicast next hop*/
        app_log_info("%s: Filtered out 0x%x", FN, nh_msg->nh);
        free_cbuf(b);
        return;
    }
    if (tb[NDA_LLADDR]) {
        int ifindex = r->ndm_ifindex;
        alen = RTA_PAYLOAD(tb[NDA_LLADDR]);

        if (alen != 6) {
            free_cbuf(b);
            app_log_err("%s: Unsupported lltype", FN);
            return;
        }
        memcpy(nh_msg->mac_addr, RTA_DATA(tb[NDA_LLADDR]), 6);

        if (prism_vif_idx_to_dp_attr(ifindex, &nh_msg->dpid, &nh_msg->oif)) {
            free_cbuf(b);
            return;
        }

    }

    if (1) {
        char nhstr[INET_ADDRSTRLEN];
        app_log_debug("%s: %s Next-hop %s mac %02x:%02x:%02x:%02x:%02x:%02x:" 
                    " 0x%llx:%lu (%d)", FN,
                nh_msg->hdr.cmd == PRISM_LEGACY_NH_DEL ? "NH-del":"NH-add",
                inet_ntop(AF_INET, &nh_msg->nh, nhstr, INET_ADDRSTRLEN),
                nh_msg->mac_addr[0], nh_msg->mac_addr[1], nh_msg->mac_addr[2],
                nh_msg->mac_addr[3], nh_msg->mac_addr[4], nh_msg->mac_addr[5],
                U642ULL(ntohll(nh_msg->dpid)), U322UL(ntohl(nh_msg->oif)),
                r->ndm_state);
    }

    if (CTX->prism_app_service) {
        err = prism_service_send(CTX->prism_app_service, b, true,
                                 PRISM_SERVICE_SUCCESS); 
        if (err) {
            app_log_err("%s: NH update failed", FN);
        }
    }

    return;
}

static void
prism_nl_proc(struct prism_nl *nl, struct nlmsghdr *n)
{
    switch (n->nlmsg_type) {
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
        prism_nl_proc_route(nl, n);
        break;
    case RTM_NEWNEIGH:
    case RTM_DELNEIGH:
    case RTM_GETNEIGH:
        prism_nl_proc_neigh(nl, n);
        break;
    default:
        break;
        
    }
}

static void
prism_nl_rx_parse(void *nl_arg, struct cbuf *b)
{
    int msg_sz = b->len;
    int len = 0, rem = 0;
    struct nlmsghdr *h;

    /* c_log_info("%s: Rx pkt len %u", FN, (unsigned)b->len); */

    for (h = (struct nlmsghdr*)b->data; msg_sz >= sizeof(*h); ) {
        len = h->nlmsg_len;
        rem = len - sizeof(*h);

        if (rem < 0 || len > msg_sz) {
            app_rlog_err("%s: Corrupt NL packet", FN);
            return;
        }

        prism_nl_proc(nl_arg, h);
        
        msg_sz -= NLMSG_ALIGN(len);
        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
    }
}

static void 
prism_nl_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    struct prism_nl *nl = arg;
    int ret = 0;

    ret = c_socket_read_msg_nonblock_loop(fd, nl, &nl->conn,
                                          PRISM_NL_RX_BUF_SZ, 
                                          prism_nl_rx_parse,
                                          NULL);
    if (c_recvd_sock_dead(ret)) {
        app_log_err("%s: NL socket err (%s)", FN, strerror(errno));
        c_conn_destroy(&nl->conn);
    }

    return;
}

static void
prism_nl_write_event_sched(void *conn_arg)
{
    c_conn_t *conn = conn_arg;
    event_add((struct event *)(conn->wr_event), NULL);
}

static void
prism_nl_write_event(evutil_socket_t fd UNUSED, short events UNUSED,
                     void *arg UNUSED)
{
    c_conn_t *conn = arg;

    c_wr_lock(&conn->conn_lock);
    c_socket_write_nonblock_loop(conn, prism_nl_write_event_sched);
    c_wr_unlock(&conn->conn_lock);
}

void
prism_nl_replay_routes(void)
{
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
        /* attribute has to be NLMSG aligned */
        struct rtattr ext_req __attribute__ ((aligned(NLMSG_ALIGNTO)));
        uint32_t ext_filter_mask;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
    req.nlh.nlmsg_pid = 0;
    req.nlh.nlmsg_seq = CTX->seq++;
    req.ifm.ifi_family = AF_INET;

    req.ext_req.rta_type = IFLA_EXT_MASK;
    req.ext_req.rta_len = RTA_LENGTH(sizeof(uint32_t));
    req.ext_filter_mask = RTEXT_FILTER_VF;

    if (send(CTX->nl.fd, (void*)&req, sizeof(req), MSG_NOSIGNAL) <=0 ){
        app_log_err("%s: Failed to send Route get %d", FN, errno);
    } else {
        prism_nl_read(CTX->nl.fd, 0, &CTX->nl.fd);
    }
    return;
}

void
prism_nl_replay_nh(void)
{
    struct ndmsg ndm;
    struct nlmsghdr nlh;
    struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
    struct iovec iov[2] = {
        { .iov_base = &nlh, .iov_len = sizeof(nlh) },
        { .iov_base = &ndm, .iov_len = sizeof(ndm)}
    };
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen =  sizeof(nladdr),
        .msg_iov = iov,
        .msg_iovlen = 2,
    };

    memset(&ndm, 0, sizeof(ndm));
    ndm.ndm_family = AF_INET;

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ndm));
    nlh.nlmsg_type = RTM_GETNEIGH;
    nlh.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
    nlh.nlmsg_pid = 0;
    nlh.nlmsg_seq = CTX->seq++;

    if (sendmsg(CTX->nl.fd, &msg, MSG_NOSIGNAL) <= 0) {
        app_log_err("%s: Failed to send NH get %d", FN, errno); 
    } else {
        prism_nl_read(CTX->nl.fd, 0, &CTX->nl.fd);
    }
    return;

}

static void
prism_netlink_conn_init(struct prism_nl *nl, int fd)
{
    c_conn_t *conn = &nl->conn;

    if (fd <= 0) return;

    c_make_socket_nonblocking(fd);
    conn->fd = fd;
    c_conn_prep(conn);
    /* conn->conn_type = C_CONN_TYPE_FILE; */

    conn->rd_event = event_new(CTX->base,
                               fd,
                               EV_READ|EV_PERSIST,
                               prism_nl_read, nl);
    conn->wr_event = event_new(CTX->base,
                               fd,
                               EV_WRITE, //|EV_PERSIST,
                               prism_nl_write_event, &nl->conn);

    event_add(conn->rd_event, NULL);
}

static int
prism_rtnl_open(struct prism_nl *nl, unsigned int subscriptions, int protocol)
{
    socklen_t addr_len;
    int rcvbuf = 1024 * 1024;

    memset(nl, 0, sizeof(*nl));
    nl->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
    if (nl->fd < 0) {
        app_log_err("%s: Netlink socket open fail(%s)", FN, strerror(errno));
        return -1;
    }

    if (setsockopt(nl->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("SO_RCVBUF");
        return -1;
    }

    memset(&nl->local, 0, sizeof(nl->local));
    nl->local.nl_family = AF_NETLINK;
    nl->local.nl_groups = subscriptions;

    if (bind(nl->fd, (struct sockaddr*)&nl->local, sizeof(nl->local)) < 0) {
        perror("Cannot bind netlink socket");
        return -1;
    }
    addr_len = sizeof(nl->local);
    if (getsockname(nl->fd, (struct sockaddr*)&nl->local, &addr_len) < 0) {
        perror("Cannot getsockname");
        return -1;
    }
    if (addr_len != sizeof(nl->local)) {
        app_log_err("Wrong address length %d", addr_len);
        return -1;
    }
    if (nl->local.nl_family != AF_NETLINK) {
        app_log_err("Wrong address family %d", nl->local.nl_family);
        return -1;
    }
    nl->seq = time(NULL);
    prism_netlink_conn_init(nl, nl->fd);

    return 0;
}

int
prism_netlink_init(void *ctx_arg)
{
    struct prism_agent_ctx *CTX = ctx_arg;
    unsigned int groups = 0;

    groups |= nl_mgrp(RTNLGRP_IPV4_IFADDR);
    groups |= nl_mgrp(RTNLGRP_IPV4_ROUTE);
    groups |= nl_mgrp(RTNLGRP_NEIGH);

    if (prism_rtnl_open(&CTX->nl, groups, NETLINK_ROUTE) < 0) {
        return -1;
    }        

    return 0;
}
