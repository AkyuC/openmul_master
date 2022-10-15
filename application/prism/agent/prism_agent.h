/*
 *  prism_agent.h: PRISM agent application headers
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
#ifndef __PRISM_AGENT_H__
#define __PRISM_AGENT_H__
#include "prism_common.h"

#define PRISM_VIF_RX_BUF_SZ (2048)
#define PRISM_NL_RX_BUF_SZ (4096)

#define PRISM_EXP_VIF_NAME "pr-vif"
#define PRISM_EXP_VIF_DPID ((uint64_t)(-1)) 
#define PRISM_EXP_VIF_PORT ((uint16_t)(-1))
#define PRISM_EXP_VIF_MAC_ADDR { 0x00, 0x01, 0xab, 0xcd, 0xde, 0xad }

struct prism_vif
{
    int fd;
    char vif_name[IFNAMSIZ];
    uint8_t hw_addr[ETH_ADDR_LEN];

#define PRISM_VIF_LIVE 0x01
    int flags;
    int if_flags;

    int if_idx;
    uint64_t dpid;
    uint32_t port;

    c_conn_t conn;
};

#include <linux/netlink.h>

struct prism_nl
{
    int fd;
    struct sockaddr_nl local;
    uint32_t seq;
    uint32_t dump;

    c_conn_t conn;
};

#define IPV4_HOST_LEN 32

#define RTA_ALIGNTO 4
#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
#define RTA_OK(rta,len) ((len) >= (int)sizeof(struct rtattr) && \
             (rta)->rta_len >= sizeof(struct rtattr) && \
             (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen)   ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                 (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_LENGTH(len) (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_SPACE(len)  RTA_ALIGN(RTA_LENGTH(len))
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((char*) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#ifndef IFA_RTA
#define IFA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#endif
#ifndef IFA_PAYLOAD
#define IFA_PAYLOAD(n)  NLMSG_PAYLOAD(n,sizeof(struct ifaddrmsg))
#endif

#ifndef IFLA_RTA
#define IFLA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif
#ifndef IFLA_PAYLOAD
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#endif

#ifndef NDA_RTA
#define NDA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif
#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n)  NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#endif

#ifndef NDTA_RTA
#define NDTA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndtmsg))))
#endif
#ifndef NDTA_PAYLOAD
#define NDTA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndtmsg))
#endif

struct prism_agent_ctx
{
    void *base;
    c_rw_lock_t lock;
    GSList *vif_list;
    struct prism_nl nl;
    int seq;

    mul_service_t *prism_agent_service;

    mul_service_t *prism_app_service;

    void *serv_base;
    pthread_t serv_thread;
    c_rw_lock_t serv_lock;
    struct event *serv_timer_event;
    bool need_replay;
};

/* Cast to struct event */
#define C_EVENT(x) ((struct event *)(x))

static inline void
c_conn_events_del(c_conn_t *conn)
{
    if (conn->rd_event) {
        event_del(C_EVENT(conn->rd_event));
        event_free(C_EVENT(conn->rd_event));
        conn->rd_event = NULL;
    }
    if (conn->wr_event) {
        event_del(C_EVENT(conn->wr_event));
        event_free(C_EVENT(conn->wr_event));
        conn->wr_event = NULL;
    }
}

static inline void
c_conn_destroy(c_conn_t *conn)
{
    c_wr_lock(&conn->conn_lock);
    c_conn_events_del(conn);
    c_conn_close(conn);
    __c_conn_clear_buffers(conn, true);

    conn->ssl = NULL;
    c_wr_unlock(&conn->conn_lock);
}

int prism_service_send(void *service, struct cbuf *b,
                       bool wait, uint8_t resp);
int prism_vif_idx_to_dp_attr(int ifindex, uint64_t *dpid, uint32_t *port);
struct prism_vif *__prism_dp_port_to_vif(uint64_t dpid, uint32_t port);
void prism_nl_replay_routes(void);
void prism_nl_replay_nh(void);
int prism_netlink_init(void *ctx);
void prism_agent_init(void *ctx);
void prism_agent_vty_init(void *arg);
void prism_vif_init(void);
int prism_vif_link_mod(struct prism_agent_ctx *CTX, struct prism_vif *vif, bool up);
int prism_vif_update_mac_addr(struct prism_agent_ctx *CTX, struct prism_vif *vif,
							  uint8_t mac_addr[]);

#endif
