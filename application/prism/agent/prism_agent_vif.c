/*
 *  prism_agent_main.c: PRISM agent application for MUL Controller 
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
#include <linux/if_tun.h>
#include <net/if_arp.h>
#include "mul_vty.h"
#include "prism_agent.h"

extern struct prism_agent_ctx *CTX;

int
prism_vif_idx_to_dp_attr(int ifindex, uint64_t *dpid, uint32_t *port)
{
    GSList *iterator;

    c_rd_lock(&CTX->lock);
    for (iterator = CTX->vif_list; iterator; iterator = iterator->next) {
        struct prism_vif *vif = iterator->data;
        if (vif && vif->if_idx == ifindex) {
            *dpid = vif->dpid;
            *port = vif->port;
            c_rd_unlock(&CTX->lock);
            return 0;
        }   
        c_rd_unlock(&CTX->lock);
    } 

    c_rd_unlock(&CTX->lock);
    return -1;
}

struct prism_vif *
__prism_dp_port_to_vif(uint64_t dpid, uint32_t port)
{
    GSList *iterator;

    for (iterator = CTX->vif_list; iterator; iterator = iterator->next) {
        struct prism_vif *vif = iterator->data;
        if (vif && (vif->dpid == dpid) && (vif->port == port)) {
            return vif;
        }   
    } 
    return NULL;
}

static int 
get_vif_index(const char *if_name)
{
    struct ifreq ifr;
    int fd;
 
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        app_log_err("%s: raw socket create fail:%s", FN, strerror(errno));
        return -1;
    }
 
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        close(fd);
        return -1;
    }
    close(fd);
 
    return ifr.ifr_ifindex;
}

static void
prism_vif_write_event_sched(void *conn_arg)
{
    c_conn_t *conn = conn_arg;
    event_add((struct event *)(conn->wr_event), NULL);
}

static void
prism_vif_rx_dev(void *vif_arg, struct cbuf *b)
{
    struct prism_vif *vif = vif_arg;
    struct cbuf *new_b;
    struct prism_packet_out *pkt_out;
    int err;
    int plen;

    app_log_debug("%s: Rx pkt on %s len %u",
                  FN, vif->vif_name, (unsigned)b->len);

    plen = b->len;
    
    new_b = zalloc_cbuf(sizeof(*pkt_out) + plen);
    pkt_out = cbuf_put(new_b, sizeof(*pkt_out) + plen);
    pkt_out->hdr.cmd = PRISM_LEGACY_PACKET_OUT;
    pkt_out->hdr.len = htons(sizeof(*pkt_out) + plen);
    pkt_out->hdr.version = OFP_VERSION;

    pkt_out->dpid = vif->dpid;
    pkt_out->oif = vif->port;

    pkt_out->pkt_len = htonl(plen);
    memcpy(pkt_out->pkt_data, b->data, plen);

     if (CTX->prism_app_service) {
        err = prism_service_send(CTX->prism_app_service, new_b, false,
                                 PRISM_SERVICE_SUCCESS); 
        if (err) {
            app_log_err("%s: Pkt out failed", FN);
        }
    } else {
        free_cbuf(new_b);
    }
}

static void 
prism_vif_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    struct prism_vif *vif = arg;
    int ret = 0;

    ret = c_socket_read_msg_nonblock_loop(fd, vif, &vif->conn,
                                          PRISM_VIF_RX_BUF_SZ,
                                          prism_vif_rx_dev, NULL);
    if (c_recvd_sock_dead(ret)) {
        app_log_err("%s: VIF socket err (%s)", FN, strerror(errno));
        c_conn_destroy(&vif->conn);
        vif->flags &= ~PRISM_VIF_LIVE;
    }

    return;
}

static void
prism_vif_write_event(evutil_socket_t fd UNUSED, short events UNUSED,
                      void *arg)
{
    c_conn_t *conn = arg;

    c_wr_lock(&conn->conn_lock);
    c_socket_write_nonblock_loop(conn, prism_vif_write_event_sched);
    c_wr_unlock(&conn->conn_lock);
}

static void UNUSED
prism_vif_write(struct prism_vif *vif, struct cbuf *b)
{
    if (vif->flags & PRISM_VIF_LIVE)
        c_conn_tx(&vif->conn, b, prism_vif_write_event_sched);
    else
        free_cbuf(b);
}

static void
prism_vif_conn_init(struct prism_vif *vif, int fd)
{
    c_conn_t *conn = &vif->conn;

    if (fd <= 0) return;

    c_make_socket_nonblocking(fd);
    conn->fd = fd;
    c_conn_prep(conn);
    conn->conn_type = C_CONN_TYPE_FILE;

    conn->rd_event = event_new(CTX->base,
                               fd,
                               EV_READ|EV_PERSIST,
                               prism_vif_read, vif);
    conn->wr_event = event_new(CTX->base,
                               fd,
                               EV_WRITE, //|EV_PERSIST,
                               prism_vif_write_event, &vif->conn);

    event_add(conn->rd_event, NULL);
}

static int
prism_vif_compare(const char *dev1, const char *dev2)
{
    return strncmp(dev1, dev2, IFNAMSIZ);
}

static int
prism_vif_add(uint64_t dpid, uint16_t port, const char *dev, int fd)
{
    struct prism_vif *vif;

    c_wr_lock(&CTX->lock);
    if (CTX->vif_list &&
        g_slist_find_custom(CTX->vif_list, dev,
                            (GCompareFunc)prism_vif_compare)) {
        app_log_err("%s: Vif %s exists", FN, dev);
        c_wr_unlock(&CTX->lock);
        return -1;
    }
    
    vif = calloc(1, sizeof(*vif));
    if (!vif) {
        c_wr_unlock(&CTX->lock);
        return -1;
    }
    strncpy(vif->vif_name, dev, IFNAMSIZ - 1);
    if ((vif->if_idx = get_vif_index(vif->vif_name)) < 0) {
        c_wr_unlock(&CTX->lock);
        free(vif);
        return -1;
    }         
    vif->vif_name[IFNAMSIZ - 1] = '\0';
   	vif->dpid = htonll(dpid);
	vif->port = htonl(port);
    memset(vif->hw_addr,0,ETH_ADDR_LEN);

	prism_vif_conn_init(vif, fd); 
    vif->flags = PRISM_VIF_LIVE;
    CTX->vif_list = g_slist_append(CTX->vif_list, vif);
    c_wr_unlock(&CTX->lock);

    return 0;
}

static void UNUSED
prism_vif_del(const char *dev)
{
    GSList *list_item;
    struct prism_vif *vif;

    c_wr_lock(&CTX->lock);
    if (!CTX->vif_list ||
        !(list_item = g_slist_find_custom(CTX->vif_list, dev,
                                         (GCompareFunc)prism_vif_compare))) {
        app_log_err("%s: No such vif %s", FN, dev);
        c_wr_unlock(&CTX->lock);
        return;
    }

    vif = list_item->data;
    CTX->vif_list = g_slist_remove(CTX->vif_list, vif);

    c_conn_destroy(&vif->conn);
    free(vif);

    c_wr_unlock(&CTX->lock);
}

int 
prism_vif_link_mod(struct prism_agent_ctx *CTX UNUSED, struct prism_vif *vif,
                   bool up)
{
    struct ifreq ifr;
    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        app_log_err("%s: VIF interface %s socket err (%s)",
                     FN, vif->vif_name, strerror(errno));
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name,vif->vif_name,IFNAMSIZ);
    ifr.ifr_ifindex = vif->if_idx;

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        app_log_err("%s: VIF interface %s get flags err (%s)",
                     FN, vif->vif_name, strerror(errno));
        return -1;
    }
    if (up && !(ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP;
    } else if (!up && ifr.ifr_flags & IFF_UP) {
        ifr.ifr_flags &= ~IFF_UP;
    } else return 0;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        app_log_err("%s: VIF interface %s link up err (%s)",
                     FN, vif->vif_name, strerror(errno));
        return -1;
    }
    close(sock);
	return 0;
}

static int UNUSED
prism_vif_idx_for_mac(int *idx, uint64_t dpid, uint32_t port)
{
    GSList *iterator;

    c_rd_lock(&CTX->lock);
    for (iterator = CTX->vif_list; iterator; iterator = iterator->next) {
        struct prism_vif *vif = iterator->data;
        if (vif && (vif->dpid == dpid) && (vif->port == port)) {
            *idx = vif->if_idx;
            c_rd_unlock(&CTX->lock);
            return 0;
        }
        c_rd_unlock(&CTX->lock);
    }

    c_rd_unlock(&CTX->lock);
    return -1;
}

int 
prism_vif_update_mac_addr(struct prism_agent_ctx *CTX UNUSED,
						  struct prism_vif *vif, uint8_t mac_addr[])
{
    struct ifreq ifr;
    int sock, idx;

    idx = vif->if_idx;
	
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        app_log_err("%s: VIF interface socket err (%s)", FN, strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_ifindex = idx;
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;    /* Ethernet 10Mbps */

    memcpy(ifr.ifr_name,vif->vif_name,IFNAMSIZ);
    memcpy(ifr.ifr_hwaddr.sa_data, mac_addr, sizeof(mac_addr));

    if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
    
        app_log_err("%s: VIF interface MAC addr change err (%s)",
                     FN, strerror(errno));
        return -1;
    }

    close(sock);
    return 0;
}

void
prism_vif_init(void)
{
    FILE *fp;
    char buf[2048];
    char *tmp1, *tmp2, *name;
    int fd = 0;
	uint64_t dpid;
	uint16_t port;

    fp = fopen(PRISM_VIF_FILE, "r");
    if (!fp) {
        app_log_err("%s: File open error", FN);
        return;
    }
       
	while (fgets(buf, sizeof(buf), fp) != NULL) {

        if((buf[0] == '#') || (buf[0] == ' ') || (buf[0] == '\n'))
            continue;
		
		tmp1 = strtok(buf, "|");
        tmp2 = strtok(NULL, "|");
        name = strtok(NULL, "|\n");

        if (!tmp1 || !tmp2 || !name) {
            app_log_err("Can't parse conf file %s", PRISM_VIF_FILE);
            continue;
        }

		dpid = strtoull(tmp1, NULL, 16);
		port = atoi(tmp2);
		
		if ((fd = tun_alloc(name, IFF_TAP | IFF_NO_PI)) <= 0) {
            app_log_err("%s: Tap interface %s creat err(%s)",
                      FN, name, strerror(errno));
            return;
        }

        if (prism_vif_add(dpid, port, name, fd) < 0) {
            app_log_err("%s: Tap interface %s add err", FN, name);
            tun_dev_free(name, fd);
        }
          
        app_log_info("%s interface created", name);
    }

    fclose(fp);

    memcpy(buf, PRISM_EXP_VIF_NAME, IFNAMSIZ);
    name = buf;

    /* Create generic exception VIF */
    if ((fd = tun_alloc(name, IFF_TAP | IFF_NO_PI)) <= 0) {
        app_log_err("%s: Tap interface %s creat err(%s)",
                    FN, name, strerror(errno));
        return;
    }

    if (prism_vif_add(PRISM_EXP_VIF_DPID, PRISM_EXP_VIF_PORT, 
                      name, fd) < 0) {
        app_log_err("%s: Tap interface %s add err", FN, name);
        tun_dev_free(name, fd);
    }

    app_log_info("%s interface created", name);
}
