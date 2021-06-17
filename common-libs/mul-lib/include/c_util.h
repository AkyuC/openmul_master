/*
 *  c_util.h: Common utility functions 
 *  Copyright (C) 2012, Dipjyoti Saikia
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

#ifndef __C_UTIL_H__
#define __C_UTIL_H__

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>

#include "compiler.h"
#include "lock.h"
#include "cbuf.h"

#define C_RBUF_STATE_BEGIN 0
#define C_RBUF_STATE_CONT  1
#define C_RBUF_STATE_END   2
#define C_RBUF_PART_DATA   (1 << 7)

#define C_TX_BUF_SZ        (1024)

#define C_MAX_TX_RETRIES   (4)

#define C_ALIGN_8B_LEN(len) (((len) + 7) & ~7)

#define C_SET_BMASK(var, len, pos, mask) ((var&~(((1<<len)-1)<<pos))|(mask&((1<<len)-1)<<pos))

#define SET_BIT_IN_32MASK(mask, bit) \
do { \
    *((uint32_t *)(mask) + ((bit)/32)) |= (1 << ((bit)%32)); \
} while(0)

#define GET_BIT_IN_32MASK(mask, bit) \
    (((*((uint32_t *)(mask) + ((bit)/32))) >> ((bit)%32)) & 0x1)

#define SET_BIT_IN_64MASK(mask, bit) \
do { \
    *((uint64_t *)(mask) + ((bit)/64)) |= (1 << ((bit)%64)); \
} while(0)

#define GET_BIT_IN_64MASK(mask, bit) \
    (((*((uint64_t *)(mask) + ((bit)/64))) >> ((bit)%64)) & 0x1)

typedef struct c_conn_
{
    void                    *rd_event;
    void                    *wr_event;
    void                    *ssl;
#define C_CONN_SSL_NONE 0
#define C_CONN_SSL_CONNECTING 1
#define C_CONN_SSL_CONNECTED 2
    int                     ssl_state;
    int                     fd;
    int                     rd_fd;      /* Only used for unidir connections */
    struct cbuf             *cbuf;
    struct cbuf_head        tx_q;
#define C_CONN_TYPE_SOCK    0
#define C_CONN_TYPE_FILE    1
    uint16_t                conn_type;
    uint16_t                dead;
    uint32_t                rx_pkts;
    uint32_t                tx_pkts;
    uint32_t                tx_err;
    uint16_t                rd_blk_on_wr;
    uint16_t                wr_blk_on_rd;
#define C_CONN_DESC_SZ 32
    char                    conn_str[C_CONN_DESC_SZ];       /* connection str */
    c_rw_lock_t             conn_lock __aligned; 
}c_conn_t;

typedef void (*conn_proc_t)(void *, struct cbuf *);


int     c_daemon(int nochdir, int noclose, const char *path);
pid_t   c_pid_output(const char *path);
int     c_server_socket_create(uint32_t server_ip, uint16_t port);
int     c_server_socket_create_blocking(uint32_t server_ip, uint16_t port);
int     c_client_socket_create(const char *server_ip, uint16_t port);
int     c_client_socket_create_blocking(const char *server_ip, uint16_t port);
int     c_server_socket_close(int fd);
int     c_client_socket_close(int fd);
int     c_make_socket_nonblocking(int fd);
int     c_make_socket_blocking(int fd);
int     c_tcpsock_set_nodelay(int fd);
int     c_sock_set_recvbuf(int fd, size_t len);
int     c_sock_set_sndbuf(int fd, size_t len);
void    c_hex_dump(void *ptr, int len);
int     c_socket_read_nonblock_loop(int fd, void *arg, c_conn_t *conn, 
                            const size_t rcv_buf_sz,
                            conn_proc_t proc_msg,
                            int (*get_data_len)(void *), 
                            bool (*validate_hdr)(void *), 
                            size_t hdr_sz);
int     c_socket_write_nonblock_loop(c_conn_t *conn, 
                                     void (*sched_tx)(void *));
int     c_socket_write_nonblock_sg_loop(c_conn_t *conn, 
                                     void (*sched_tx)(void *));
int     c_socket_drain_nonblock(int fd);
int     c_socket_read_block_loop(int fd, void *arg, c_conn_t *conn,
                                const size_t max_rcv_buf_sz,
                                conn_proc_t proc_msg, int (*get_data_len)(void *),
                                bool (*validate_hdr)(void *), size_t hdr_sz);
int     __c_socket_write_block_loop(c_conn_t *conn, struct cbuf *buf, bool nblk);
int     c_socket_write_block_loop(c_conn_t *conn, struct cbuf *buf);
void    c_conn_tx(void *conn_arg, struct cbuf *b, void (*delay_tx)(void *arg));
size_t  c_count_one_bits(uint32_t num);
size_t  c_count_ipv6_plen(const struct in6_addr *netmask);
int     c_socket_read_msg_nonblock_loop(int fd, void *arg, c_conn_t *conn,
                            const size_t rcv_buf_sz,
                            conn_proc_t proc_msg,
                            bool (*validate_hdr)(void *, int));

static inline int
c_recvd_sock_dead(int recv_res) 
{
    if ((recv_res == 0) ||
        ((recv_res < 0) && (errno != EAGAIN))) {
        return 1;    
    }

    return 0;
}

static inline void
c_conn_mark_dead(c_conn_t *conn)
{
    conn->dead = 1;
}

static inline void
c_conn_mark_alive(c_conn_t *conn)
{
    conn->dead = 0;
}

static inline void
c_conn_close(c_conn_t *conn)
{
    if (conn->fd > 0) {
        shutdown(conn->fd, SHUT_WR);
        close(conn->fd);
    }
    conn->fd = 0;
    c_conn_mark_dead(conn);
}

static inline void
__c_conn_clear_buffers(c_conn_t *conn, bool locked)
{
    if (conn->cbuf) {
        free_cbuf(conn->cbuf);
        conn->cbuf = NULL;
    }
    if (!locked) c_wr_lock(&conn->conn_lock);
    cbuf_list_purge(&conn->tx_q);
    if (!locked) c_wr_unlock(&conn->conn_lock);
}

static inline void
c_conn_clear_buffers(c_conn_t *conn)
{
    return __c_conn_clear_buffers(conn, false);
} 

static inline void
c_conn_prep(c_conn_t *conn)
{
    c_conn_mark_alive(conn);
    c_conn_clear_buffers(conn);
}

static inline void 
c_timeval_diff(struct timeval *res,
               struct timeval *t2,
               struct timeval *t1)
{
    if (t2->tv_usec >= t1->tv_usec) {
        res->tv_usec = t2->tv_usec - t1->tv_usec;
        res->tv_sec = t2->tv_sec - t1->tv_sec;
    } else {
        res->tv_usec = 1000000 - t1->tv_usec + t2->tv_usec;
        res->tv_sec = t2->tv_sec - t1->tv_sec - 1;
    }

    return;
}

static inline bool
c_timeval_a_more_b(struct timeval *a, struct timeval *b)
{
    long long diff = (long long)(a->tv_sec) - (long long)(b->tv_sec);
    if (diff > 0) {
        return true;
    } else if (diff < 0) {
        return false;
    } else {
        if ((long long)(a->tv_usec) > (long long)(b->tv_usec)) {
            return true;
        }
        return false;
    }
    return false;
}

static inline uint32_t
make_inet_mask(uint8_t len)
{
    if (len)
        return (~((1 << (32 - (len))) - 1));
    return 0;
}

#define TIME_uS_SCALE (1000000)
#define TIME_uS(x) (x*TIME_uS_SCALE)

#include <stddef.h>
#define container_of(ptr, str, memb)                           \
        ((str *) ((char *) (ptr) - offsetof(str, memb)))

#define FN  __FUNCTION__

#define U642ULL(x) ((unsigned long long)(x))
#define U322UL(x) ((unsigned long)(x))
#define INC_PTR8(x, len) ((void *)(((uint8_t *)(x)) + (len)))
#define ASSIGN_PTR(x) ((void *)(x))
#define DIFF_PTR8(x, y) (((uint8_t *)(x)) - ((uint8_t *)(y)))

#endif
