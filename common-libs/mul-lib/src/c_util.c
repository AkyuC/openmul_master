/*
 *  c_util.c: Common utility functions 
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "event2/event.h"
#include "cbuf.h"
#include "c_util.h"

int
c_daemon(int nochdir, int noclose, const char *path)
{
    pid_t pid;

    pid = fork ();

    if (pid < 0) {
        return -1;
    }

    if (pid != 0) {
        exit (0);
    }

    umask (0027);

    pid = setsid();

    if (pid == -1) {
        return -1;
    }

    if (!nochdir) {
        if (chdir("/")) {
            printf("Failed to chdir /\n");
            return -1;
        }
    }

    if (path) {
        c_pid_output(path);
    }

    if (!noclose) {
        int fd;

        fd = open ("/dev/null", O_RDWR, 0);
        if (fd != -1) {
	        dup2 (fd, STDIN_FILENO);
	        dup2 (fd, STDOUT_FILENO);
	        dup2 (fd, STDERR_FILENO);
	        if (fd > 2)
	            close (fd);
	    }
    }

    return 0;
}


pid_t
c_pid_output(const char *path)
{
    int tmp;
    int fd;
    pid_t pid;
    char buf[16];
    struct flock lock;
    mode_t oldumask;

    pid = getpid ();
#define PIDFILE_MASK 0644
    oldumask = umask(0777 & ~PIDFILE_MASK);
    fd = open(path, O_RDWR | O_CREAT, PIDFILE_MASK);
    if (fd < 0) {
        perror("open");
        umask(oldumask);
        exit(1);
    } else {
        unsigned int pidsize;

        umask(oldumask);
        memset (&lock, 0, sizeof(lock));

        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;

        if (fcntl(fd, F_SETLK, &lock) < 0) {
            printf("Duplicate instance running\n");
            exit(1);
        }

        sprintf (buf, "%d\n", (int) pid);
        pidsize = strlen(buf);
        if ((tmp = write (fd, buf, pidsize)) != (int)pidsize)
            printf("Could not write pid %d to pid_file %s\n",
                   (int)pid, path);
        else if (ftruncate(fd, pidsize) < 0)
            printf("Could not truncate pid_file %s to %u bytes\n",
                   path, (u_int)pidsize);
    }
    return pid;
}


int
c_make_socket_nonblocking(int fd)
{
    int flags;
    if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;
}

int
c_make_socket_blocking(int fd)
{
    int flags;
    if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;
}


int
c_server_socket_create(uint32_t server_ip, uint16_t port)
{
    struct sockaddr_in sin;
    int                fd;
    int                one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("");
        return fd;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(server_ip);
    sin.sin_port = htons(port);

    c_make_socket_nonblocking(fd);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return -1;
    }

    if (listen(fd, 16) < 0) {
        perror("listen");
        return -1;
    }

    return fd;
}

int
c_server_socket_create_blocking(uint32_t server_ip, uint16_t port)
{
    struct sockaddr_in sin;
    int                fd;
    int                one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("");
        return fd;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(server_ip);
    sin.sin_port = htons(port);

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return -1;
    }

    if (listen(fd, 16) < 0) {
        perror("listen");
        return -1;
    }

    return fd;
}


int
c_client_socket_create(const char *server_ip, uint16_t port)
{
    struct sockaddr_in sin;
    int                fd;
    int                one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return fd;
    }

    sin.sin_family = AF_INET; 
    sin.sin_port = htons(port);
    if (!inet_aton(server_ip, &sin.sin_addr)) {
        return -1;
    }

    memset(sin.sin_zero, 0, sizeof sin.sin_zero);
    if (connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1) {
        close(fd);
        return -1;
    }

    c_make_socket_nonblocking(fd);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));    

    return fd;
}


int 
c_client_socket_create_blocking(const char *server_ip, uint16_t port)
{   
    struct sockaddr_in sin;
    int                fd;
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return fd;
    }
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (!inet_aton(server_ip, &sin.sin_addr)) {
        return -1;
    }   
        
    memset(sin.sin_zero, 0, sizeof sin.sin_zero);
    if (connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1) {
        close(fd);
        return -1;
    }

    return fd;
}

int
c_server_socket_close(int fd)
{
    close(fd);
    return 0;
}

int
c_client_socket_close(int fd)
{
    close(fd);
    return 0;
}

int
c_sock_set_recvbuf (int fd, size_t size)
{
  return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof (size));
}

int 
c_sock_set_sndbuf (int fd, size_t size)
{
  return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof (size));
}


int c_tcpsock_set_nodelay(int fd)
{
    int zero = 0;

    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));

}

void
c_hex_dump(void *ptr, int len)
{
    int i= 0, idx = 0;
    unsigned char tmp_buf[64] = { 0 };

    for (i = 0; i < len; i++) {
        idx += snprintf((void *)(tmp_buf + idx), 3, "%02x",
                        *((unsigned char *)ptr + i));

        if (idx >= 32) {
            printf("0x%s\r\n", tmp_buf);
            memset(tmp_buf, 0, 32);
            idx = 0;
        }
    }

    if (idx) {
        printf("0x%s\r\n", tmp_buf);
    }

    return;
}

/**
 * c_socket_read_nonblock_loop -
 *
 * Non blocking read loop given socket fd 
 * NOTE - It does not support SSL yet
 */
int 
c_socket_read_nonblock_loop(int fd, void *arg, c_conn_t *conn,
                            const size_t rcv_buf_sz, 
                            conn_proc_t proc_msg, int (*get_data_len)(void *),
                            bool (*validate_hdr)(void *), size_t hdr_sz )
{
    ssize_t             rd_sz = -1;
    struct cbuf         curr_b, *b = NULL;
    int                 loop_cnt = 0;

    if (!conn->cbuf) {
        b = alloc_cbuf(rcv_buf_sz);
    } else {
        b = conn->cbuf; 
    }

    while (1) {
        if (!cbuf_tailroom(b)) {
            b = cbuf_realloc_tailroom(b, rcv_buf_sz, true);
        }

        if (conn->conn_type == C_CONN_TYPE_SOCK) {
            if (++loop_cnt < 100) {
                rd_sz = recv(fd, b->tail, cbuf_tailroom(b), 0);
            } else rd_sz = -1;
        } else {
            rd_sz = read(fd, b->tail, cbuf_tailroom(b));
        }

        if (rd_sz <= 0) {
            conn->cbuf = b;
            break;
        }

        cbuf_put(b, rd_sz);

        while (b->len >= hdr_sz && 
               b->len >= get_data_len(b->data))  {

            if (!validate_hdr(b->data)) {
                conn->cbuf = b;
                printf("%s: Corrupted header", FN);
                return 0; /* Close the socket */
            }

            curr_b.data = b->data;
            curr_b.len = get_data_len(b->data);
            curr_b.tail = b->data + curr_b.len;
            curr_b.nofree = 1; 

            proc_msg(arg, &curr_b);
            cbuf_pull(b, curr_b.len);
        }
    }

    return rd_sz;
}

int
c_socket_write_nonblock_loop(c_conn_t *conn, 
                             void (*sched_tx)(void *))
{
    struct cbuf *buf;
    int         sent_sz;
    int         err = 0;
    int         ssl_err = 0;

    if (unlikely(conn->dead)) {
        cbuf_list_purge(&conn->tx_q);
        err = -1;
        goto out;
    }

    /* Wait for read to complete */
    if (conn->wr_blk_on_rd) goto out;

    while ((buf = cbuf_list_dequeue(&conn->tx_q))) {
        if (conn->ssl) {
            sent_sz = SSL_write(conn->ssl, buf->data, buf->len);
            if (sent_sz <= 0) {
                ssl_err = SSL_get_error(conn->ssl, sent_sz);
                sent_sz = -1;
                switch (ssl_err) {
                case SSL_ERROR_WANT_WRITE:
                    errno = EAGAIN;
                    break;
                case SSL_ERROR_WANT_READ:
                    conn->wr_blk_on_rd = 1;;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    conn->dead = 1;
                    err = -1;
                    goto out;
                default:
                    break;
                }
            }
        }
        else {
            if (conn->conn_type == C_CONN_TYPE_SOCK)
                sent_sz = send(conn->fd, buf->data, buf->len, MSG_NOSIGNAL);
            else
                sent_sz = write(conn->fd, buf->data, buf->len);
        }

        if (sent_sz <= 0) {
            cbuf_list_queue(&conn->tx_q, buf);
            if (conn->wr_blk_on_rd) goto out;
            if (sent_sz == 0 || errno == EAGAIN) {
                conn->tx_err++;
                goto sched_tx_event;
            }
            conn->dead = 1;
            err = -1;
            goto out;
        }

        if (conn->rd_blk_on_wr) {
            conn->rd_blk_on_wr = 0;
            event_active(conn->rd_event, EV_READ, 0);
        }

        if (sent_sz < buf->len) {
            cbuf_pull(buf, sent_sz);
            cbuf_list_queue(&conn->tx_q, buf);
            goto sched_tx_event;
        }

        conn->tx_pkts++;

        free_cbuf(buf);
    }

out:
    if (cbuf_list_queue_len(&conn->tx_q)) {
        cbuf_list_rm_inline_bufs(&conn->tx_q);
    }
    return err;

sched_tx_event:
    cbuf_list_rm_inline_bufs(&conn->tx_q);
    sched_tx(conn);
    return err;

}

/**
 * c_socket_read_msg_nonblock_loop -
 *
 * Non blocking message read loop given socket fd 
 * NOTE - It does not support SSL yet
 */
int 
c_socket_read_msg_nonblock_loop(int fd, void *arg, c_conn_t *conn,
                            const size_t rcv_buf_sz, 
                            conn_proc_t proc_msg,
                            bool (*validate_hdr)(void *, int))
{
    ssize_t             rd_sz = -1, delta = 0;
    struct cbuf         *b = NULL;
    int                 loop_cnt = 0;

    if (!conn->cbuf) {
        b = alloc_cbuf(rcv_buf_sz);
    } else {
        b = conn->cbuf;
    }

    while (1) {
        if (!cbuf_tailroom(b) || delta) {
            b = cbuf_realloc_tailroom(b, 
                        delta > rcv_buf_sz ? delta : rcv_buf_sz , true);
        }

        delta = 0;

        if (++loop_cnt < 100) {
            if (conn->conn_type == C_CONN_TYPE_SOCK) {
                rd_sz = recv(fd, b->tail, cbuf_tailroom(b), MSG_TRUNC);
            } else {
                rd_sz = read(fd, b->tail, cbuf_tailroom(b));
            }
        } else rd_sz = -1;

        if (rd_sz <= 0) {
            cbuf_reset(b);
            conn->cbuf = b;
            break;
        }

        if (rd_sz > cbuf_tailroom(b)) {
            delta = rd_sz + cbuf_tailroom(b);
            continue;
        }

        cbuf_put(b, rd_sz);

        if (validate_hdr && !validate_hdr(b->data, rd_sz)) 
            continue;

        proc_msg(arg, b);
        cbuf_reset(b);
    }

    return rd_sz;
}

int 
c_socket_write_nonblock_sg_loop(c_conn_t *conn,
                                void (*sched_tx)(void *))
{
    struct cbuf     *buf;
    struct cbuf     *curr = conn->tx_q.next;
    int             sent_sz;
    int             err = 0, qlen = 0;
    struct iovec    iov[C_TX_BUF_SZ];

    if (unlikely(!cbuf_list_queue_len(&conn->tx_q))) {
        return 0;
    }

    if (unlikely(conn->dead)) {
        cbuf_list_purge(&conn->tx_q);
        err = -1;
        goto out;
    }

    /* TODO : Optimize this */
    while (curr && qlen < C_TX_BUF_SZ) {
        iov[qlen].iov_base = curr->data;
        iov[qlen++].iov_len = curr->len;
        curr = curr->next;
    }

    sent_sz = writev(conn->fd, iov, qlen);

    if (sent_sz <= 0) {
        if (sent_sz == 0 || errno == EAGAIN) {
            conn->tx_err++;
            goto sched_tx_event;
        }
        conn->dead = 1;
        err = -1;
        goto out;
    }

    while (sent_sz && (buf = cbuf_list_dequeue(&conn->tx_q))) {
        if (sent_sz >= buf->len) {
            sent_sz -= buf->len;
            free_cbuf(buf);
            conn->tx_pkts++;
        } else {
            cbuf_pull(buf, sent_sz);
            cbuf_list_queue(&conn->tx_q, buf);
            goto sched_tx_event;
        }
    }

out:
    if (cbuf_list_queue_len(&conn->tx_q)) {
        cbuf_list_rm_inline_bufs(&conn->tx_q);
    } 

    return err;

sched_tx_event:
    cbuf_list_rm_inline_bufs(&conn->tx_q);
    sched_tx(conn);
    return err;
}

int
c_socket_drain_nonblock(int fd)
{
    int ret = 0;
    char buf[2048];

    while(1) {
        ret = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (ret <= 0) {
            break;
        }
    } 
    return ret;
}

int
__c_socket_write_block_loop(c_conn_t *conn, struct cbuf *buf,
                            bool force_nblk)
{
    int         sent_sz;
    int         err = 0;
    int         retries = C_MAX_TX_RETRIES;
    
    if (unlikely(conn->dead)) {
        err = -1;
        goto out;
    }

    if (force_nblk)
        c_make_socket_nonblocking(conn->fd);
try_again:
    sent_sz = send(conn->fd, buf->data, buf->len, MSG_NOSIGNAL);
    if (sent_sz <= 0) {
        if ((force_nblk &&
            (sent_sz == 0 || errno == EAGAIN)) ||
            errno == EINTR)
            goto retry;
        conn->tx_err++;
        conn->dead = 1;
        goto out;
    }

    if (sent_sz < buf->len) {
        cbuf_pull(buf, sent_sz);
        goto retry;
    }

    conn->tx_pkts++;

    free_cbuf(buf);

out:
    if (force_nblk)
        c_make_socket_blocking(conn->fd);
    return err;

retry:
    if (retries-- <= 0) {
        conn->tx_err++;
        free_cbuf(buf);
        err = -1;
        goto out;
    }

    goto try_again;
}

int
c_socket_write_block_loop(c_conn_t *conn, struct cbuf *buf)
{
    return __c_socket_write_block_loop(conn, buf, false);
}

static int
c_socket_read_chunk_loop(int fd, struct cbuf **orig_b,
                         c_conn_t *conn, size_t tot_rcv_sz)
{
    struct cbuf *b = *orig_b;
    size_t rd_sz = 0, rem_rcv_sz = tot_rcv_sz;

    if (!b) {
        return -1;
    }

read_again:
    if (cbuf_tailroom(b) < rem_rcv_sz) {
        b = cbuf_realloc_tailroom(b, rem_rcv_sz, true);
    }

    if (conn->conn_type == C_CONN_TYPE_SOCK) {
        rd_sz = recv(fd, b->tail, rem_rcv_sz, MSG_WAITALL);
    } else {
        rd_sz = read(fd, b->tail, rem_rcv_sz);
    }

    if (rd_sz > rem_rcv_sz) {
        /* Unexpected */
        return -1;
    }

    if (rd_sz <= 0) {
        return rd_sz;
    }

    cbuf_put(b, rd_sz);
    rem_rcv_sz -= rd_sz;

    if (rem_rcv_sz) goto read_again;

    *orig_b = b;
    return tot_rcv_sz; 
}

int 
c_socket_read_block_loop(int fd, void *arg, c_conn_t *conn,
                         const size_t max_rcv_buf_sz, 
                         conn_proc_t proc_msg, int (*get_data_len)(void *),
                         bool (*validate_hdr)(void *), size_t hdr_sz) 
{
    ssize_t             rd_sz = -1;
    struct cbuf         *b = NULL;
    size_t              tot_need_rd = hdr_sz, tot_len = 0;

    b = alloc_cbuf(max_rcv_buf_sz);
    rd_sz = c_socket_read_chunk_loop(fd, &b, conn, hdr_sz); 
    if (rd_sz <= 0) {
        free_cbuf(b);
        return rd_sz;
    }

    tot_need_rd = get_data_len(b->data);
    if (tot_need_rd < hdr_sz) {
        free_cbuf(b);
        printf("%s: Buf sz < hdr_sz \n", FN);
        return 0;
    }

    if (!validate_hdr(b->data)) {
        printf("%s: Corrupted header\n", FN);
        free_cbuf(b);
        return 0; /* Close the socket */
    }
   
    if (tot_need_rd - hdr_sz) {
        rd_sz = c_socket_read_chunk_loop(fd, &b, conn, tot_need_rd - hdr_sz);
        if (rd_sz <= 0) {
            free_cbuf(b);
            return rd_sz;
        }
    }

    tot_len = b->len;
    conn->rx_pkts++;
    proc_msg(arg, b);

    return tot_len;
}

void
c_conn_tx(void *conn_arg, struct cbuf *b,
          void (*delay_tx)(void *conn))
{
    c_conn_t *conn = conn_arg;

    c_wr_lock(&conn->conn_lock);

    if (cbuf_list_queue_len(&conn->tx_q) > 1024) {
        c_wr_unlock(&conn->conn_lock);
        free_cbuf(b);
        return;
    }

    cbuf_list_queue_tail(&conn->tx_q, b);
    c_socket_write_nonblock_loop(conn, delay_tx);
    c_wr_unlock(&conn->conn_lock);

}

size_t
c_count_one_bits(uint32_t num)
{
    int n = 0;
    while (num > 0) {
        num &= num-1;
        n++;
    }
    return n;
}

size_t
c_count_ipv6_plen(const struct in6_addr *netmask)
{
    int len = 0;
    unsigned char val;
    unsigned char *p;

    p = (unsigned char *)netmask;

    while ((*p == 0xff) && len < 128) {
        len += 8;
        p++;
    }

    if (len < 128) {
        val = *p;
        while (val) {
            len++;
            val <<= 1;
        }
    }
    return len;
}
