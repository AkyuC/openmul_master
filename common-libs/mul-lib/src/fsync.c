/*
 *  fsync.c: File syncing function 
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>

#include "c_util.h"
#include "clog.h"
#include "fsync.h"

pthread_t server_thread;

static int
readn(int sd, char *ptr, int size)
{         
    int no_left,no_read;

    no_left = size;
    while (no_left > 0) {
        no_read = read(sd,ptr,no_left);
        if(no_read <0)  return(no_read);
        if (no_read == 0) break;
        no_left -= no_read;
        ptr += no_read;
    }
    return(size - no_left);
}

static int
writen(int sd,char *ptr,int size)
{      
    int no_left,no_written;
    no_left = size;
    while (no_left > 0)  {
        no_written = write(sd,ptr,no_left);
        if(no_written <=0)  return(no_written);
        no_left -= no_written;
        ptr += no_written;
    }
    return(size - no_left);
}

int
c_fsync(const char *fname, const char *server_ip, 
        uint16_t port)
{
    int sockid, i, getfile, ack, msg, msg_2, len;
    int start_xfer, num_blks, num_blks1, num_last_blk, num_last_blk1;
    struct sockaddr_in server_addr; 
#ifdef FSYNC_CLIENT_BIND
    struct sockaddr_in my_addr; 
#endif
    FILE *fp; 
    char out_buf[MAX_BLK_SIZE];
    int err = 0, fsize = 0;
    int no_read = 0;

    num_blks = 0;
    num_last_blk = 0;

    len = strlen(fname)+1;

    signal(SIGPIPE, SIG_IGN);

    if ((sockid = socket(AF_INET,SOCK_STREAM,0)) < 0) {
        c_log_err("client: socket error : %d\n", errno);
        return -1;
    }
  
    i = 1;
    setsockopt(sockid, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
    i = 0;

#ifdef FSYNC_CLIENT_BIND
    bzero((char *) &my_addr,sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    my_addr.sin_port = htons(FSYNC_CLIENT_PORT);
    if (bind(sockid ,(struct sockaddr *) &my_addr,sizeof(my_addr)) < 0) {
        c_log_err("|fsync|: bind  error :%d\n", errno);
        err = -1;
        goto sclose_out;
    }
#endif
                                             
    bzero((char *) &server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_aton(server_ip, &server_addr.sin_addr);
    server_addr.sin_port = htons(port ? : FSYNC_SERVER_PORT);
    if (connect(sockid ,(struct sockaddr *) &server_addr,
                sizeof(server_addr)) < 0) {
        c_log_err("|fsync|: connect error :%d\n", errno);
        err = -1;
        goto sclose_out;
    }

    /* tell server that we want to send a file */
    getfile = htons(SENDFILE);
    if((writen(sockid, (char *)&getfile, sizeof(getfile))) < 0) {
        c_log_err("|fsync| client: write  error :%d", errno);
        err = -1;
        goto sclose_out;
    } 

    /* Wait for go-ahead from server */
    msg = 0;  
    if((readn(sockid,(char *)&msg,sizeof(msg)))< 0) {
        c_log_err("|fsync| client: write  error :%d", errno);
        err = -1;
        goto sclose_out;
    }

    if (ntohs(msg) == COMMANDNOTSUPPORTED) {
        c_log_err("|fsync| client: not supported");
        err = -1;
        goto sclose_out;
    }

    /* send file name to server */
    if ((writen(sockid, (char *)fname, len)) < 0) {
        c_log_err("|fsync| client: write  error :%d", errno);
        err = -1;
        goto sclose_out;
    }

    /* see if server replied that file name is OK */
    msg_2 = 0;
    if ((readn(sockid, (char *)&msg_2, sizeof(msg_2))) < 0) {
        c_log_err("|fsync| client: read error :%d", errno);
        err = -1;
        goto sclose_out; 
    }

    if (ntohs(msg_2) == BADFILENAME) {
        c_log_err("|fsync| client: fname rejected by server");
        err = -1;
        goto sclose_out;
    }

    start_xfer = htons(STARTTRANSFER);
    if ((writen(sockid, (char *)&start_xfer, sizeof(start_xfer))) < 0) {
        c_log_err("|fsync| client: write xfer err %d", errno);
        err = -1;
        goto sclose_out;
    }

    if((fp = fopen(fname, "r")) == NULL) {
        c_log_err("|fsync| client: %s fname cant open", fname);
        err = -1;
        goto sclose_out;
    } 

    fsize = 0;
    ack = 0;   

    fseek(fp, 0L, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    num_blks = fsize / MAX_BLK_SIZE; 
    num_blks1 = htons(num_blks);
    num_last_blk = fsize % MAX_BLK_SIZE; 
    num_last_blk1 = htons(num_last_blk);
    if ((writen(sockid, (char *)&num_blks1, sizeof(num_blks1))) < 0) {
        c_log_err("|fsync| client: write err %d", errno);
        err = -1;
        goto fclose_out;
    }

    if ((readn(sockid, (char *)&ack, sizeof(ack))) < 0) {
        c_log_err("|fsync| client: ack read err %d", errno);
        err = -1;
        goto fclose_out;
        
    }
    if (ntohs(ack) != ACK) {
        c_log_err("|fsync| client: ack err %d", errno);
        err = -1;
        goto fclose_out;
    }
    if ((writen(sockid, (char *)&num_last_blk1, sizeof(num_last_blk1))) < 0) {
        c_log_err("|fsync| client: write err %d", errno);
        err = -1;
        goto fclose_out;
    }
    if((readn(sockid, (char *)&ack, sizeof(ack))) < 0) {
        c_log_err("|fsync| client: ack read err %d", errno);
        err = -1;
        goto fclose_out;
    }
    if (ntohs(ack) != ACK) {
        c_log_err("|fsync| client: ack err");
        err = -1;
        goto fclose_out;
    }

    for(i= 0; i < num_blks; i++) { 
        no_read = fread(out_buf, sizeof(char), MAX_BLK_SIZE, fp);
        if (no_read == 0 || no_read != MAX_BLK_SIZE) {
            c_log_err("|fsync| client: file read err");
            err = -1;
            goto fclose_out;
        }

        if ((writen(sockid, out_buf, MAX_BLK_SIZE)) < 0) {
            c_log_err("|fsync| client: write err %d", errno);
            err = -1;
            goto fclose_out;
        }

        if ((readn(sockid,(char *)&ack,sizeof(ack))) < 0) {
            c_log_err("|fsync| client: ack read err %d", errno);
            err = -1;
            goto fclose_out;
        }
        if (ntohs(ack) != ACK) {
            c_log_err("|fsync| client: ack err");
            err = -1;
            goto fclose_out;
        }
    }

    if (num_last_blk > 0) { 
        no_read = fread(out_buf,sizeof(char),num_last_blk,fp); 
        if (no_read == 0 || no_read != num_last_blk) {
            c_log_err("|fsync| client: file read err");
            err = -1;
            goto fclose_out;
        }
        if((writen(sockid, out_buf, num_last_blk)) < 0) {
            c_log_err("|fsync| client: write err %d", errno);
            err = -1;
            goto fclose_out;
        }
        if((readn(sockid, (char *)&ack, sizeof(ack))) < 0) {
            c_log_err("|fsync| client: ack rd err %d", errno);
            err = -1;
            goto fclose_out;
        }
        if (ntohs(ack) != ACK) {
            c_log_err("|fsync| client: ack err");
            err = -1;
            goto fclose_out;
        }
    }

fclose_out:
    fclose(fp);
sclose_out:
    close(sockid);

    return err;
}        

int
c_fsync_dir(const char *dir, const char *server_ip, uint16_t port)
{
    DIR *fd = 0;
    struct dirent* in_file;
    int err = 0;
    char fname[MAX_FLINE];

    if (!(fd = opendir(dir))) { 
        c_log_err("%s: Fail to open dir %s", FN, dir);
        return -1;
    }

    memset(fname, 0, sizeof(fname));
    while ((in_file = readdir(fd))) {
        if (!strcmp (in_file->d_name, ".") ||
            !strcmp (in_file->d_name, ".."))
            continue;
        strncpy(fname, dir, MAX_FLINE - 1);
        strncat(fname, in_file->d_name,
                MAX_FLINE - 1 - strlen(fname)); 
        c_log_info("%s: Syncing file %s to %s:%u",
                    FN, fname, server_ip, port?:FSYNC_SERVER_PORT);
        err = c_fsync(fname, server_ip, port);
    }

    return err;
}

static void
dofsync(int newsd)
{       
    int i, msg_ok, fail, req, ack;
    int num_blks, num_last_blk;
    int no_writen, tmp;
    char fname[MAX_FLINE];
    char in_buf[MAX_BLK_SIZE];
    FILE *fp = NULL;
      
#define FSYNC_TMP_FILE "/tmp/fsync.tmp"
    num_blks = 0;
    num_last_blk = 0; 

    req = 0;
    if((readn(newsd, (char *)&req, sizeof(req))) < 0) {
        c_log_err("|fsync| server : rd err %d", errno);
        return;
    }

    if (ntohs(req) != SENDFILE) {
         /* reply to client: command not OK  (code: 150) */
         msg_ok = COMMANDNOTSUPPORTED; 
         msg_ok = htons(msg_ok);
         if((writen(newsd, (char *)&msg_ok, sizeof(msg_ok))) < 0) {
            c_log_err("|fsync| server : wr err %d", errno);
            return;
         }
    }

    /* reply to client: command OK  (code: 160) */
    msg_ok = COMMANDSUPPORTED; 
    msg_ok = htons(msg_ok);
    if((writen(newsd, (char *)&msg_ok, sizeof(msg_ok))) < 0) {
        c_log_err("|fsync| server : wr err %d", errno);
        return;           
    }

    fail = FILENAMEOK;
    if ((read(newsd, fname, MAX_FLINE)) < 0) {
        fail = BADFILENAME;
    }
   
    if (fail != BADFILENAME) {
        c_log_info("%s: Syncing file %s", FN, fname);
        if((fp = fopen(fname, "w+")) == NULL) /*cant open file*/
            fail = BADFILENAME;
        else {
            fclose(fp);
            if((fp = fopen(FSYNC_TMP_FILE, "w+")) == NULL)
                fail = BADFILENAME;
        }
    } else {
        perror("");
    }

    tmp = htons(fail);
    if ((writen(newsd, (char *)&tmp, sizeof(tmp))) < 0) {
        c_log_err("|fsync| server : wr err %d", errno);
        goto out;
    }
    if(fail == BADFILENAME) {
        c_log_err("|fsync| server file err");
        goto out;
    }
  
    req = 0;
    if ((readn(newsd,(char *)&req, sizeof(req))) < 0) {
        c_log_err("|fsync| server rd err %d", errno);
        goto out;
    }

    if ((readn(newsd,(char *)&num_blks,sizeof(num_blks))) < 0) {
        c_log_err("|fsync| server read error on nblocks :%d", errno);
        goto out;
    }

    num_blks = ntohs(num_blks);
    ack = ACK;  
    ack = htons(ack);
    if ((writen(newsd, (char *)&ack ,sizeof(ack))) < 0) {
        c_log_err("|fsync| server : wr err %d", errno);
        goto out;
    }

    if ((readn(newsd, (char *)&num_last_blk, sizeof(num_last_blk))) < 0) {
        c_log_err("|fsync| server : wr err %d", errno);
        goto out;
    }

    num_last_blk = ntohs(num_last_blk);  
    if((writen(newsd, (char *)&ack, sizeof(ack))) < 0) {
        c_log_err("|fsync| server : wr err %d", errno);
        goto out;
    }

    for(i= 0; i < num_blks; i ++) {
        if((readn(newsd, in_buf, MAX_BLK_SIZE)) < 0) {
            c_log_err("|fsync| server : rd err %d", errno);
            goto out;
        }
        no_writen = fwrite(in_buf,sizeof(char),MAX_BLK_SIZE,fp);
        if (no_writen == 0 || no_writen != MAX_BLK_SIZE) {
            c_log_err("|fsync| server : wr err %d", errno);
            goto out;
        }
        /* send an ACK for this block */
        if ((writen(newsd, (char *)&ack, sizeof(ack))) < 0) {
            c_log_err("|fsync| server : wr ack err %d", errno);
            goto out;
        }
    }

    if (num_last_blk > 0) {
        if((readn(newsd, in_buf, num_last_blk)) < 0) {
            c_log_err("|fsync| server : wr err %d", errno);
            goto out;
        }
        no_writen = fwrite(in_buf, sizeof(char), num_last_blk, fp); 
        if (no_writen == 0 || no_writen != num_last_blk) { 
            c_log_err("|fsync| server last block file write err :%d", errno);
            goto out;
        }
        if((writen(newsd, (char *)&ack, sizeof(ack))) < 0) {
            c_log_err("|fsync| server : wr ack err %d", errno);
            goto out;
        }
    }

    if (unlink(fname) < 0) {
        c_log_err("|fsync| Cant unlink existing file %s", fname);
    } else {
        if (link(FSYNC_TMP_FILE, fname) < 0) {
            c_log_err("|fsync| Cant link to file %s", fname);
        }
    }
    unlink(FSYNC_TMP_FILE);
    sync();

out:
   fclose(fp);
}

static void *
fsync_server_thread(void *arg __attribute__((unused)))
{
    int sockid, newsd, pid;
    struct sockaddr_in my_addr, client_addr;   
    socklen_t client_addr_len = sizeof(my_addr);

    if ((sockid = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        c_log_err("|fsync| socket err %d", errno);
        return NULL;
    }

    pid = 1;
    setsockopt(sockid, SOL_SOCKET, SO_REUSEADDR, &pid, sizeof(pid));

    memset(&my_addr, 0, sizeof(my_addr));

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(FSYNC_SERVER_PORT);
    my_addr.sin_addr.s_addr = htons(INADDR_ANY);

    if (bind(sockid, (struct sockaddr *) &my_addr, sizeof(my_addr)) < 0) {
        c_log_err("server: bind  error :%d\n", errno);
        close(sockid);
        return NULL;
    }
    if (listen(sockid,5) < 0) {
        c_log_err("server: listen error :%d\n",errno);
        return NULL;
    }                                        

    c_log_info("[FSYNC] Server started");
    while(1) { 
        if ((newsd = accept(sockid ,(struct sockaddr *) &client_addr,
                            &client_addr_len)) < 0) {
            c_log_err("%s: Accept failed", FN);
            continue;
        }
        if ((pid = fork()) == 0) {
            close(sockid);   /* child shouldn't do an accept */
            dofsync(newsd);
            close (newsd);
            exit(0);         /* child all done with work */
         }
         close(newsd);       /* parent all done with client, only child */
    }
    return NULL;
} 

int
fsync_server_start(void)
{
    return pthread_create(&server_thread, NULL, fsync_server_thread, NULL); 
}
