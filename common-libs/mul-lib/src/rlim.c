/*
 * rlimit.c - Simple rate limit
 * Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "lock.h"
#include "c_util.h"
#include "clog.h"
#include "rlim.h"

#define ZERO_TS(ts) (!(ts)->tv_sec && !(ts)->tv_usec)
#define SET_ZERO_TS(ts) do { (ts)->tv_sec = 0; (ts)->tv_usec = 0; } while (0)

/*
 * c_rlim - Perform rate limiting
 *
 * return val :
 * false - Ok to process
 * true - Rlim exceeded 
 */
bool
c_rlim(struct c_rlim_dat *rs)
{
    bool do_limit;
    struct timeval curr_ts, diff_ts;
 
    c_wr_lock(&rs->lock);

    if (ZERO_TS(&rs->limit_ts)) {
        c_wr_unlock(&rs->lock);
        return 1;
    }
 
    if (ZERO_TS(&rs->start_ts)) {
        gettimeofday(&rs->start_ts, NULL);
    }

    gettimeofday(&curr_ts, NULL);
    c_timeval_diff(&diff_ts, &curr_ts, &rs->start_ts);

    if (c_timeval_a_more_b(&diff_ts, &rs->limit_ts)) {
        if (rs->skip) {
            c_log_info("RLIM:%d suppressed", rs->skip);
        }
        SET_ZERO_TS(&rs->start_ts);
        rs->pass = 0;
        rs->skip  = 0;
    }

    if (rs->max && rs->max > rs->pass) {
        rs->pass++;
        do_limit = false;
    } else {
        rs->skip++;
        do_limit = true;
    }
    c_wr_unlock(&rs->lock);
 
    return do_limit;
}
 
int
c_rlim_dat_update(struct c_rlim_dat *rs, uint32_t pps)
{
    uint32_t msecs = 1000;

    if (!rs || !pps) {
        return -1;
    }

    c_wr_lock(&rs->lock);
    rs->limit_ts.tv_sec = (msecs)/1000;
    rs->limit_ts.tv_usec = ((msecs%1000)*1000);
    rs->max = pps;
    c_wr_unlock(&rs->lock);

    return 0;
}
