/*
 * rlimit.h - Simple rate limit headers
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

#ifndef __C_RLIM_H__
#define __C_RLIM_H__

#include "lock.h"

struct c_rlim_dat
{
    c_rw_lock_t lock;
    struct timeval limit_ts;
    struct timeval start_ts;
    int  max;
    int  pass;
    int  skip;
};

extern bool c_rlim(struct c_rlim_dat *rs);

#define C_RL_DEFINE(name__, lim_ms, max__) \
struct c_rlim_dat name__ = {        \
    .lock = PTHREAD_RWLOCK_INITIALIZER, \
    .limit_ts = { .tv_sec = ((lim_ms)/1000), \
                  .tv_usec = (((lim_ms)%1000)*1000)  \
                }, \
    .start_ts = { .tv_sec = 0, \
                  .tv_usec = 0 \
                }, \
    .max = max__ \
} \

static inline void
c_rlim_dat_init(struct c_rlim_dat *rs, uint32_t msecs, int max)
{
    memset(rs, 0, sizeof(struct c_rlim_dat));
    c_rw_lock_init(&rs->lock);
    rs->limit_ts.tv_sec = (msecs)/1000;
    rs->limit_ts.tv_usec = ((msecs%1000)*1000);

    rs->max = max;
}

int c_rlim_dat_update(struct c_rlim_dat *rs, uint32_t pps);

#endif 
