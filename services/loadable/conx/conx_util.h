/*
 *  conx_util.h: ConX  utility headers
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
#ifndef __CONX_UTIL_H__
#define __CONX_UTIL_H__
/* Note: Normally switch's table 0 is a hardware table and may not support all
 * actions which may be required by ConX, so to be on safer side ConX is
 * going to use Table 1 and Table 2*/
#define CONX_L1_TABLE_ID 1
#define CONX_L2_TABLE_ID 2

#define CONX_UFLOW_PRIO 100
#define CONX_UFLOW_PRIO_LO 50 
#define CONX_5SEC_TV {5,0} 

static inline
void *__conx_calloc(size_t len, char *file, int line, bool safe)
{
    void *ptr = calloc(1, len);
    if (!ptr) {
        c_log_warn("%s: fail (%s:%d)", FN, file, line);
        if (!safe) assert(0);
    }
    return ptr;
}

#define conx_calloc(x) __conx_calloc(x, __FILE__, __LINE__, false)
#define conx_mallox(x) __conx_calloc(x, __FILE__, __LINE__, false)
#define conx_safe_calloc(x) __conx_calloc(x, __FILE__, __LINE__, true)
#define conx_free(x) free(x)

#endif
