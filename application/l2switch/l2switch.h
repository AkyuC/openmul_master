/*
 *  l2switch.h: L2switch application headers
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
#ifndef __L2SW_H__
#define __L2SW_H__

#define L2FDB_ITIMEO_DFL (60) 
#define L2FDB_HTIMEO_DFL (0) 

#define L2MFDB_ITIMEO_DFL (5) 
#define L2MFDB_HTIMEO_DFL  (20) 

#define L2SW_UNK_BUFFER_ID (0xffffffff)
//#define CONFIG_L2SW_FDB_CACHE 1

struct l2fdb_ent_
{
    uint8_t  mac_da[OFP_ETH_ALEN];
    uint32_t lrn_port;
};
typedef struct l2fdb_ent_ l2fdb_ent_t;

struct l2mcast_port
{
    uint32_t port;
    time_t installed;
};
typedef struct l2mcast_port l2mcast_port_t;

struct l2mfdb_ent_
{
    uint32_t group;
    uint32_t dpid;
    GSList *port_list;
};
typedef struct l2mfdb_ent_ l2mfdb_ent_t;

struct l2sw_
{
    c_rw_lock_t lock;
    c_atomic_t  ref;
    uint64_t    swid;
    GHashTable  *l2fdb_htbl;
    GHashTable  *l2mfdb_htbl;
};

typedef struct l2sw_ l2sw_t;

struct l2sw_fdb_port_args
{
    l2sw_t   *sw;
    uint16_t port;
};

void l2sw_module_init(void *ctx);
void l2sw_module_vty_init(void *arg);

#endif
