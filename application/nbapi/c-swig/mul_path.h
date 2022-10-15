/*
 * mul_nbapi_path.h: Mul Northbound Path Compute API application headers
 * Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#ifndef __MUL_NBAPI_PATH_H__
#define __MUL_NBAPI_PATH_H__


typedef struct {
    uint64_t datapath_id;
    uint8_t of_version;
    uint8_t n_tables;       /* Number of tables supported by datapath. */
    uint32_t capabilities;  /* Bitmap of support "ofp_capabilities". */
    uint32_t actions;       /* Bitmap of supported "ofp_action_type"s. */
    uint32_t n_ports;
} Switch;

typedef struct {
    uint64_t datapath_id;
    uint32_t n_ports;
    uint32_t state;
#define OFP_CONN_DESC_SZ (32)
    char peer[OFP_CONN_DESC_SZ];
} Switch_Brief;

/* TODO: add more info into Port*/
typedef struct {
    uint16_t port_no;
    uint8_t hw_addr[OFP_ETH_ALEN];
    uint32_t port_status;
    uint32_t link_id;
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */
} Port;

typedef struct {
    uint16_t port_no;
    uint8_t mac_addr[OFP_ETH_ALEN];
    uint32_t port_status;
    /* TODO: Link currently not supported by MLAPI */
    /* uint32_t link_id; */
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */
} Port_Brief;

Switch *get_switch(uint64_t datapath_id);
Switch_Brief *get_switch_all(void);

Port *get_switch_port(uint64_t datapath_id, uint16_t port_no);
Port_Brief *get_switch_port_all(uint64_t datapath_id);

/* TODO: Device not supported by Topology Manager MLAPI Service */
/*
typedef struct {
    uint64_t device_id;
    uint32_t type;
    uint32_t tenant_id;
} Device;

Device *get_device_all();
int add_device(Device *device);
Device get_device(uint64_t datapath_id);
int modify_device(Device *device);
int remove_device(Device *device);
Port *get_device_port_all(uint64_t device_id);
int add_device_port(Port *port);
Port get_device_port(uint64_t device_id, uint16_t port_id);
int modify_device_port(Port *port);
int remove_device_port(Port *port);
*/

typedef struct {
    uint32_t link_id;
    uint64_t node1_id;
    uint64_t node2_id;
    uint16_t node1_port_id;
    uint16_t node2_port_id;
    /* more info */
} Link;
/*
Link *get_link_all();
int add_link(Link *link);
Link *get_link(Link *link);
int modify_link(Link *link);
int remove_link(Link *link);
*/
#endif
