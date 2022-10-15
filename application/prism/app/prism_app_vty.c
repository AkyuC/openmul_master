/*  mul_fabric_vty.c: Mul fabric vty implementation 
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
#include "mul_vty.h"
#include "prism_common.h"
#include "prism_app.h"
#include "prism_app_route.h"
#include "prism_app_nh.h"


#ifdef MUL_APP_VTY

extern prism_app_struct_t *prism_ctx;
static int 
__add_prism_route_cmd(struct vty *vty, const char **argv)
{
    uint64_t dpid;
    uint32_t dst_nw;
    uint32_t nmask;
    uint32_t next_hop;
    uint32_t oif;
    struct prefix_ipv4 host_ip;
    int ret = 0;

    ret = str2prefix(argv[0], (void *)&host_ip);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    dst_nw = host_ip.prefix.s_addr;
    nmask = make_inet_mask(host_ip.prefixlen);

    ret = str2prefix(argv[1], (void *)&host_ip);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    next_hop = host_ip.prefix.s_addr;
    dpid = strtoull(argv[2], NULL, 16);
    oif = atoi(argv[3]);

    prism_route_add(prism_ctx, dst_nw, nmask, next_hop, dpid, oif);

    return CMD_SUCCESS;

}

DEFUN (add_prism_route,
       add_prism_route_cmd,
        "add prism-route "
        "host-ip A.B.C.D/M "
        "next-hop A.B.C.D "
        "conn-sw-dpid X "
        "port <0-65535> ",
        "Add a configuration\n" 
        "Prism connected host\n"
        "Host ip address and mask\n"
        "Valid ip address/mask\n"
        "Next Hop ip address \n"
        "Valid ip address\n"
        "Connected switch dpid\n"
        "Valid dpid in X format\n"
        "Outgoing interface port-no\n"
        "Enter port-number\n")
{
    return __add_prism_route_cmd(vty, argv);
}

static int 
__del_prism_route_cmd(struct vty *vty, const char **argv)
{
    uint32_t dst_nw;
    uint32_t nmask;
    struct prefix_ipv4 host_ip;
    int  ret = 0;

    ret = str2prefix(argv[0], (void *)&host_ip);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    dst_nw = host_ip.prefix.s_addr;
    nmask = make_inet_mask(host_ip.prefixlen);

    prism_route_delete(prism_ctx, dst_nw, nmask, true);

    return CMD_SUCCESS;

}

DEFUN (del_prism_route,
       del_prism_route_cmd,
        "del prism-route "
        "host-ip A.B.C.D/M ",
        "Delete a configuration\n" 
        "Prism connected host\n"
        "Host ip address and mask\n"
        "Valid ip address/mask\n")
{
    return __del_prism_route_cmd(vty, argv);
}

static void
show_vty_prism_route(void *route, void *v_arg UNUSED, void *vty_arg)
{
    char *pbuf;
    struct vty *vty = vty_arg;

    pbuf = prism_dump_single_route(route);

    vty_out(vty, "%s", pbuf);    
    vty_out(vty, "%s", VTY_NEWLINE);
    free(pbuf);
}

DEFUN (show_prism_route_all,
       show_prism_route_all_cmd,
        "show prism-routes all",
        SHOW_STR
        "Prism connected routes\n"
        "All Routes\n")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    prism_loop_all_routes(prism_ctx,show_vty_prism_route,vty);

    vty_out(vty, "%s", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

static int 
__add_prism_nh_cmd(struct vty *vty, const char **argv)
{
    uint64_t dpid;
    uint32_t next_hop;
    uint32_t oif;
    uint32_t nh_flags;
    struct prefix_ipv4 host_ip;
    uint8_t *mac_str = NULL, *next = NULL;
    uint8_t nh_mac[ETH_ADDR_LEN];
    int ret = 0, i = 0;

    ret = str2prefix(argv[0], (void *)&host_ip);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    next_hop = host_ip.prefix.s_addr;
   

    dpid = strtoull(argv[1], NULL, 16);
    oif = atoi(argv[2]);
    
    mac_str = (void *)argv[3];

    for (i = 0; i < 6; i++) {
        nh_mac[i] = (uint8_t)strtoul((const char*)mac_str,(char**) &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    nh_flags = atoi(argv[4]);

    prism_next_hop_add(prism_ctx, next_hop, dpid, oif, nh_flags, nh_mac);

    return CMD_SUCCESS;

}

DEFUN (add_prism_nh,
       add_prism_nh_cmd,
        "add prism-nh "
        "next-hop A.B.C.D "
        "conn-dpid X "
        "port <0-65535> "
        "next-hop-mac X "
        "flag (1|2) ",
        "Add a configuration\n" 
        "Prism connected host\n"
        "Next Hop ip address \n"
        "Valid ip address\n"
        "Connected switch dpid\n"
        "Valid dpid in X format\n"
        "Outgoing interface port-no\n"
        "Enter port-number\n"
        "Next hop mac address\n"
        "Valid mac address in X:X...X format\n"
        "Next Hop Flag\n"
        "1 - RESOLVED\n"
        "2 - PERMANENT")
{
    return __add_prism_nh_cmd(vty, argv);
}

static int 
__del_prism_nh_cmd(struct vty *vty, const char **argv)
{
    uint64_t dpid;
    uint32_t next_hop;
    uint32_t oif;
    struct prefix_ipv4 host_ip;
    int ret = 0;

    ret = str2prefix(argv[0], (void *)&host_ip);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    next_hop = host_ip.prefix.s_addr;
    dpid = strtoull(argv[1], NULL, 16);
    oif = atoi(argv[2]);

    prism_next_hop_del(prism_ctx, next_hop, dpid, oif);

    return CMD_SUCCESS;

}

DEFUN (del_prism_nh,
       del_prism_nh_cmd,
        "del prism-nh "
        "next-hop A.B.C.D "
        "conn-dpid X "
        "port <0-65535> ",
        "Add a configuration\n" 
        "Prism connected host\n"
        "Next Hop ip address \n"
        "Valid ip address\n"
        "Connected switch Dpid\n"
        "Valid DPID in X format\n"
        "Outgoing interface port-no\n"
        "Enter port-number\n")

{
    return __del_prism_nh_cmd(vty, argv);
}

static void
show_vty_prism_nh(void *route, void *v_arg UNUSED, void *vty_arg)
{
    char *pbuf;
    struct vty *vty = vty_arg;

    pbuf = prism_dump_single_nh(route);

    vty_out(vty, "%s", pbuf);    
    vty_out(vty, "%s", VTY_NEWLINE);
    free(pbuf);
}

DEFUN (show_prism_nh_all,
       show_prism_nh_all_cmd,
        "show prism-nh all",
        SHOW_STR
        "Prism connected routes\n"
        "All Next hop\n")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    prism_loop_all_nh(prism_ctx,show_vty_prism_nh,vty);

    vty_out(vty, "%s", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

/* install available commands */
void
prism_vty_init(void *arg UNUSED)
{
    /* commands work only after "enable" command in the beginning */
    app_log_debug("%s: installing prism vty command", FN);
    install_element(ENABLE_NODE, &show_prism_route_all_cmd);
    install_element(ENABLE_NODE, &add_prism_route_cmd);
    install_element(ENABLE_NODE, &del_prism_route_cmd);
    install_element(ENABLE_NODE, &show_prism_nh_all_cmd);
    install_element(ENABLE_NODE, &add_prism_nh_cmd);
    install_element(ENABLE_NODE, &del_prism_nh_cmd);
}

#else
/* install available commands */
void
prism_vty_init(void *arg UNUSED)
{
}
#endif
