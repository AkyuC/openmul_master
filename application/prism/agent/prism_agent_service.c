/*
 *  prism_agent_service.c: PRISM agent service for MUL Controller 
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
#include <netinet/in.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_tun.h>
#include "mul_vty.h"
#include "prism_agent.h"
#include "prism_common.h"

extern struct prism_agent_ctx *CTX;

static bool
check_reply_type(struct cbuf *b, uint8_t cmd_code)
{
    struct prism_idl_hdr *hdr = CBUF_DATA(b);
	
	if (ntohs(hdr->len) < sizeof(struct prism_idl_hdr)) {
        c_log_err("%s: Size err (%hu) of (%lu)", FN, 
				  (unsigned short)ntohs(hdr->len), 
				  (unsigned long)(sizeof(struct prism_idl_hdr)));
		return false;
    }

    if (hdr->cmd != cmd_code) {
		c_log_err("%s: cmd code err (%u)", FN, hdr->cmd);
        return false;
    }

    return true;
}

int
prism_service_send(void *service, struct cbuf *b,
                   bool wait, uint8_t resp)
{
    int ret = 0;

    wait = false; // Override
    if (!service || !b) {
        if (b) free_cbuf(b);
        return -1;
    }

    if (!mul_service_available(service)) {
        app_rlog_err("%s: %s is dead", FN,
                     ((mul_service_t *)service)->service_name); 
        return -1;
    }

    c_wr_lock(&CTX->serv_lock);
    c_service_send(service, b);

    if(wait) {
        b = c_service_wait_response(service);
    } else {
        b = NULL;
    }
    c_wr_unlock(&CTX->serv_lock);
    if (b) {
        if (wait &&
            !check_reply_type(b, resp)) {
            ret = -1;
        }
        free_cbuf(b); 
    }

    return ret;
}

