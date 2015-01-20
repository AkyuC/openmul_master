/*
 *  prism_servlet.c: MUL fabric cli service 
 *  Copyright (C) 2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#include "prism_common.h"
#include "prism_app.h"

extern prism_app_struct_t *prism_ctx;
int prism_app_service_send(void *service, struct cbuf *b,
                           bool wait, uint8_t resp);

static bool
check_reply_type(struct cbuf *b, uint8_t cmd_code)
{
    struct prism_idl_hdr *hdr = CBUF_DATA(b);
	
	if (ntohs(hdr->len) < sizeof(struct prism_idl_hdr)) {
        app_log_err("%s: Size err (%hu) of (%lu)", FN, 
				  (unsigned short)ntohs(hdr->len), 
				  (unsigned long)(sizeof(struct prism_idl_hdr)));
		return false;
    }

    if (hdr->cmd != cmd_code) {
		app_log_err("%s: cmd code err (%u)", FN, hdr->cmd);
        return false;
    }

    return true;
}

int
prism_app_service_send(void *service, struct cbuf *b,
                   bool wait, uint8_t resp)
{
    int ret = 0;

    if (!service || !b) {
        if (b) free_cbuf(b);
        return -1;
    }

    c_wr_lock(&prism_ctx->serv_lock);
    c_service_send(service, b);

    if(wait) {
        b = c_service_wait_response(service);
    } else {
        b = NULL;
    }
    c_wr_unlock(&prism_ctx->serv_lock);
    if (b) {
        if (wait &&
            !check_reply_type(b, resp)) {
            ret = -1;
        }
        free_cbuf(b); 
    }

    return ret;
}


