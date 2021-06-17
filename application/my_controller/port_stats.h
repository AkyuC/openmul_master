#ifndef __MUL_PORT_STATS_H__
#define __MUL_PORT_STATS_H__
#include "mul_common.h"
#include "config.h"

struct c_ofp_stats_request {
    struct ofp_header header;
    uint64_t            datapath_id;
    uint16_t type;              /* One of the OFPST_* constants. */
    uint16_t flags;             /* OFPSF_REQ_* flags (none yet defined). */
    uint8_t body[0];            /* Body of the request. */
};
void mul_app_send_stats_request(uint64_t dpid, uint32_t port_no);

#endif