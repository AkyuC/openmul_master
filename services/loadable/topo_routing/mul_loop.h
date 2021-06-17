/*  mul_loop.h: MUL loop detection framework headers
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 *
 */
#ifndef __MUL_LOOP_H__
#define __MUL_LOOP_H__

#define LOOP_PORT_HOLD_TIMEO (2)
#define LOOP_PORT_TR_TIMEO (2)

void __mul_loop_port_update(lldp_switch_t *sw, lldp_port_t *port,
                       int new_state);
void mul_loop_port_mod(uint64_t dpid, uint32_t port_no,
                       int loop_state);
void mul_loop_detect(topo_hdl_t *topo, bool timeo);
void mul_loop_detect_reset(bool lock);

#endif
