/*
 *  l2switch.c: L2switch application for MUL Controller 
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
#include "l2switch.h"

extern struct mul_app_client_cb l2sw_app_cbs;
int l2sw_mod_flow(l2sw_t *l2sw, l2fdb_ent_t *fdb, 
                  bool add_del, uint32_t buffer_id);
static void l2sw_install_dfl_flows(uint64_t dpid);
static void l2_fdb_ent_free(void *arg);

c_rw_lock_t app_lock;
struct event *l2sw_timer_event;

#ifndef CONFIG_L2SW_FDB_CACHE
static int
l2sw_set_fp_ops(l2sw_t *l2sw)
{
    c_ofp_set_fp_ops_t  *cofp_fp;
    struct cbuf         *b;

    b = of_prep_msg(sizeof(*cofp_fp), C_OFPT_SET_FPOPS, 0);

    cofp_fp = (void *)(b->data);
    cofp_fp->datapath_id = htonll(l2sw->swid); 
    cofp_fp->fp_type = htonl(C_FP_TYPE_L2);

    return mul_app_command_handler(L2SW_APP_NAME, b);
}
#endif

static void
l2_fdb_ent_free(void *arg)
{
    free(arg);
}

static void
l2_mfdb_ent_free(void *arg)
{
    l2mfdb_ent_t *mfdb = arg;

    if (mfdb->port_list)
        g_slist_free_full(mfdb->port_list, l2_fdb_ent_free);
    free(mfdb);
}

static unsigned int 
l2fdb_key(const void *p)
{   
    const uint8_t *mac_da = p;
    
    return hash_bytes(mac_da, OFP_ETH_ALEN, 1);
}

static int
l2fdb_equal(const void *p1, const void *p2)
{
    return !memcmp(p1, p2, OFP_ETH_ALEN);
}

#ifdef CONFIG_L2SW_FDB_CACHE
static int
check_l2port_down_l2sw_fdb(void *key UNUSED, void *ent, void *u_arg)
{
    l2fdb_ent_t                 *fdb = ent;
    struct l2sw_fdb_port_args   *args = u_arg;
    l2sw_t                      *l2sw = args->sw;

    if (fdb->lrn_port != args->port) {
        return 0;
    }

    l2sw_mod_flow(l2sw, fdb, false, L2SW_UNK_BUFFER_ID);
    return 1;
}
#endif

static int
l2sw_alloc(void **priv)
{
    l2sw_t **l2sw = (l2sw_t **)priv;

    *l2sw = calloc(1, sizeof(l2sw_t)); 
    assert(*l2sw);
    return 0;
}

static void 
l2sw_free(void *priv)
{
    free(priv);
}

static void 
l2sw_add(mul_switch_t *sw)
{
    l2sw_t      *l2sw = MUL_PRIV_SWITCH(sw);

    c_rw_lock_init(&l2sw->lock);
    l2sw->swid = sw->dpid;
    l2sw->l2fdb_htbl = g_hash_table_new_full(l2fdb_key,
                                             l2fdb_equal,
                                             NULL,
                                             l2_fdb_ent_free);
    assert(l2sw->l2fdb_htbl);

    l2sw->l2mfdb_htbl = g_hash_table_new_full(g_int_hash,
                                              g_int_equal,
                                              NULL,
                                              l2_mfdb_ent_free);
    assert(l2sw->l2mfdb_htbl);


#ifndef CONFIG_L2SW_FDB_CACHE
    /* Let controller handle exception forwarding */
    l2sw_set_fp_ops(l2sw);
#endif

    /* Add flood flows for this switch eg Brdcast, mcast etc */
    l2sw_install_dfl_flows(sw->dpid);

    c_log_debug("L2 Switch 0x%llx added", (unsigned long long)(sw->dpid));
}

static void
l2sw_install_dfl_flows(uint64_t dpid)
{
    struct flow                 fl;
    struct flow                 mask;
    struct mul_act_mdata mdata;  
    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);

    /* Clear all entries for this switch */
    /*mul_app_send_flow_del(L2SW_APP_NAME, NULL, dpid, &fl,
                          &mask, 0, 0, C_FL_ENT_NOCACHE, OFPG_ANY);*/

    /* Zero DST MAC Drop */
    of_mask_set_dl_dst(&mask); 
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, &mask,
                          L2SW_UNK_BUFFER_ID, NULL, 0, 0, 0, 
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    /* Zero SRC MAC Drop */
    of_mask_set_dc_all(&mask);
    of_mask_set_dl_src(&mask); 
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, &mask, 
                          L2SW_UNK_BUFFER_ID, NULL, 0, 0, 0,  
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    /* Broadcast SRC MAC Drop */
    memset(&fl.dl_src, 0xff, OFP_ETH_ALEN);
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, &mask,
                          L2SW_UNK_BUFFER_ID, NULL, 0, 0, 0,
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);


    /* Send any unknown flow to app */
    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, &mask,
                          L2SW_UNK_BUFFER_ID, NULL, 0, 0, 0, C_FL_PRIO_LDFL, 
                          C_FL_ENT_LOCAL);
    
    /* Default flow to be added in switch so that switch sends all 
     * IGMP packets to Controller */
    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    of_mask_set_dl_type(&mask);
    of_mask_set_nw_proto(&mask);
    fl.dl_type = htons(ETH_TYPE_IP);
    fl.nw_proto = IP_TYPE_IGMP;

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, dpid);
    mul_app_action_output(&mdata, 0);
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, 
                          &mask, 0xffffffff,
                          mdata.act_base, mul_app_act_len(&mdata),
                          0, 0,
                          C_FL_PRIO_EXM,
                          C_FL_ENT_GSTATS | C_FL_ENT_CTRL_LOCAL);

    mul_app_act_free(&mdata);
}

static void
l2sw_del(mul_switch_t *sw)
{
    l2sw_t *l2sw = MUL_PRIV_SWITCH(sw);
 
    c_wr_lock(&l2sw->lock);
    if (l2sw->l2fdb_htbl) g_hash_table_destroy(l2sw->l2fdb_htbl);
    l2sw->l2fdb_htbl = NULL;
    c_wr_unlock(&l2sw->lock);
    c_log_debug("L2 Switch 0x%llx removed", (unsigned long long)(sw->dpid));
}


int 
l2sw_mod_flow(l2sw_t *l2sw, l2fdb_ent_t *fdb, 
              bool add, uint32_t buffer_id)
{
    struct mul_act_mdata mdata;  
    struct flow          fl; 
    struct flow          mask;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    of_mask_set_dl_dst(&mask);
    memcpy(&fl.dl_dst, fdb->mac_da, OFP_ETH_ALEN);

    if (add) { 
        mul_app_act_alloc(&mdata);
        mul_app_act_set_ctors(&mdata, l2sw->swid);
        mul_app_action_output(&mdata, fdb->lrn_port) ;
        mul_app_send_flow_add(L2SW_APP_NAME, NULL, l2sw->swid, &fl, 
                              &mask, buffer_id,
                              mdata.act_base, mul_app_act_len(&mdata),
                              L2FDB_ITIMEO_DFL, L2FDB_HTIMEO_DFL,
                              C_FL_PRIO_DFL, C_FL_ENT_NOCACHE);
        mul_app_act_free(&mdata);
    } else {
        mul_app_send_flow_del(L2SW_APP_NAME, NULL, l2sw->swid, &fl,
                              &mask, 0, C_FL_PRIO_DFL,
                              C_FL_ENT_NOCACHE, OFPG_ANY);
    }

    return 0;
}

static void
__l2sw_mod_mflow_add_oport(void *mport_arg,
                           void *mdata_arg)
{
    const l2mcast_port_t *mport = mport_arg;
    struct mul_act_mdata *mdata = mdata_arg;

    mul_app_action_output(mdata, mport->port); 
}

static int 
__l2sw_mod_mflow(l2sw_t *l2sw, l2mfdb_ent_t *mfdb,  bool add)
{
    struct mul_act_mdata mdata;  
    struct flow          fl; 
    struct flow          mask;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    of_mask_set_nw_dst(&mask, 32);
    of_mask_set_dl_type(&mask);
    fl.ip.nw_dst = htonl(mfdb->group);
    fl.dl_type = htons(ETH_TYPE_IP);

    if (add) {
        assert(mfdb->port_list);
        mul_app_act_alloc(&mdata);
        mul_app_act_set_ctors(&mdata, l2sw->swid);
        g_slist_foreach(mfdb->port_list, __l2sw_mod_mflow_add_oport, &mdata);
        mul_app_send_flow_add(L2SW_APP_NAME, NULL, l2sw->swid, &fl, 
                              &mask, 0xffffffff,
                              mdata.act_base, mul_app_act_len(&mdata),
                              0, 0,
                              C_FL_PRIO_DFL, C_FL_ENT_NOCACHE); 
        mul_app_act_free(&mdata);
    } else {
        mul_app_send_flow_del(L2SW_APP_NAME, NULL, l2sw->swid, &fl,
                              &mask, OFPP_NONE, C_FL_PRIO_DFL,
                              C_FL_ENT_NOCACHE, OFPG_ANY);
    }

    return 0;
}

static int 
__l2sw_mod_umflow(l2sw_t *l2sw, struct flow *in_fl, uint32_t port)
{
    struct mul_act_mdata mdata;  
    struct flow fl; 
    struct flow mask;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);
    of_mask_set_dl_dst(&mask);
    of_mask_set_in_port(&mask);
    memcpy(fl.dl_dst, in_fl->dl_dst, OFP_ETH_ALEN);
    fl.in_port = htonl(port);

    mul_app_act_alloc(&mdata);
    mul_app_act_set_ctors(&mdata, l2sw->swid);
    mul_app_action_output(&mdata, OF_ALL_PORTS);
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, l2sw->swid, &fl, 
                          &mask, 0xffffffff,
                          mdata.act_base, mul_app_act_len(&mdata),
                          L2MFDB_ITIMEO_DFL, L2MFDB_HTIMEO_DFL,
                          C_FL_PRIO_DFL, C_FL_ENT_NOCACHE);
    mul_app_act_free(&mdata);

    return 0;
}

static int
l2sw_port_in_mfdb(void *mp_arg, void *u_arg)
{
    uint32_t port = *(uint32_t *)(u_arg);
    l2mcast_port_t *mport = mp_arg;

    if (port == mport->port) return 0;
    return -1;
}

static l2mcast_port_t *
mport_alloc(uint32_t port)
{
    l2mcast_port_t *mport= NULL;

    mport = calloc(1, sizeof(*mport));
    if (!mport) {
        return NULL;
    }

    mport->port = port;
    mport->installed = time(NULL);
    return mport;
}

static l2mfdb_ent_t *
mfdb_alloc(uint32_t group, uint64_t dpid)
{
    l2mfdb_ent_t *mfdb = NULL;

    mfdb = calloc(1, sizeof(*mfdb));
    if (!mfdb) {
        return NULL;
    }

    mfdb->group = group;
    mfdb->dpid = dpid;
    return mfdb;
}

static void 
l2sw_add_mcast_group(uint32_t group, l2sw_t *sw, uint32_t inport)
{
    l2mfdb_ent_t *mfdb;
    l2mcast_port_t  *mport= NULL;
    
    c_wr_lock(&sw->lock);

    if ((mfdb = g_hash_table_lookup(sw->l2mfdb_htbl, &group))) {
        if (g_slist_find_custom(mfdb->port_list, &inport,
                                (GCompareFunc)l2sw_port_in_mfdb)) {
            c_log_err("%s: DP (0x%llx) Port (%lu) already in group (0x%x)",
                      FN, U642ULL(sw->swid), U322UL(inport), group);
            goto out;
        }

        mport = mport_alloc(inport);
        if (!mport) goto out;

        mfdb->port_list = g_slist_append(mfdb->port_list, mport);

        __l2sw_mod_mflow(sw, mfdb, false); /* Del for modify */
        __l2sw_mod_mflow(sw, mfdb, true); /* Add */
    } else {
        mfdb = mfdb_alloc(group, sw->swid); 
        if (!mfdb) goto out;

        mport = mport_alloc(inport);
        if (!mport) {
            free(mfdb);
            goto out;
        }

        mfdb->port_list = g_slist_append(mfdb->port_list, mport);
        __l2sw_mod_mflow(sw, mfdb, true); /* Add */

        /*Insert mfdb in hash table*/
        g_hash_table_insert(sw->l2mfdb_htbl, &mfdb->group, mfdb);

    }
    
out:
    c_wr_unlock(&sw->lock);

    return;
}

static void 
l2sw_del_mcast_group(uint32_t group, l2sw_t *sw, uint32_t inport)
{
    l2mfdb_ent_t *mfdb;
    GSList *elem = NULL;

    c_wr_lock(&sw->lock);
    if ((mfdb = g_hash_table_lookup(sw->l2mfdb_htbl, &group))) {
        if (!(elem = g_slist_find_custom(mfdb->port_list, &inport, 
                                         (GCompareFunc)l2sw_port_in_mfdb))) {
            c_log_err("%s: DP (0x%llx) Port (%lu) has no group (0x%x)",
                      FN, U642ULL(sw->swid), U322UL(inport), group);
            goto out;
        }

        mfdb->port_list = g_slist_remove(mfdb->port_list, elem->data);

        __l2sw_mod_mflow(sw, mfdb, false); /* Del for modify */

        if (g_slist_length(mfdb->port_list))
            __l2sw_mod_mflow(sw, mfdb, true); /* Add */
        else {
            g_hash_table_remove(sw->l2mfdb_htbl, &group);
        }
    }
    else {
        c_log_err("%s: No Records were found for sw (0x%llx) Group (0x%x) and"
				" port (%u)",FN, U642ULL(sw->swid), group, inport);
    }
out:
    c_wr_unlock(&sw->lock);

    return;
}

static int
__l2sw_mfdb_traverse_all(l2sw_t *l2sw, GHFunc iter_fn, void *arg) 
{
    if (l2sw->l2mfdb_htbl) {
        g_hash_table_foreach(l2sw->l2mfdb_htbl,
                             (GHFunc)iter_fn, arg);
    }

    return 0;
}


static void
l2sw_mcast_learn_and_fwd(l2sw_t *sw, struct flow *fl, uint32_t inport,
                         uint32_t buffer_id, uint8_t *raw, size_t pkt_len)
{
    uint8_t  grec_type = 0, grec_auxwords = 0;
    uint16_t ngrec = 0, grp_counter = 0,grec_nsrcs = 0;
    uint32_t group;
    struct igmphdr *igmp_hdr;
    struct ip_header *ip;
    size_t ip_len;
    size_t grp_len = 0;
    size_t rem_pkt_len = pkt_len;
    struct of_pkt_out_params parms;
    struct mul_act_mdata mdata;  
    struct igmpv3_report *igmpv3_rep = NULL;
    struct igmpv3_grec   *grp_rec    = NULL;

    if (fl->dl_type == htons(ETH_TYPE_LLDP)) {
        return;
    }

    if (fl->nw_proto != IP_TYPE_IGMP) {
        goto add_mcast;
    }

    ip = INC_PTR8(raw, sizeof(struct eth_header) + 
                      (fl->dl_vlan ? VLAN_HEADER_LEN : 0));

    ip_len = ((ip->ip_ihl_ver & 0x0f) *4); 
    if (rem_pkt_len < ip_len + sizeof(*igmp_hdr)) {
        c_log_err("%s: Something wrong with IGMP packet", FN);
        return; /* Something wrong with IGMP packet */
    }

    igmp_hdr = INC_PTR8(ip, ((ip->ip_ihl_ver & 0x0f) *4));
    switch (igmp_hdr->type) {
    case IGMPV2_HOST_MEMBERSHIP_REPORT:
		
		/*Remaining packet length*/
    	rem_pkt_len -= ip_len + sizeof(*igmp_hdr);

		/*Getting the MCAST group*/
        group = ntohl(igmp_hdr->group);
		
		/*Adding mcast group in MFDB*/
        l2sw_add_mcast_group(group, sw, inport);
        goto fwd_pkt;
    
	case IGMP_HOST_LEAVE_MESSAGE: 
		
		/*Remaining packet length*/
    	rem_pkt_len -= ip_len + sizeof(*igmp_hdr);
        
		/*Getting the MCAST group*/
		group = ntohl(igmp_hdr->group);
        
		/*Deleting mcast group from MFDB*/
		l2sw_del_mcast_group(group, sw, inport);
        goto fwd_pkt;
    case IGMPV3_HOST_MEMBERSHIP_REPORT:
		igmpv3_rep = (void*)igmp_hdr;
		
		/*Getting the number of MCAST grp records*/
		ngrec = ntohs(igmpv3_rep->ngrec);

		grp_rec = igmpv3_rep->grec;
		rem_pkt_len -= (ip_len + sizeof(struct igmpv3_report));
		while(grp_counter < ngrec) {

			grec_type = grp_rec->grec_type;

			/*Getting the number of Src IPs*/
			grec_nsrcs = ntohs(grp_rec->grec_nsrcs);
			grec_auxwords = grp_rec->grec_auxwords;
			/*Calculating grp length*/
			grp_len = sizeof(struct igmpv3_grec) +  
					 (sizeof(uint32_t) * grec_nsrcs) + /*sizeof(srcip) * nsrc*/
					 (sizeof(uint32_t) * grec_auxwords); /*Total Aux data*/

			if (rem_pkt_len < grp_len) {
				c_log_err("%s: Something wrong with the IGMPv3 report header", FN);
				return; /* Something wrong with IGMP packet */
			}
			
			switch(grec_type) {
				case IGMPV3_MODE_IS_INCLUDE:
					/*Getting the MCAST grp*/
					group = ntohl(grp_rec->grec_mca);
					l2sw_add_mcast_group(group, sw, inport);
					break;

				case IGMPV3_BLOCK_OLD_SOURCES:
					/*Getting the MCAST grp*/
					group = ntohl(grp_rec->grec_mca);
					l2sw_del_mcast_group(group, sw, inport);
					break;
				default:
					c_log_err("IGMP Group Mode (%u) not supported",grec_type);
					break;

			}

			
			/*Remaining packet length*/
    		rem_pkt_len -= grp_len;

			/*Jump to next grp record*/
			grp_rec = INC_PTR8(grp_rec, grp_len);

			/*Increment the grp counter*/
			++grp_counter;
		}

		goto fwd_pkt;
	default:
		c_log_err("%s: Something wrong with IGMP packet - Wrong Message type", FN);
		goto fwd_pkt;
		} 

add_mcast:
    __l2sw_mod_umflow(sw, fl, inport); 

fwd_pkt:

    if (buffer_id != L2SW_UNK_BUFFER_ID) {
        pkt_len = 0;
    }

    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    mul_app_act_set_ctors(&mdata, sw->swid);
    mul_app_action_output(&mdata, OF_ALL_PORTS);
    parms.buffer_id = buffer_id;
    parms.in_port = inport;
    parms.action_list = mdata.act_base;
    parms.action_len = mul_app_act_len(&mdata);
    parms.data_len = pkt_len;
    parms.data = raw;
    mul_app_send_pkt_out(NULL, sw->swid, &parms);
    mul_app_act_free(&mdata);

    return;
}

static void 
l2sw_learn_and_fwd(mul_switch_t *sw, struct flow *fl, uint32_t inport,
                   uint32_t buffer_id, uint8_t *raw, size_t pkt_len)
{
    l2sw_t                      *l2sw = MUL_PRIV_SWITCH(sw);
#ifdef CONFIG_L2SW_FDB_CACHE
    l2fdb_ent_t                 *fdb;
#endif
    uint32_t                    oport = OF_ALL_PORTS;
    struct of_pkt_out_params    parms;
    struct mul_act_mdata mdata;  

    memset(&parms, 0, sizeof(parms));

    /* Check packet validity */
    if (is_zero_ether_addr(fl->dl_src) || 
        is_zero_ether_addr(fl->dl_dst) ||
        is_multicast_ether_addr(fl->dl_src) || 
        is_broadcast_ether_addr(fl->dl_src)) {
        //c_log_err("%s: Invalid src/dst mac addr", FN);
        return;
    }
    
    if (is_multicast_ether_addr(fl->dl_dst)) {
        return l2sw_mcast_learn_and_fwd(l2sw, fl, inport,
                                        buffer_id, raw, pkt_len); 
    }

#ifdef CONFIG_L2SW_FDB_CACHE
    c_wr_lock(&l2sw->lock);
    fdb = g_hash_table_lookup(l2sw->l2fdb_htbl, fl->dl_src);
    if (fdb) { 
        /* Station moved ? */
        if (ntohl(fl->in_port) != fdb->lrn_port) {
            l2sw_mod_flow(l2sw, fdb, false, (uint32_t)(-1));
            fdb->lrn_port = ntohl(fl->in_port); 
            l2sw_mod_flow(l2sw, fdb, true, (uint32_t)(-1));
        }  

        goto l2_fwd;
    }
    fdb = malloc(sizeof(*fdb));
    memcpy(fdb->mac_da, fl->dl_src, OFP_ETH_ALEN);
    fdb->lrn_port = ntohl(fl->in_port);
    g_hash_table_insert(l2sw->l2fdb_htbl, fdb->mac_da, fdb);

l2_fwd:

    fdb = g_hash_table_lookup(l2sw->l2fdb_htbl, fl->dl_dst);
    if (fdb) { 
        oport = fdb->lrn_port;
        l2sw_mod_flow(l2sw, fdb, true, L2SW_UNK_BUFFER_ID);
    } 
    c_wr_unlock(&l2sw->lock);
#endif

    if (buffer_id != L2SW_UNK_BUFFER_ID) {
        pkt_len = 0;
    }

    mul_app_act_alloc(&mdata);
    mdata.only_acts = true;
    mul_app_act_set_ctors(&mdata, l2sw->swid);
    mul_app_action_output(&mdata, oport);
    parms.buffer_id = buffer_id;
    parms.in_port = inport;
    parms.action_list = mdata.act_base;
    parms.action_len = mul_app_act_len(&mdata);
    parms.data_len = pkt_len;
    parms.data = raw;
    mul_app_send_pkt_out(NULL, l2sw->swid, &parms);
    mul_app_act_free(&mdata);

    return;
}

#ifdef CONFIG_L2SW_FDB_CACHE
static int
__l2sw_fdb_traverse_all(l2sw_t *l2sw, GHFunc iter_fn, void *arg) 
{
    if (l2sw->l2fdb_htbl) {
        g_hash_table_foreach(l2sw->l2fdb_htbl,
                             (GHFunc)iter_fn, arg);
    }

    return 0;
}

static int 
__l2sw_fdb_del_all_with_inport(l2sw_t *l2sw, uint16_t in_port) 
{
    c_ofp_flow_mod_t            *cofp_fm;
    uint32_t                    wildcards = OFPFW_ALL;
    struct cbuf                 *b;

    b = of_prep_msg(sizeof(*cofp_fm), C_OFPT_FLOW_MOD, 0);

    cofp_fm = (void *)(b->data);
    cofp_fm->datapath_id = htonll(l2sw->swid);
    cofp_fm->command = C_OFPC_DEL;
    cofp_fm->flags = C_FL_ENT_NOCACHE;
    cofp_fm->wildcards = htonl(wildcards);
    cofp_fm->itimeo = htons(L2FDB_ITIMEO_DFL);
    cofp_fm->htimeo = htons(L2FDB_HTIMEO_DFL);
    cofp_fm->buffer_id = (uint32_t)(-1);
    cofp_fm->oport = htons(in_port);

    return mul_app_command_handler(L2SW_APP_NAME, b);
}
#endif

static void
l2sw_core_closed(void)
{
    c_log_info("%s: ", FN);
    return;
}

static void
l2sw_core_reconn(void)
{
    c_log_info("%s: ", FN);
    mul_register_app_cb(NULL, L2SW_APP_NAME,
                        C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &l2sw_app_cbs);
}

struct mul_app_client_cb l2sw_app_cbs = {
    .switch_priv_alloc = l2sw_alloc,
    .switch_priv_free = l2sw_free,
    .switch_add_cb =  l2sw_add,
    .switch_del_cb = l2sw_del,
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = NULL,
    .switch_port_del_cb = NULL,
    .switch_port_link_chg = NULL,
    .switch_port_adm_chg = NULL,
    .switch_packet_in = l2sw_learn_and_fwd,
    .core_conn_closed = l2sw_core_closed,
    .core_conn_reconn = l2sw_core_reconn 
};  

/* Housekeep Timer for app monitoring */
static void
l2sw_main_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                void *arg UNUSED)
{
    struct timeval tv    = { 1 , 0 };
    evtimer_add(l2sw_timer_event, &tv);
}  

void
l2sw_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval    tv = { 1, 0 };

    c_log_debug("%s", FN);

    l2sw_timer_event = evtimer_new(base, l2sw_main_timer, NULL); 
    evtimer_add(l2sw_timer_event, &tv);

    mul_register_app_cb(NULL, L2SW_APP_NAME, 
                        C_APP_ALL_SW, C_APP_ALL_EVENTS,
                        0, NULL, &l2sw_app_cbs);

    return;
}

#ifdef MUL_APP_VTY
#ifdef CONFIG_L2SW_FDB_CACHE
static void
show_l2sw_fdb_info(void *key UNUSED, void *fdb_arg, void *uarg)
{
    l2fdb_ent_t *fdb = fdb_arg;
    struct vty  *vty = uarg;

    vty_out(vty, "%02x:%02x:%02x:%02x:%02x:%02x %5hu%s", 
            fdb->mac_da[0], fdb->mac_da[1], fdb->mac_da[2],
            fdb->mac_da[3], fdb->mac_da[4], fdb->mac_da[5],
            fdb->lrn_port, VTY_NEWLINE);
}

DEFUN (show_l2sw_fdb,
       show_l2sw_fdb_cmd,
       "show l2-switch X fdb",
       SHOW_STR
       "L2 switches\n"
       "Datapath-id in 0xXXX format\n"
       "Learned Forwarding database\n")
{
    uint64_t        swid;
    mul_switch_t    *sw;
    l2sw_t          *l2sw;

    swid = strtoull(argv[0], NULL, 16);

    sw = c_app_switch_get_with_id(swid);
    if (!sw) {
        vty_out(vty, "No such switch 0x%llx\r\n", U642ULL(swid));
        return CMD_SUCCESS;
    }

    l2sw = MUL_PRIV_SWITCH(sw);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    vty_out (vty, "%8s %18s%s", "mac", "lrn_port", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    c_rd_lock(&l2sw->lock);
    __l2sw_fdb_traverse_all(l2sw, show_l2sw_fdb_info, vty);
    c_rd_unlock(&l2sw->lock);

    c_app_switch_put(sw);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}
#endif

static void
show_l2sw_mfdb_port_info(void *port_arg, void *u_arg)
{
    struct vty *vty = u_arg;
    l2mcast_port_t *mport = port_arg;

    vty_out(vty, "0x%x(%us)", mport->port, (unsigned int)mport->installed);
}

static void
show_l2sw_mfdb_info(void *key UNUSED, void *fdb_arg, void *uarg)
{
    l2mfdb_ent_t *mfdb = fdb_arg;
    struct vty  *vty = uarg;

    vty_out(vty, "0x%08x : ", mfdb->group);
    if (mfdb->port_list) {
        g_slist_foreach(mfdb->port_list, show_l2sw_mfdb_port_info, vty);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
}

DEFUN (show_l2sw_mfdb,
       show_l2sw_mfdb_cmd,
       "show l2-switch X mfdb",
       SHOW_STR
       "L2 switches\n"
       "Datapath-id in 0xXXX format\n"
       "Learned Multicast Forwarding database\n")
{
    uint64_t        swid;
    mul_switch_t    *sw;
    l2sw_t          *l2sw;

    swid = strtoull(argv[0], NULL, 16);

    sw = c_app_switch_get_with_id(swid);
    if (!sw) {
        vty_out(vty, "No such switch 0x%llx\r\n", U642ULL(swid));
        return CMD_SUCCESS;
    }

    l2sw = MUL_PRIV_SWITCH(sw);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    vty_out (vty, "%8s %18s%s", "groups", "ports", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    c_rd_lock(&l2sw->lock);
    __l2sw_mfdb_traverse_all(l2sw, show_l2sw_mfdb_info, vty);
    c_rd_unlock(&l2sw->lock);

    c_app_switch_put(sw);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

void
l2sw_module_vty_init(void *arg UNUSED)
{
    c_log_debug("%s:", FN);
#ifdef CONFIG_L2SW_FDB_CACHE
    install_element(ENABLE_NODE, &show_l2sw_fdb_cmd);
#endif
    install_element(ENABLE_NODE, &show_l2sw_mfdb_cmd);
}

module_vty_init(l2sw_module_vty_init);
#endif

module_init(l2sw_module_init);
