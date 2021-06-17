/*
 * mul_of_msg.h: MUL openflow message handling 
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
#ifndef __MUL_OF_MSG_H__
#define __MUL_OF_MSG_H__

#define OF_DUMP_INST_SZ 4096
#define OF_DUMP_ACT_SZ 4096
#define OF_DUMP_WC_SZ 4096
#define FL_PBUF_SZ 4096
#define OF_DUMP_METER_FEAT_SZ 1024
#define OF_DUMP_PORT_STATS_SZ 1024
#define OF_DUMP_GRP_FEAT_SZ 4096 
#define OF_DUMP_TBL_FEAT_SZ 8192 
#define OF_DUMP_MSG_SZ 4096
#define OF_DUMP_PORT_DESC_SZ 1024

#define OF_MAX_MISS_SEND_LEN (1518)

#define OF_MAX_FLOW_MOD_BUF_SZ (4096) 
#define OF_ALL_TABLES (0xff) 

#define OF_NO_PORT (0) 
#define OF_SEND_IN_PORT (OFPP131_IN_PORT)
#define OF_ALL_PORTS (OFPP131_ALL)
#define OF_MAX_LOG_PORTS (OFPP131_MAX)
#define OF_ANY_PORT (OFPP131_ANY)

#define OF_FL_TBL_FEAT_INSTRUCTIONS 0
#define OF_FL_TBL_FEAT_INSTRUCTIONS_MISS 1
#define OF_FL_TBL_FEAT_ACTIONS 2
#define OF_FL_TBL_FEAT_ACTIONS_MISS 3
#define OF_FL_TBL_FEAT_NTABLE 4
#define OF_FL_TBL_FEAT_NTABLE_MISS 5
#define OF_FL_TBL_FEAT_WR_ACT 6
#define OF_FL_TBL_FEAT_WR_ACT_MISS 7
#define OF_FL_TBL_FEAT_APP_ACT 8
#define OF_FL_TBL_FEAT_APP_ACT_MISS 9
#define OF_FL_TBL_FEAT_WR_SETF  10
#define OF_FL_TBL_FEAT_WR_SETF_MISS 11
#define OF_FL_TBL_FEAT_APP_SETF 12
#define OF_FL_TBL_FEAT_APP_SETF_MISS 13

struct of_flow_tbl_props
{
    char name[OFP_MAX_TABLE_NAME_LEN];
    uint64_t metadata_match;
    uint64_t metadata_write;
    uint32_t config;
    uint32_t max_entries;
    uint32_t bm_inst;
    uint32_t bm_inst_miss;
    uint32_t bm_wr_actions;
    uint32_t bm_wr_actions_miss;
    uint32_t bm_app_actions;
    uint32_t bm_app_actions_miss;
#define OF_MAX_TABLE_BMASK_SZ (8)
    uint32_t bm_next_tables[OF_MAX_TABLE_BMASK_SZ];
    uint32_t bm_next_tables_miss[OF_MAX_TABLE_BMASK_SZ];
#define OF_MAX_SET_FIELD_BMASK_SZ (2)
    uint32_t bm_wr_set_field[OF_MAX_SET_FIELD_BMASK_SZ];
    uint32_t bm_wr_set_field_miss[OF_MAX_SET_FIELD_BMASK_SZ];
    uint32_t bm_app_set_field[OF_MAX_SET_FIELD_BMASK_SZ];
    uint32_t bm_app_set_field_miss[OF_MAX_SET_FIELD_BMASK_SZ];
};
typedef struct of_flow_tbl_props of_flow_tbl_props_t;

struct ofp_act_parsers {
    int (*act_output)(struct ofp_action_header *act, void *arg);
    int (*act_push)(struct ofp_action_header *act, void *arg);
    int (*act_pop_vlan)(struct ofp_action_header *act, void *arg);
    int (*act_pop_mpls)(struct ofp_action_header *act, void *arg);
    int (*act_set_mpls_ttl)(struct ofp_action_header *act, void *arg);
    int (*act_dec_mpls_ttl)(struct ofp_action_header *act, void *arg);
    int (*act_pop_pbb)(struct ofp_action_header *act, void *arg);
    int (*act_set_queue)(struct ofp_action_header *act, void *arg);
    int (*act_set_grp)(struct ofp_action_header *act, void *arg);
    int (*act_set_nw_ttl)(struct ofp_action_header *act, void *arg);
    int (*act_dec_nw_ttl)(struct ofp_action_header *act, void *arg);
    int (*act_set_vlan)(struct ofp_action_header *act, void *arg);     // OF1.0 Excl
    int (*act_set_vlan_pcp)(struct ofp_action_header *act, void *arg); // OF1.0 Excl
    int (*act_set_dl_dst)(struct ofp_action_header *act, void *arg);   // OF1.0 Excl
    int (*act_set_dl_src)(struct ofp_action_header *act, void *arg);   // OF1.0 Excl
    int (*act_set_nw_src)(struct ofp_action_header *act, void *arg);   // OF1.0 Excl
    int (*act_set_nw_dst)(struct ofp_action_header *act, void *arg);   // OF1.0 Excl
    int (*act_set_nw_tos)(struct ofp_action_header *act, void *arg);   // OF1.0 Excl
    int (*act_set_field)(struct ofp_action_header *act, void *arg);
    int (*act_setf_in_port)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_dst)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_src)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_type)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_vlan)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_dl_vlan_pcp)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_mpls_label)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_mpls_tc)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_mpls_bos)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_ipv4_src)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_ipv4_dst)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_ipv6_src)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_ipv6_dst)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_ipv4_dscp)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_tcp_src)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_tcp_dst)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_udp_dst)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_udp_src)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_setf_tunnel)(struct ofp_oxm_header *oxm, void *arg);
    int (*act_cp_ttl_out)(struct ofp_action_header *act, void *arg);
    int (*act_cp_ttl_in)(struct ofp_action_header *act, void *arg);
    int (*act_exp)(struct ofp_action_header *act, void *arg);
};

struct ofp_inst_parsers {
    void *(*prep_inst_parser)(struct flow *fl, struct flow *mask,
                              void *arg, struct ofp_inst_parsers *parsers,
                              struct ofp_act_parsers *act_parsers);
    void (*pre_proc)(void *arg);
    void (*post_proc)(void *arg);
    void (*no_inst)(void *arg);
    int (*goto_inst)(struct ofp_instruction *inst, void *arg);
    int (*wr_meta_inst)(struct ofp_instruction *inst, void *arg);
    int (*wr_act_inst)(struct ofp_instruction *inst, void *arg);
    int (*apply_act_inst)(struct ofp_instruction *inst, void *arg);
    int (*clear_act_inst)(struct ofp_instruction *inst, void *arg);
    int (*meter_inst)(struct ofp_instruction *inst, void *arg);
    int (*exp_inst)(struct ofp_instruction *inst, void *arg);
    struct ofp_inst_parser_arg *(*fini_inst_parser)(void *arg);
};

struct ofp_inst_parser_arg
{
    struct flow *fl;
    struct flow *mask;
    int res;
    char *pbuf;
    size_t len;
    void *u_arg;
    bool act_set;
    bool inst_wr;
    bool inst_app;
    bool inst_goto;
    bool inst_meter;
    bool inst_clear;
    bool inst_wr_meta;
    bool mod_fl_flag;
    int push_mpls;
    int push_vlan;
    int push_pbb;
    struct ofp_inst_parsers *parsers;
    struct ofp_act_parsers *act_parsers;
};

struct ofp_inst_check_args
{
    struct flow *fl;
    void *sw_ctx;
    bool group_act_check;
    void *tbl_prop;
    void *grp_prop;
    bool check_setf_supp;
    bool inst_local;
    void *grp_list;
    void *meter_list;
    uint32_t out_port;
    uint32_t group_id;
    bool (*check_port)(void *sw_arg, uint32_t port);
    bool (*check_add_meter)(void *sw_arg, uint32_t group, void *u_arg);
    bool (*check_add_group)(void *sw_arg, uint32_t meter, void *u_arg);
    uint8_t (*get_v2p_tbl)(void *sw_arg, uint8_t tbl);
};

struct ofpx_oxm_parser_arg
{
    struct flow *flow;
    struct flow *mask;
};

struct of_act_vec_elem
{
    uint16_t weight;
    uint32_t ff_port;
    uint32_t ff_group;
    void *actions;
    size_t action_len;
};

struct of_meter_band_elem
{
    void *band;
    size_t band_len;
};

struct of_meter_band_parms
{
    uint32_t rate;
    uint32_t burst_size;
    uint32_t prec_level;
};

struct mul_act_mdata
{
    uint8_t *act_base;
    uint8_t *act_wr_ptr;
    uint8_t *act_inst_wr_ptr;
    uint8_t *act_inst_app_ptr;
    uint8_t n_wracts;
    uint8_t n_appacts;
    uint8_t n_clracts;
#define MUL_ACT_BUF_SZ (4096)
    size_t  buf_len;
    bool only_acts;
    uint16_t act_inst_type;
    uint32_t inst_bm;
    uint32_t act_bm;
    uint32_t setf_bm[OF_MAX_SET_FIELD_BMASK_SZ];
    void *ofp_ctors;
};
typedef struct mul_act_mdata mul_act_mdata_t;

static void inline
of_mact_mdata_reset(mul_act_mdata_t *mdata)
{
    mdata->act_wr_ptr = mdata->act_base;
    mdata->act_inst_wr_ptr = NULL;
    mdata->act_inst_app_ptr = NULL;
    mdata->n_wracts = 0;
    mdata->n_appacts = 0;
    mdata->n_clracts = 0;
    mdata->only_acts = 0;
    mdata->act_inst_type = 0;
    mdata->ofp_ctors = NULL;
    mdata->act_bm = 0;
    mdata->inst_bm = 0;
    memset(mdata->setf_bm, 0, sizeof(mdata->setf_bm));
}

static void inline
of_mact_mdata_init(mul_act_mdata_t *mdata, size_t len)
{
    of_mact_mdata_reset(mdata);
    mdata->buf_len = len;
}

static void inline
of_mact_mdata_reset_act_wr_inst(mul_act_mdata_t *mdata)
{
    mdata->act_inst_wr_ptr = NULL;
}

static inline size_t
of_mact_buf_room(mul_act_mdata_t *mdata)
{
    size_t len;

    assert(mdata->act_base <= mdata->act_wr_ptr);
    len = (size_t)(mdata->act_wr_ptr - mdata->act_base);
    return (len > mdata->buf_len ? 0 : mdata->buf_len - len);
}

static inline size_t
of_mact_len(mul_act_mdata_t *mdata)
{
    assert(mdata->act_base <= mdata->act_wr_ptr);
    return (size_t)(mdata->act_wr_ptr - mdata->act_base);
}

static inline size_t
of_mact_inst_act_len(mul_act_mdata_t *mdata)
{
    uint8_t *inst_ptr = NULL;
    if (mdata->act_inst_type == OFPIT_WRITE_ACTIONS) {
        inst_ptr = mdata->act_inst_wr_ptr;
    } else if (mdata->act_inst_type == OFPIT_APPLY_ACTIONS) {
        inst_ptr = mdata->act_inst_app_ptr;
    }

    assert(inst_ptr <= mdata->act_wr_ptr);
    return (size_t)(mdata->act_wr_ptr - inst_ptr);
}

static inline bool
of_mask_is_dc_all(struct flow *mask)
{
    struct flow m;
    memset(&m, 0, sizeof(m));
    return !memcmp(mask, &m, sizeof(*mask));
}

static inline void
of_mask_set_dc_all(struct flow *mask)
{
    memset(mask, 0, sizeof(*mask));
}

static inline void
of_mask_set_no_dc(struct flow *mask)
{
    size_t len = sizeof(*mask) - sizeof(mask->pad);
    memset(mask, 0xff, len);
}

static inline void
of_mask_set_dl_dst(struct flow *mask)
{
    memset(mask->dl_dst, 0xff, 6);
}

static inline void
of_mask_clr_dl_dst(struct flow *mask)
{
    memset(mask->dl_dst, 0, 6);
}

static inline void
of_mask_set_dl_src(struct flow *mask)
{
    memset(mask->dl_src, 0xff, 6);
}

static inline void
of_mask_set_dl_vlan_pcp(struct flow *mask)
{
    mask->dl_vlan_pcp = 0xff;
}

static inline void
of_mask_set_nw_tos(struct flow *mask)
{
    mask->nw_tos = 0xff;
}

static inline void
of_mask_clr_dl_src(struct flow *mask)
{
    memset(mask->dl_src, 0x0, 6);
}

static inline void
of_mask_set_nw_src(struct flow *mask, size_t prefixlen)
{
    assert(prefixlen <= 32);
    mask->ip.nw_src = htonl(make_inet_mask(prefixlen));
}

static inline void
of_mask_clr_nw_src(struct flow *mask)
{
    mask->ip.nw_src = 0x0;
}

static inline void
of_mask_set_nw_dst(struct flow *mask, size_t prefixlen)
{
    assert(prefixlen <= 32);
    mask->ip.nw_dst = htonl(make_inet_mask(prefixlen));
}
static inline void
of_mask_set_tp_src(struct flow *mask)
{
    mask->tp_src = 0xffff;
}

static inline void
of_mask_set_tp_dst(struct flow *mask)
{
    mask->tp_dst = 0xffff;
}

static inline void
of_mask_clr_nw_dst(struct flow *mask)
{
    mask->ip.nw_dst = 0x0;
}

static inline void
of_mask_set_dl_type(struct flow *mask)
{
    mask->dl_type = 0xffff;
}

static inline void
of_mask_clr_dl_type(struct flow *mask)
{
    mask->dl_type = 0x0;
}

static inline void
of_mask_set_dl_vlan(struct flow *mask)
{
    mask->dl_vlan = 0xffff;
}

static inline void
of_mask_set_dl_vlan_present(struct flow *mask)
{
    mask->dl_vlan = htons(OFPVID_PRESENT);
}

static inline void
of_mask_clr_dl_vlan(struct flow *mask)
{
    mask->dl_vlan = 0x0;
}

static inline bool
of_mask_has_in_port(struct flow *mask)
{
    return mask->in_port ? true: false;
}

static inline void
of_mask_set_in_port(struct flow *mask)
{
    mask->in_port = 0xffffffff;
}

static inline void
of_mask_clr_in_port(struct flow *mask)
{
    mask->in_port = 0x0;
}

static inline void
of_mask_set_nw_proto(struct flow *mask)
{
    mask->nw_proto = 0xff;
}

static inline void
of_mask_clr_nw_proto(struct flow *mask)
{
    mask->nw_proto = 0x0;
}

static inline void
of_mask_set_metadata(struct flow *mask)
{
    mask->metadata = 0xffffffffffffffff;
}

static inline void
of_mask_clr_metadata(struct flow *mask)
{
    mask->metadata = 0x0;
}

static inline void
of_mask_set_tunnel_id(struct flow *mask)
{
    mask->tunnel_id = 0xffffffffffffffff;
}

static inline void
of_mask_clr_tunnel_id(struct flow *mask)
{
    mask->tunnel_id = 0x0;
}

static inline void
of_mask_set_table_id(struct flow *mask)
{
    mask->table_id = 0xff;
}

static inline int 
of_get_data_len(void *h)
{
    return ntohs(((struct ofp_header *)h)->length);
}

static inline bool 
__of_hdr_valid(void *h_arg, int len)
{
    struct ofp_header *h = h_arg;
    return (len <= OFP_MAX_PAYLOAD &&
           (h->version == OFP_VERSION || h->version == OFP_VERSION_131 ||
            h->version == OFP_VERSION_140) && 
            h->type < OFP_MAX_TYPE);
}

static inline void
of_put_mpls_label_oxm(uint8_t *dat, uint32_t label, int sz)
{
    uint8_t *vp = ASSIGN_PTR(&label);

    if (sz == 3) {
        dat[0] = vp[1];
        dat[1] = vp[2];
        dat[2] = vp[3];
    } else {
        *(uint32_t *)(dat) = label;
    }
}

static inline void
of_get_mpls_label_oxm(uint8_t *dat, uint32_t *label, int sz)
{
    uint8_t *vp = ASSIGN_PTR(label);
    if (sz == 3) {
        vp[0] = 0;
        vp[1] = dat[0];
        vp[2] = dat[1];
        vp[3] = dat[2];
    } else {
        *label = *(uint32_t *)(dat);
    }
}

static inline bool 
of_hdr_valid(void *h_arg)
{
    return __of_hdr_valid(h_arg, of_get_data_len(h_arg));
}

struct of_flow_mod_params {
    void *app_owner;
    struct flow *flow;
    struct flow *mask;
    void *actions;
    size_t action_len;
    uint32_t wildcards;
    uint32_t buffer_id;
    uint16_t prio;
    uint16_t itimeo; 
    uint16_t htimeo;
    uint32_t oport;
    uint64_t flags;
    uint8_t reason;
    uint16_t command;
    uint32_t ogroup;
    uint32_t cookie;
    uint32_t seq_cookie;
    void *meter_dep;
    void *grp_dep;
};

struct of_group_mod_params {
    uint8_t command;           /* Command type - add, del or modify */
    void *app_owner;           /* Application owner pointer */
    uint32_t group;            /* Group id */
    uint8_t type;              /* Group type */
    uint8_t flags;             /* Group flags for controller use */
#define OF_MAX_ACT_VECTORS (128)
    struct of_act_vec_elem *act_vectors[OF_MAX_ACT_VECTORS]; /* Vector of actions */
    size_t act_vec_len;        /* Length of action vector */
};

struct of_meter_mod_params {
    uint8_t command;           /* Command type - add, del or modify */  
    void *app_owner;           /* Application owner pointer */
    uint32_t meter;            /* Meter id */
    uint16_t flags;            /* Meter flags as per Openflow */
    uint8_t cflags;            /* Meter flags for controller use */
#define OF_MAX_METER_VECTORS (128)
    struct of_meter_band_elem *meter_bands[OF_MAX_METER_VECTORS]; /* Vector of bands */
    size_t meter_nbands;       /* Valid number of bands */
};

struct ofp_port_mod_properties {
    uint32_t advertise;
    uint32_t configure;
    uint32_t freq_lmda;
    int32_t fl_offset;
    uint32_t grid_span;
    uint32_t tx_pwr;
};

struct of_port_mod_params {
    uint16_t type;
    uint32_t port_no;
    uint32_t config;
    uint32_t mask;
    struct ofp_port_mod_properties properties;
};

struct of_vendor_params {
    uint32_t vendor;
    uint16_t data_len;
    void *data;
};

struct of_async_config_params {
    uint32_t packet_in_mask[2];
    uint32_t port_status_mask[2];
    uint32_t flow_removed_mask[2];
};

struct of_pkt_out_params {
    uint32_t buffer_id;
    uint32_t in_port;
    uint16_t action_len;
    void *action_list;
    void *data;
    uint16_t data_len;
    uint8_t pad[2];
};  

struct c_ofp_ctors {
    struct cbuf *(*hello)(void);
    struct cbuf *(*echo_req)(void);
    struct cbuf *(*echo_rsp)(uint32_t xid);
    struct cbuf *(*set_config)(uint16_t flags, uint16_t miss_len);
    struct cbuf *(*role_request)(uint32_t role, uint64_t gen_id);
    struct cbuf *(*features)(void);
    struct cbuf *(*pkt_out)(struct of_pkt_out_params *parms);
    void (*pkt_out_fast)(void *arg, struct of_pkt_out_params *parms);
    struct cbuf *(*flow_add)(const struct flow *flow,
                             const struct flow *mask,
                             uint32_t buffer_id, void *actions,
                             size_t actions_len, uint16_t i_timeo,
                             uint16_t h_timeo,
                             uint16_t prio,
                             uint64_t cookie,
                             bool mod);
    struct cbuf *(*flow_del)(const struct flow *flow,
                             const struct flow *mask,
                             uint32_t oport, bool strict,
                             uint16_t prio, uint32_t group);
    struct cbuf *(*flow_stat_req)(const struct flow *flow,
                                  const struct flow *mask,
                                  uint32_t oport, uint32_t group);
    struct cbuf *(*group_stat_req)(uint32_t group);
    struct cbuf *(*meter_stat_req)(uint32_t meter);
    struct cbuf *(*meter_stat_cfg_req)(uint32_t meter);
    struct cbuf *(*port_stat_req)(uint32_t port_no);
    struct cbuf *(*port_q_get_conf)(uint32_t port_no);
    struct cbuf *(*port_q_stat_req)(uint32_t port_no, uint32_t queue_id);
    bool (*group_validate)(bool add, uint32_t group, uint8_t type,
                           struct of_act_vec_elem *act_vectors[],
                           size_t act_vec_len);
    struct cbuf *(*group_add)(uint32_t group, uint8_t type,
                              struct of_act_vec_elem *act_vectors[],
                              size_t act_vec_len, bool modify);
    struct cbuf *(*group_del)(uint32_t group);
    struct cbuf *(*tbl_mod)(void);  /* FIXME */
    struct cbuf *(*meter_add)(uint32_t meter, uint16_t flags,
                             struct of_meter_band_elem *band_vectors[],
                             size_t nbands, bool modify);
    struct cbuf *(*meter_del)(uint32_t meter);
    struct cbuf *(*port_mod)(uint32_t port_no, 
            struct of_port_mod_params *pm_params, uint8_t *hw_addr);
    struct cbuf *(*async_config)(const struct of_async_config_params
                                         * async_params);
    struct cbuf *(*prep_mpart_msg)(uint16_t type, uint16_t flags, 
            size_t body_len);
    struct cbuf *(*prep_barrier_req)(void);
    struct cbuf *(*prep_vendor_msg)(struct of_vendor_params *vp);

    /* Action Ctors */
    int (*set_act_inst)(struct mul_act_mdata *mdata, uint16_t act_type);
    size_t (*inst_goto)(struct mul_act_mdata *mdata, uint8_t table_id);
    size_t (*inst_meter)(struct mul_act_mdata *mdata, uint32_t meter);
    size_t (*inst_wr_meta)(struct mul_act_mdata *mdata, uint64_t metadata,
                            uint64_t metadata_mask);
    size_t (*act_output)(struct mul_act_mdata *mdata, uint32_t oport);
    size_t (*act_set_vid)(struct mul_act_mdata *mdata, uint16_t vid);
    size_t (*act_strip_vid)(struct mul_act_mdata *mdata);
    size_t (*act_push)(struct mul_act_mdata *mdata, uint16_t eth_type);
    size_t (*act_strip_mpls)(struct mul_act_mdata *mdata, uint16_t eth_type);
    size_t (*act_strip_pbb)(struct mul_act_mdata *mdata);
    size_t (*act_set_mpls_ttl)(struct mul_act_mdata *mdata, uint8_t ttl);
    size_t (*act_dec_mpls_ttl)(struct mul_act_mdata *mdata);
    size_t (*act_set_ip_ttl)(struct mul_act_mdata *mdata, uint8_t ttl);
    size_t (*act_dec_ip_ttl)(struct mul_act_mdata *mdata);
    size_t (*act_cp_ttl)(struct mul_act_mdata *mdata, bool in);
    size_t (*act_set_dmac)(struct mul_act_mdata *mdata, uint8_t *dmac);
    size_t (*act_set_smac)(struct mul_act_mdata *mdata, uint8_t *dmac);
    size_t (*act_set_eth_type)(struct mul_act_mdata *mdata, uint16_t type);
    size_t (*act_set_mpls_label)(struct mul_act_mdata *mdata, uint32_t label);
    size_t (*act_set_mpls_tc)(struct mul_act_mdata *mdata, uint8_t tc);
    size_t (*act_set_mpls_bos)(struct mul_act_mdata *mdata, uint8_t bos);
    size_t (*act_set_nw_saddr)(struct mul_act_mdata *mdata, uint32_t nw_saddr);
    size_t (*act_set_nw_daddr)(struct mul_act_mdata *mdata, uint32_t nw_daddr);
    size_t (*act_set_nw_saddr6)(struct mul_act_mdata *mdata, 
            uint8_t *nw_saddr);
    size_t (*act_set_nw_daddr6)(struct mul_act_mdata *mdata,
            uint8_t *nw_daddr);
    size_t (*act_set_vlan_pcp)(struct mul_act_mdata *mdata, uint8_t vlan_pcp);
    size_t (*act_set_nw_tos)(struct mul_act_mdata *mdata, uint8_t tos);
    size_t (*act_set_tp_udp_dport)(struct mul_act_mdata *mdata, uint16_t port);
    size_t (*act_set_tp_udp_sport)(struct mul_act_mdata *mdata, uint16_t port);
    size_t (*act_set_tp_tcp_dport)(struct mul_act_mdata *mdata, uint16_t port);
    size_t (*act_set_tp_tcp_sport)(struct mul_act_mdata *mdata, uint16_t port);
    size_t (*act_set_group)(struct mul_act_mdata *mdata, uint32_t group);
    size_t (*act_set_queue)(struct mul_act_mdata *mdata, uint32_t queue);
    size_t (*act_set_tunnel)(struct mul_act_mdata *mdata, uint64_t queue);

    /* Meter band ctors */
    size_t (*meter_drop)(struct mul_act_mdata *mdata, 
                         struct of_meter_band_parms *bparms);
    size_t (*meter_mark_dscp)(struct mul_act_mdata *mdata, 
                         struct of_meter_band_parms *bparms);

    int (*validate_acts)(struct flow *fl, struct flow *mask,
                         void *actions, size_t action_len,
                         bool acts_only, void *u_arg);
    int (*normalize_flow)(struct flow *flow, struct flow *mask);
    int (*group_validate_feat)(struct of_group_mod_params *g_parms,
                               void *gp_feat);
    int (*meter_validate_feat)(struct of_meter_mod_params *m_parms,
                               void *m_feat);

    /* Dump Helpers */
    char *(*dump_flow)(struct flow *fl, struct flow *mask);
    char *(*dump_acts)(void *actions, size_t action_len, bool acts_only);
    void (*dump_of_msg)(struct cbuf *b, bool tx, uint64_t *mask, uint64_t dpid);

    /* Supported features */
    bool (*multi_table_support)(uint8_t n_tables, uint8_t table_id);
    bool (*flow_stats_support)(uint32_t cap);
    bool (*group_stats_support)(uint32_t cap);
    bool (*table_stats_support)(uint32_t cap);
    int (*act_modify_uflow)(struct flow *fl, struct flow *mask,
                            void *actions, size_t action_len,
                            bool acts_only, void *u_arg);
};
typedef struct c_ofp_ctors c_ofp_ctors_t;

char *of_switch_desc_dump(void *desc, size_t desc_len);
void of_mact_alloc(mul_act_mdata_t *mdata);
void of_mact_free(mul_act_mdata_t *mdata);
void of_capabilities_tostr(char *string, uint32_t capabilities);
bool of_switch_supports_flow_stats(uint32_t cap);
bool __of_match_flows(const struct flow *f1, const struct flow *m1,
                      const struct flow *f2);
bool of_match_flows_prio(struct flow *f1, struct flow *m1,
                         struct flow *f2, struct flow *m2,
                         uint16_t p1, uint16_t p2);
bool of_check_flow_wildcard_generic(struct flow *fl, struct flow *mask);
char *of_dump_flow_generic_cmd(struct flow *fl, struct flow *mask);
char *of_dump_flow_generic(struct flow *fl, struct flow *mask);
char *of_dump_flow_all(struct flow *fl);
void *of_prep_msg_common(uint8_t ver, size_t len, uint8_t type, uint32_t xid);
const char *of_role_to_str(uint32_t role);
size_t of_make_action_output(mul_act_mdata_t *mdata, uint32_t oport);
size_t of_make_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid);
size_t of_make_action_strip_vlan(mul_act_mdata_t *mdata);
size_t of_make_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac);
size_t of_make_action_set_nw_saddr(mul_act_mdata_t *mdata, uint32_t nw_saddr);
size_t of_make_action_set_nw_daddr(mul_act_mdata_t *mdata, uint32_t nw_saddr);
size_t of_make_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp);
size_t of_make_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac);
size_t of_make_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos);
size_t of_make_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port);
size_t of_make_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port);
size_t of_make_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port);
size_t of_make_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port);
struct ofp_inst_parser_arg *of10_parse_actions(struct flow *fl, struct flow *mask,
                                               void *actions, size_t action_len,
                                               struct ofp_inst_parsers *inst_parsers,
                                               struct ofp_act_parsers *act_parsers,
                                               void *u_arg);
char *of10_dump_actions(void *actions, size_t action_len, bool acts_only);
char *of10_dump_actions_cmd(void *actions, size_t action_len, bool acts_only);
char *of_dump_flow(struct flow *fl, uint32_t wildcards);
char *of10_dump_flow(struct flow *fl, struct flow *mask);
int of10_flow_correction(struct flow *fl, struct flow *mask);
int of_validate_actions(struct flow *fl, struct flow *mask,
                        void *actions, size_t action_len,
                        bool acts_only, void *u_arg); 
char *of_dump_wildcards(uint32_t wildcards);
void *of_prep_msg(size_t len, uint8_t type, uint32_t xid);
struct cbuf *of_prep_hello(void);
struct cbuf *of_prep_echo(void);
struct cbuf *of_prep_echo_reply(uint32_t xid);
struct cbuf *of_prep_features_request(void);
struct cbuf *of_prep_set_config(uint16_t flags, uint16_t miss_len);
struct cbuf *of_prep_flow_mod(uint16_t command, const struct flow *flow, 
                              const struct flow *mask, size_t actions_len);
struct cbuf *of_prep_flow_add_msg(const struct flow *flow, 
                                  const struct flow *mask,
                                  uint32_t buffer_id,
                                  void *actions, size_t actions_len, 
                                  uint16_t i_timeo, uint16_t h_timeo, 
                                  uint16_t prio, uint64_t cookie, bool mod);
struct cbuf *of_prep_flow_del_msg(const struct flow *flow, 
                                  const struct flow *mask,
                                  uint32_t oport,
                                  bool strict, uint16_t prio,
                                  uint32_t group);
struct cbuf *of_prep_pkt_out_msg(struct of_pkt_out_params *parms);
struct cbuf *of_prep_flow_stat_msg(const struct flow *flow, 
                                   const struct flow *mask,
                                   uint32_t oport,
                                   uint32_t group);
struct cbuf *of_prep_port_stat_msg(uint32_t port_no);
struct cbuf *of_prep_q_get_config(uint32_t port_no);
struct cbuf *of_prep_vendor_msg(struct of_vendor_params *vp);

uint32_t of10_mask_to_wc(const struct flow *mask);
void of10_wc_to_mask(uint32_t wildcards, struct flow *mask);

void of131_capabilities_tostr(char *string, uint32_t capabilities);
struct cbuf *of131_prep_hello_msg(void);
struct cbuf *of131_prep_echo_msg(void);
struct cbuf *of131_prep_echo_reply_msg(uint32_t xid);
struct cbuf *of131_prep_features_request_msg(void);
struct cbuf *of131_prep_pkt_out_msg(struct of_pkt_out_params *parms);
struct cbuf *of131_prep_flow_add_msg(const struct flow *flow,
                                     const struct flow *mask,
                                     uint32_t buffer_id, void *ins_list,
                                     size_t ins_len, uint16_t i_timeo,
                                     uint16_t h_timeo, uint16_t prio,
                                     uint64_t cookie, bool mod);
struct cbuf *of131_prep_barrier_req(void);
struct cbuf *of131_prep_flow_del_msg(const struct flow *flow,
                                     const struct flow *mask,
                                     uint32_t oport, bool strict,
                                     uint16_t prio, uint32_t group);
struct cbuf *of131_prep_flow_stat_msg(const struct flow *flow,
                                      const struct flow *mask,
                                      uint32_t eoport,
                                      uint32_t group);
struct cbuf *of131_prep_queue_stat_msg(uint32_t port, uint32_t queue);
struct cbuf *of131_prep_group_add_msg(uint32_t group, uint8_t type,
                                      struct of_act_vec_elem *act_vectors[],
                                      size_t act_vec_len, bool modify);
struct cbuf *of131_prep_group_del_msg(uint32_t group);
struct cbuf *of131_prep_meter_add_msg(uint32_t meter, uint16_t flags,
                         struct of_meter_band_elem *band_vectors[],
                         size_t nbands, bool modify);
struct cbuf *of131_prep_meter_del_msg(uint32_t meter);
struct cbuf * of131_prep_port_mod_msg(uint32_t port_no, 
                        struct of_port_mod_params *pm_params, 
                        uint8_t *hw_addr);
struct cbuf *of131_prep_async_config(const struct of_async_config_params
                                      *ac_params) ;
struct cbuf *of131_prep_mpart_msg(uint16_t type, uint16_t flags, 
                        size_t body_len);
bool of131_group_validate_parms(bool add, uint32_t group, uint8_t type,
                                struct of_act_vec_elem *act_vectors[],
                                size_t act_vec_len);
int of131_ofpx_match_to_flow(struct ofpx_match *ofx,
                             struct flow *flow, struct flow *mask);
struct cbuf *of131_prep_set_config_msg(uint16_t flags, uint16_t miss_len);
struct cbuf *of131_prep_role_request_msg(uint32_t role, uint64_t gen_id);
int of131_set_inst_action_type(mul_act_mdata_t *mdata, uint16_t type);
size_t of131_make_inst_actions(mul_act_mdata_t *mdata, uint16_t type);
void of131_fini_inst_actions(mul_act_mdata_t *mdata);
size_t of131_make_inst_goto(mul_act_mdata_t *mdata, uint8_t tbl_id);
size_t of131_make_inst_meter(mul_act_mdata_t *mdata, uint32_t meter);
size_t of131_make_inst_wr_meta(mul_act_mdata_t *mdata, uint64_t metadata, 
        uint64_t metadata_mask);
size_t of131_make_inst_clear_act(mul_act_mdata_t *mdata);
size_t of131_make_action_output(mul_act_mdata_t *mdata, uint32_t oport);
size_t of131_make_action_push(mul_act_mdata_t *mdata, uint16_t eth_type);
size_t of131_make_action_strip_mpls(mul_act_mdata_t *mdata, uint16_t eth_type);
size_t of131_make_action_set_mpls_ttl(mul_act_mdata_t *mdata, uint8_t ttl);
size_t of131_make_action_dec_mpls_ttl(mul_act_mdata_t *mdata);
size_t of131_make_action_set_ip_ttl(mul_act_mdata_t *mdata, uint8_t ttl);
size_t of131_make_action_dec_ip_ttl(mul_act_mdata_t *mdata);
size_t of131_make_action_cp_ttl(mul_act_mdata_t *mdata, bool in);
size_t of131_make_action_strip_pbb(mul_act_mdata_t *mdata);
size_t of131_make_action_set_vid(mul_act_mdata_t *mdata, uint16_t vid);
size_t of131_make_action_strip_vlan(mul_act_mdata_t *mdata);
size_t of131_make_action_set_vlan_pcp(mul_act_mdata_t *mdata, uint8_t vlan_pcp);
size_t of131_make_action_set_mpls_label(mul_act_mdata_t *mdata, uint32_t label);
size_t of131_make_action_set_mpls_tc(mul_act_mdata_t *mdata, uint8_t tc);
size_t of131_make_action_set_mpls_bos(mul_act_mdata_t *mdata, uint8_t bos);
size_t of131_make_action_set_dmac(mul_act_mdata_t *mdata, uint8_t *dmac);
size_t of131_make_action_set_smac(mul_act_mdata_t *mdata, uint8_t *smac);
size_t of131_make_action_set_eth_type(mul_act_mdata_t *mdata, uint16_t eth_type);
size_t of131_make_action_set_ipv4_src(mul_act_mdata_t *mdata, uint32_t nw_saddr);
size_t of131_make_action_set_ipv4_dst(mul_act_mdata_t *mdata, uint32_t nw_daddr);
size_t of131_make_action_set_ipv6_src(mul_act_mdata_t *mdata, uint8_t *nw_saddr);
size_t of131_make_action_set_ipv6_dst(mul_act_mdata_t *mdata, uint8_t *nw_daddr);
size_t of131_make_action_set_nw_tos(mul_act_mdata_t *mdata, uint8_t tos);
size_t of131_make_action_set_tp_udp_sport(mul_act_mdata_t *mdata, uint16_t port);
size_t of131_make_action_set_tp_udp_dport(mul_act_mdata_t *mdata, uint16_t port);
size_t of131_make_action_set_tp_tcp_sport(mul_act_mdata_t *mdata, uint16_t port);
size_t of131_make_action_set_tp_tcp_dport(mul_act_mdata_t *mdata, uint16_t port);
size_t of131_make_action_group(mul_act_mdata_t *mdata, uint32_t group);
size_t of131_make_action_set_queue(mul_act_mdata_t *mdata, uint32_t queue);
size_t of131_make_action_set_tunnel_id(mul_act_mdata_t *mdata,
                                       uint64_t tunnel_id);
size_t of131_make_meter_band_drop(mul_act_mdata_t *mdata,
                                  struct of_meter_band_parms *bparms);
size_t of131_make_meter_band_mark_dscp(mul_act_mdata_t *mdata,
                                       struct of_meter_band_parms *bparms);
void of131_parse_actions(void *actions, size_t act_len,
                         void *parse_ctx);
void of131_parse_act_set_field_tlv(struct ofp_action_set_field *ofp_sf,
                              struct ofp_act_parsers *act_parsers,
                              void *parse_ctx);
struct ofp_inst_parser_arg *of131_parse_instructions(
                                struct flow *fl, struct flow *mask,
                                void *inst_list, size_t inst_len,
                                struct ofp_inst_parsers *inst_handlers,
                                struct ofp_act_parsers *act_handlers,
                                void *u_arg, bool acts_only);
int of131_validate_actions(struct flow *fl, struct flow *mask,
                           void *inst_list, size_t inst_len,
                           bool acts_only, void *arg);
char *of131_dump_actions(void *inst_list, size_t inst_len, bool acts_only);
char *of131_dump_actions_cmd(void *inst_list, size_t inst_len, bool acts_only);
char *of131_dump_queue_stats(void *q_stats, size_t stat_len);
bool of131_supports_multi_tables(uint8_t n_tables, uint8_t table_id);
int of131_flow_normalize(struct flow *fl, struct flow *mask);
char *of131_group_features_dump(void *feat, size_t feat_len);
char *of131_meter_features_dump(void *feat, size_t feat_len);
int of131_group_validate_feat(struct of_group_mod_params *g_parms,
                              void *gp_feat);
int of131_meter_validate_feat(struct of_meter_mod_params *m_parms,
                              void *m_feat);
char *of131_table_features_dump(of_flow_tbl_props_t *prop);
bool of131_switch_supports_group_stats(uint32_t cap);
bool of131_switch_supports_flow_stats(uint32_t cap);
bool of131_switch_supports_table_stats(uint32_t cap);
struct cbuf *of131_prep_group_stat_req(uint32_t group_id);
struct cbuf *of131_prep_meter_stat_req(uint32_t meter_id);
struct cbuf *of131_prep_meter_config_req(uint32_t meter_id);
struct cbuf *of131_prep_port_stat_req(uint32_t port);
struct cbuf *of131_prep_q_get_config(uint32_t port_no);
void of131_dump_msg(struct cbuf *b, bool tx, uint64_t *mask, uint64_t dpid);
char * of131_port_stats_dump(void *feat, size_t feat_len);
char * of_port_stats_dump(void *feat, size_t feat_len);
void ofp131_dump_port_details(char *string, uint32_t config, 
                              uint32_t state);
int of131_modify_uflow(struct flow *fl, struct flow *mask,
                       void *inst_list, size_t inst_len,
                       bool acts_only, void *arg);
void ofp_dump_port_details(char *string, uint32_t config, uint32_t state);
void ofp_convert_flow_endian_hton(struct flow *fl);
struct cbuf * of_prep_port_mod_msg(uint32_t port_no, 
                                   struct of_port_mod_params *pm_params, 
                                   uint8_t *hw_addr);

struct cbuf *of140_prep_hello_msg(void);
struct cbuf *of140_prep_echo_msg(void);
struct cbuf *of140_prep_echo_reply_msg(uint32_t xid);
struct cbuf * of140_prep_features_request_msg(void);
struct cbuf * of140_prep_mpart_msg(uint16_t type, uint16_t flags, size_t
        body_len);
struct cbuf * of140_prep_role_request_msg(uint32_t role, uint64_t gen_id);
void ofp_dump_port_type(char *string, uint16_t type) ;
void ofp_dump_port_speed(char *string, uint32_t curr_speed, uint32_t max_speed);
struct cbuf *of140_prep_flow_add_msg(const struct flow *flow,
                                     const struct flow *mask,
                                     uint32_t buffer_id, void *ins_list,
                                     size_t ins_len, uint16_t i_timeo,
                                     uint16_t h_timeo, uint16_t prio,
                                     uint64_t cookie, bool mod);
struct cbuf *of140_prep_flow_del_msg(const struct flow *flow,
                                     const struct flow *mask,
                                     uint32_t oport, bool strict,
                                     uint16_t prio, uint32_t group);
struct cbuf *of140_prep_flow_stat_msg(const struct flow *flow,
                                      const struct flow *mask,
                                      uint32_t eoport,
                                      uint32_t group);
struct cbuf *of140_prep_queue_stat_msg(uint32_t port, uint32_t queue);

struct cbuf *of140_prep_group_stat_req(uint32_t group_id);
struct cbuf *of140_prep_meter_stat_req(uint32_t meter_id);
struct cbuf *of140_prep_meter_config_req(uint32_t meter_id);
struct cbuf *of140_prep_port_stat_req(uint32_t port);
struct cbuf *of140_prep_group_add_msg(uint32_t group, uint8_t type,
                                      struct of_act_vec_elem *act_vectors[],
                                      size_t act_vec_len, bool modify);
struct cbuf *of140_prep_group_del_msg(uint32_t group);
struct cbuf *of140_prep_meter_add_msg(uint32_t meter, uint16_t flags,
                         struct of_meter_band_elem *band_vectors[],
                         size_t nbands, bool modify);
struct cbuf *of140_prep_meter_del_msg(uint32_t meter);
struct cbuf * of140_prep_port_mod_msg(uint32_t port_no, 
                        struct of_port_mod_params *pm_params, 
                        uint8_t *hw_addr);
char * of140_port_stats_dump(void *feat, size_t feat_len);
struct cbuf *of140_prep_pkt_out_msg(struct of_pkt_out_params *parms);
struct cbuf *of140_prep_barrier_req(void);
struct cbuf *of140_prep_q_get_config(uint32_t port_no);
struct cbuf *of140_prep_set_config_msg(uint16_t flags, uint16_t miss_len);

#endif
