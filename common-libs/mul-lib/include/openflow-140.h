/*
 * openflow-140.h: MUL openflow 1.4 definitions 
 *
 */
#ifndef __OPENFLOW_140_H__
#define __OPENFLOW_140_H__

#include "openflow-common.h"

enum ofp140_type {
    /* Immutable messages. */
    OFPT140_HELLO = 0,              /* Symmetric message */
    OFPT140_ERROR = 1,              /* Symmetric message */
    OFPT140_ECHO_REQUEST = 2,       /* Symmetric message */
    OFPT140_ECHO_REPLY = 3,         /* Symmetric message */
    OFPT140_EXPERIMENTER = 4,       /* Symmetric message */

    /* Switch configuration messages. */
    OFPT140_FEATURES_REQUEST = 5,   /* Controller/switch message */
    OFPT140_FEATURES_REPLY = 6,     /* Controller/switch message */
    OFPT140_GET_CONFIG_REQUEST = 7, /* Controller/switch message */
    OFPT140_GET_CONFIG_REPLY = 8,   /* Controller/switch message */
    OFPT140_SET_CONFIG = 9,         /* Controller/switch message */

    /* Asynchronous messages. */
    OFPT140_PACKET_IN = 10,         /* Async message */
    OFPT140_FLOW_REMOVED = 11,      /* Async message */
    OFPT140_PORT_STATUS = 12,       /* Async message */

    /* Controller command messages. */
    OFPT140_PACKET_OUT = 13,        /* Controller/switch message */
    OFPT140_FLOW_MOD = 14,          /* Controller/switch message */
    OFPT140_GROUP_MOD = 15,         /* Controller/switch message */
    OFPT140_PORT_MOD = 16,          /* Controller/switch message */
    OFPT140_TABLE_MOD = 17,         /* Controller/switch message */

    /* Multipart messages. */
    OFPT140_MULTIPART_REQUEST = 18, /* Controller/switch message */
    OFPT140_MULTIPART_REPLY = 19,   /* Controller/switch message */

    /* Barrier messages. */
    OFPT140_BARRIER_REQUEST = 20,   /* Controller/switch message */
    OFPT140_BARRIER_REPLY = 21,     /* Controller/switch message */

    /* Queue Configuration messages. */
    OFPT140_QUEUE_GET_CONFIG_REQUEST = 22,  /* Controller/switch message */
    OFPT140_QUEUE_GET_CONFIG_REPLY = 23,    /* Controller/switch message */

    /* Controller role change request messages. */
    OFPT140_ROLE_REQUEST = 24,      /* Controller/switch message */
    OFPT140_ROLE_REPLY = 25,        /* Controller/switch message */

    /* Asynchronous message configuration. */
    OFPT140_GET_ASYNC_REQUEST = 26, /* Controller/switch message */
    OFPT140_GET_ASYNC_REPLY = 27,   /* Controller/switch message */
    OFPT140_SET_ASYNC = 28,         /* Controller/switch message */

    /* Meters and rate limiters configuration messages. */
    OFPT140_METER_MOD = 29,         /* Controller/switch message */

    /* Controller role change event messages. */
    OFPT140_ROLE_STATUS = 30, /* Async message */

    /* Asynchronous messages. */
    OFPT140_TABLE_STATUS = 31, /* Async message */

    /* Request forwarding by the switch. */
    OFPT140_REQUESTFORWARD = 32, /* Async message */

    /* Bundle operations (multiple messages as a single operation). */
    OFPT140_BUNDLE_CONTROL = 33,
    OFPT140_BUNDLE_ADD_MESSAGE = 34,
};

/* Port stats property types.
   */
enum ofp_port_stats_prop_type {
    OFPPSPT_ETHERNET = 0, /* Ethernet property. */
    OFPPSPT_OPTICAL = 1, /* Optical property. */
    OFPPSPT_EXPERIMENTER = 0xFFFF, /* Experimenter property. */
};

/* Common header for all port description properties. */
struct ofp_port_desc_prop_header {
    uint16_t type; /* One of OFPPDPT_*. */
    uint16_t length; /* Length in bytes of this property. */
};
OFP_ASSERT(sizeof(struct ofp_port_desc_prop_header) == 4);

/* Ethernet port description property. */
struct ofp_port_desc_prop_ethernet {
    uint16_t type; /* OFPPDPT_ETHERNET. */
    uint16_t length; /* Length in bytes of this property. */
    uint8_t pad[4]; /* Align to 64 bits. */
   
    /* Bitmaps of OFPPF_* that describe features. All bits zeroed if
     * unsupported or unavailable. */
    uint32_t curr; /* Current features. */
    uint32_t advertised; /* Features being advertised by the port. */
    uint32_t supported; /* Features supported by the port. */
    uint32_t peer; /* Features advertised by peer. */
    uint32_t curr_speed; /* Current port bitrate in kbps. */
    uint32_t max_speed; /* Max port bitrate in kbps */
};
OFP_ASSERT(sizeof(struct ofp_port_desc_prop_ethernet) == 32);

/* Features of optical ports available in switch. */
enum ofp_optical_port_features {
    OFPOPF_RX_TUNE = 1 << 0, /* Receiver is tunable */
    OFPOPF_TX_TUNE = 1 << 1, /* Transmit is tunable */
    OFPOPF_TX_PWR = 1 << 2, /* Power is configurable */
    OFPOPF_USE_FREQ = 1 << 3, /* Use Frequency, not wavelength */
};

/* Optical port description property. */
struct ofp_port_desc_prop_optical {
    uint16_t type; /* OFPPDPT_3OPTICAL. */
    uint16_t length; /* Length in bytes of this property. */
    uint8_t pad[4]; /* Align to 64 bits. */
    uint32_t supported; /* Features supported by the port. */
    uint32_t tx_min_freq_lmda; /* Minimum TX Frequency/Wavelength */
    uint32_t tx_max_freq_lmda; /* Maximum TX Frequency/Wavelength */
    uint32_t tx_grid_freq_lmda; /* TX Grid Spacing Frequency/Wavelength */
    uint32_t rx_min_freq_lmda; /* Minimum RX Frequency/Wavelength */
    uint32_t rx_max_freq_lmda; /* Maximum RX Frequency/Wavelength */
    uint32_t rx_grid_freq_lmda; /* RX Grid Spacing Frequency/Wavelength */
    uint16_t tx_pwr_min; /* Minimum TX power */
    uint16_t tx_pwr_max; /* Maximum TX power */
};
OFP_ASSERT(sizeof(struct ofp_port_desc_prop_optical) == 40);

/* Description of a port */
struct ofp140_port {
    uint32_t port_no;
    uint16_t length;
    uint8_t pad[2];
    uint8_t hw_addr[OFP_ETH_ALEN];
    uint8_t pad2[2];    /* Align to 64 bits. */
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */
    uint32_t config;    /* Bitmap of OFPPC_* flags. */
    uint32_t state;     /* Bitmap of OFPPS_* flags. */
    /* Port description property list - 0 or more properties */
    struct ofp_port_desc_prop_header properties[0];
};
OFP_ASSERT(sizeof(struct ofp140_port) == 40);

/* Flags to indicate behavior of the physical port. These flags are
* used in ofp_port to describe the current configuration. They are
* used in the ofp_port_mod message to configure the port's behavior.
*/
enum ofp140_port_config {
    OFPPC140_PORT_DOWN = 1 << 0,   /* Port is administratively down. */
    OFPPC140_NO_RECV = 1 << 2,     /* Drop all packets received by port. */
    OFPPC140_NO_FWD = 1 << 5,      /* Drop packets forwarded to port. */
    OFPPC140_NO_PACKET_IN = 1 << 6 /* Do not send packet-in msgs for port. */
};


/* Current state of the physical port. These are not configurable from
* the controller.
*/
enum ofp140_port_state {
    OFPPS140_LINK_DOWN = 1 << 0, /* No physical link present. */
    OFPPS140_BLOCKED = 1 << 1, /* Port is blocked */
    OFPPS140_LIVE = 1 << 2, /* Live for Fast Failover Group. */
};

/* Port numbering. Ports are numbered starting from 1. */
enum ofp140_port_no {
    /* Maximum number of physical and logical switch ports. */
    OFPP140_MAX = 0xffffff00,
    /* Reserved OpenFlow Port (fake output "ports"). */
    OFPP140_IN_PORT = 0xfffffff8, /* Send the packet out the input port. This
                                  reserved port must be explicitly used
                                  in order to send back out of the input
                                  port. */
    OFPP140_TABLE = 0xfffffff9, /* Submit the packet to the first flow table
                                NB: This destination port can only be
                                used in packet-out messages. */
    OFPP140_NORMAL = 0xfffffffa, /* Process with normal L2/L3 switching. */
    OFPP140_FLOOD = 0xfffffffb, /* All physical ports in VLAN, except input
                                port and those blocked or link down. */
    OFPP140_ALL = 0xfffffffc, /* All physical ports except input port. */
    OFPP140_CONTROLLER = 0xfffffffd, /* Send to controller. */
    OFPP140_LOCAL = 0xfffffffe, /* Local openflow "port". */
    OFPP140_ANY = 0xffffffff /* Wildcard port used only for flow mod
                             (delete) and flow stats requests. Selects
                             all flows regardless of output port
                             (including flows with no output port). */
};

/* Features of ports available in a datapath. */
enum ofp140_port_features {
    OFPPF140_10MB_HD = 1 << 0, /* 10 Mb half-duplex rate support. */
    OFPPF140_10MB_FD = 1 << 1, /* 10 Mb full-duplex rate support. */
    OFPPF140_100MB_HD = 1 << 2, /* 100 Mb half-duplex rate support. */
    OFPPF140_100MB_FD = 1 << 3, /* 100 Mb full-duplex rate support. */
    OFPPF140_1GB_HD = 1 << 4, /* 1 Gb half-duplex rate support. */
    OFPPF140_1GB_FD = 1 << 5, /* 1 Gb full-duplex rate support. */
    OFPPF140_10GB_FD = 1 << 6, /* 10 Gb full-duplex rate support. */
    OFPPF140_40GB_FD = 1 << 7, /* 40 Gb full-duplex rate support. */
    OFPPF140_100GB_FD = 1 << 8, /* 100 Gb full-duplex rate support. */
    OFPPF140_1TB_FD = 1 << 9, /* 1 Tb full-duplex rate support. */
    OFPPF140_OTHER = 1 << 10, /* Other rate, not in the list. */
    OFPPF140_COPPER = 1 << 11, /* Copper medium. */
    OFPPF140_FIBER = 1 << 12, /* Fiber medium. */
    OFPPF140_AUTONEG = 1 << 13, /* Auto-negotiation. */
    OFPPF140_PAUSE = 1 << 14, /* Pause. */
    OFPPF140_PAUSE_ASYM = 1 << 15 /* Asymmetric pause. */
};

/* Full description for a queue. */
struct ofp140_packet_queue {
    uint32_t queue_id; /* id for the specific queue. */
    uint32_t port; /* Port this queue is attached to. */
    uint16_t len; /* Length in bytes of this queue desc. */
    uint8_t pad[6]; /* 64-bit alignment. */
    struct ofp_queue_prop_header properties[0]; /* List of properties. */
};
OFP_ASSERT(sizeof(struct ofp140_packet_queue) == 16);

/* Experimenter queue property description. */
struct ofp140_queue_prop_experimenter {
    struct ofp_queue_prop_header prop_header; /* prop: OFPQT_EXPERIMENTER, len: 16. */
    uint32_t experimenter; /* Experimenter ID which takes the same
                              form as in struct
                              ofp_experimenter_header. */
    uint8_t pad[4]; /* 64-bit alignment */
    uint8_t data[0]; /* Experimenter defined data. */
};
OFP_ASSERT(sizeof(struct ofp140_queue_prop_experimenter) == 16);

/* Header for OXM experimenter match fields. */
struct ofp140_oxm_experimenter_header {
    uint32_t oxm_header; /* oxm_class = OFPXMC_EXPERIMENTER */
    uint32_t experimenter; /* Experimenter ID which takes the same
                              form as in struct ofp_experimenter_header. */
};
OFP_ASSERT(sizeof(struct ofp140_oxm_experimenter_header) == 8);

enum ofp140_action_type {
    OFPAT140_OUTPUT = 0, /* Output to switch port. */
    OFPAT140_COPY_TTL_OUT = 11, /* Copy TTL "outwards" -- from next-to-outermost
                                    to outermost */
    OFPAT140_COPY_TTL_IN = 12, /* Copy TTL "inwards" -- from outermost to
                                    next-to-outermost */
    OFPAT140_MPLS_TTL = 15, /* MPLS TTL */
    OFPAT140_DEC_MPLS_TTL = 16, /* Decrement MPLS TTL */
    OFPAT140_PUSH_VLAN = 17, /* Push a new VLAN tag */
    OFPAT140_POP_VLAN = 18, /* Pop the outer VLAN tag */
    OFPAT140_PUSH_MPLS = 19, /* Push a new MPLS tag */
    OFPAT140_POP_MPLS = 20, /* Pop the outer MPLS tag */
    OFPAT140_SET_QUEUE = 21, /* Set queue id when outputting to a port */
    OFPAT140_GROUP = 22, /* Apply group. */
    OFPAT140_SET_NW_TTL = 23, /* IP TTL. */
    OFPAT140_DEC_NW_TTL = 24, /* Decrement IP TTL. */
    OFPAT140_SET_FIELD = 25, /* Set a header field using OXM TLV format. */
    OFPAT140_PUSH_PBB = 26, /* Push a new PBB service tag (I-TAG) */
    OFPAT140_POP_PBB = 27, /* Pop the outer PBB service tag (I-TAG) */
    OFPAT140_EXPERIMENTER = 0xffff
};

/* Action structure for OFPAT_OUTPUT, which sends packets out 'port'.
* When the 'port' is the OFPP_CONTROLLER, 'max_len' indicates the max
* number of bytes to send. A 'max_len' of zero means no bytes of the
* packet should be sent. A 'max_len' of OFPCML_NO_BUFFER means that
* the packet is not buffered and the complete packet is to be sent to
* the controller. */
struct ofp140_action_output {
    uint16_t type; /* OFPAT_OUTPUT. */
    uint16_t len; /* Length is 16. */
    uint32_t port; /* Output port. */
    uint16_t max_len; /* Max length to send to controller. */
    uint8_t pad[6]; /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp140_action_output) == 16);

/* OFPAT_SET_QUEUE action struct: send packets to given queue on port. */
struct ofp140_action_set_queue {
    uint16_t type; /* OFPAT_SET_QUEUE. */
    uint16_t len; /* Len is 8. */
    uint32_t queue_id; /* Queue id for the packets. */
};
OFP_ASSERT(sizeof(struct ofp140_action_set_queue) == 8);

/* Switch features. */
struct ofp140_switch_features {
    struct ofp_header header;
    uint64_t datapath_id; /* Datapath unique ID. The lower 48-bits are for
                             a MAC address, while the upper 16-bits are
                             implementer-defined. */
    uint32_t n_buffers; /* Max packets buffered at once. */
    uint8_t n_tables; /* Number of tables supported by datapath. */
    uint8_t auxiliary_id; /* Identify auxiliary connections */
    uint8_t pad[2]; /* Align to 64-bits. */
    /* Features. */
    uint32_t capabilities; /* Bitmap of support "ofp_capabilities". */
    uint32_t reserved;
};
OFP_ASSERT(sizeof(struct ofp140_switch_features) == 32);

/* Capabilities supported by the datapath. */
enum ofp140_capabilities {
    OFPC140_FLOW_STATS = 1 << 0, /* Flow statistics. */
    OFPC140_TABLE_STATS = 1 << 1, /* Table statistics. */
    OFPC140_PORT_STATS = 1 << 2, /* Port statistics. */
    OFPC140_GROUP_STATS = 1 << 3, /* Group statistics. */
    OFPC140_IP_REASM = 1 << 5, /* Can reassemble IP fragments. */
    OFPC140_QUEUE_STATS = 1 << 6, /* Queue statistics. */
    OFPC140_PORT_BLOCKED = 1 << 8 /* Switch will block looping ports. */
};

/* Flow setup and teardown (controller -> datapath). */
struct ofp140_flow_mod {
    struct ofp_header header;
    uint64_t cookie; /* Opaque controller-issued identifier. */
    uint64_t cookie_mask; /* Mask used to restrict the cookie bits
                             that must match when the command is
                             OFPFC_MODIFY* or OFPFC_DELETE*. A value
                             of 0 indicates no restriction. */
    /* Flow actions. */ 
    uint8_t table_id; /* ID of the table to put the flow in.
                         For OFPFC_DELETE_* commands, OFPTT_ALL
                         can also be used to delete matching
                         flows from all tables. */
    uint8_t command; /* One of OFPFC_*. */
    uint16_t idle_timeout; /* Idle time before discarding (seconds). */
    uint16_t hard_timeout; /* Max time before discarding (seconds). */
    uint16_t priority; /* Priority level of flow entry. */
    uint32_t buffer_id; /* Buffered packet to apply to, or
                           OFP_NO_BUFFER.
                            Not meaningful for OFPFC_DELETE*. */
    uint32_t out_port; /* For OFPFC_DELETE* commands, require
                          matching entries to include this as an
                          output port. A value of OFPP_ANY
                          indicates no restriction. */
    uint32_t out_group; /* For OFPFC_DELETE* commands, require
                           matching entries to include this as an
                           output group. A value of OFPG_ANY
                           indicates no restriction. */
    uint16_t flags; /* One of OFPFF_*. */
    uint8_t pad[2];
    struct ofpx_match match; /* Fields to match. Variable size. */
    //struct ofp_instruction instructions[0]; /* Instruction set */
};
OFP_ASSERT(sizeof(struct ofp140_flow_mod) == 56);

enum ofp140_flow_mod_flags {
    OFPFF140_SEND_FLOW_REM = OFPFF_SEND_FLOW_REM, /* Send flow removed message when flow
                                                   * expires or is deleted. */
    OFPFF140_CHECK_OVERLAP = OFPFF_CHECK_OVERLAP, /* Check for overlapping entries first. */
    OFPFF140_RESET_COUNTS = 1 << 2, /* Reset flow packet and byte counts. */
    OFPFF140_NO_PKT_COUNTS = 1 << 3, /* Don't keep track of packet count. */
    OFPFF140_NO_BYT_COUNTS = 1 << 4, /* Don't keep track of byte count. */
};

/* Port mod property types.
   */
enum ofp_port_mod_prop_type {
    OFPPMPT_ETHERNET = 0, /* Ethernet property. */
    OFPPMPT_OPTICAL = 1, /* Optical property. */
    OFPPMPT_EXPERIMENTER = 0xFFFF, /* Experimenter property. */
};

/* Common header for all port mod properties. */
struct ofp_port_mod_prop_header {
    uint16_t type; /* One of OFPPMPT_*. */
    uint16_t length; /* Length in bytes of this property. */
};
OFP_ASSERT(sizeof(struct ofp_port_mod_prop_header) == 4);
/* Ethernet port mod property. */
struct ofp_port_mod_prop_ethernet {
    uint16_t type; /* OFPPMPT_ETHERNET. */
    uint16_t length; /* Length in bytes of this property. */
    uint32_t advertise; /* Bitmap of OFPPF_*. Zero all bits to prevent
                           any action taking place. */
};
OFP_ASSERT(sizeof(struct ofp_port_mod_prop_ethernet) == 8);
struct ofp_port_mod_prop_optical {
    uint16_t type; /* OFPPMPT_OPTICAL. */
    uint16_t length; /* Length in bytes of this property. */
    uint32_t configure; /* Bitmap of OFPOPF_*. */
    uint32_t freq_lmda; /* The "center" frequency */
    int32_t fl_offset; /* signed frequency offset */
    uint32_t grid_span; /* The size of the grid for this port */
    uint32_t tx_pwr; /* tx power setting */
};
OFP_ASSERT(sizeof(struct ofp_port_mod_prop_optical) == 24);

/* Experimenter port mod property. */
struct ofp_port_mod_prop_experimenter {
    uint16_t type; /* OFPPMPT_EXPERIMENTER. */
    uint16_t length; /* Length in bytes of this property. */
    uint32_t experimenter; /* Experimenter ID which takes the same
                              form as in struct
                              ofp_experimenter_header. */
    uint32_t exp_type; /* Experimenter defined. */
    /* Followed by:
       * - Exactly (length - 12) bytes containing the experimenter data,
       * then
       * - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
       * bytes of all-zero bytes */
    uint32_t experimenter_data[0];
};
OFP_ASSERT(sizeof(struct ofp_port_mod_prop_experimenter) == 12);

/* Modify behavior of the physical port */
struct ofp140_port_mod {
    struct ofp_header header;
    uint32_t port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP_ETH_ALEN]; /* The hardware address is not
                                      configurable. This is used to
                                      sanity-check the request, so it must
                                      be the same as returned in an
                                      ofp_port struct. */
    uint8_t pad2[2]; /* Pad to 64 bits. */
    uint32_t config; /* Bitmap of OFPPC140_* flags. */
    uint32_t mask; /* Bitmap of OFPPC140_* flags to be changed. */
    /* Port mod property list - 0 or more properties */
    struct ofp_port_mod_prop_header properties[0];
};
OFP_ASSERT(sizeof(struct ofp140_port_mod) == 32);

/* Body for ofp_multipart_request of type OFPMP_FLOW. */
struct ofp140_flow_stats_request {
    uint8_t table_id; /* ID of table to read (from ofp_table_stats),
                         OFPTT_ALL for all tables. */
    uint8_t pad[3]; /* Align to 32 bits. */
    uint32_t out_port; /* Require matching entries to include this
                          as an output port. A value of OFPP_ANY
                          indicates no restriction. */
    uint32_t out_group; /* Require matching entries to include this
                           as an output group. A value of OFPG_ANY
                           indicates no restriction. */
    uint8_t pad2[4]; /* Align to 64 bits. */
    uint64_t cookie; /* Require matching entries to contain this
                        cookie value */
    uint64_t cookie_mask; /* Mask used to restrict the cookie bits that
                             must match. A value of 0 indicates
                             no restriction. */
    struct ofpx_match match; /* Fields to match. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp140_flow_stats_request) == 40);

/* Body of reply to OFPMP_FLOW request. */
struct ofp140_flow_stats {
    uint16_t length; /* Length of this entry. */
    uint8_t table_id; /* ID of table flow came from. */
    uint8_t pad;
    uint32_t duration_sec; /* Time flow has been alive in seconds. */
    uint32_t duration_nsec; /* Time flow has been alive in nanoseconds beyond
                              duration_sec. */
    uint16_t priority; /* Priority of the entry. */
    uint16_t idle_timeout; /* Number of seconds idle before expiration. */
    uint16_t hard_timeout; /* Number of seconds before expiration. */
    uint16_t flags; /* One of OFPFF_*. */
    uint8_t pad2[4]; /* Align to 64-bits. */
    uint64_t cookie; /* Opaque controller-issued identifier. */
    uint64_t packet_count; /* Number of packets in flow. */
    uint64_t byte_count; /* Number of bytes in flow. */
    struct ofpx_match match; /* Description of fields. Variable size. */
    //struct ofp_instruction instructions[0]; /* Instruction set. */
};
OFP_ASSERT(sizeof(struct ofp140_flow_stats) == 56);

/* Body for ofp_multipart_request of type OFPMP_AGGREGATE. */
struct ofp140_aggregate_stats_request {
    uint8_t table_id; /* ID of table to read (from ofp_table_stats)
                         OFPTT_ALL for all tables. */
    uint8_t pad[3]; /* Align to 32 bits. */
    uint32_t out_port; /* Require matching entries to include this
                          as an output port. A value of OFPP_ANY
                          indicates no restriction. */
    uint32_t out_group; /* Require matching entries to include this
                            as an output group. A value of OFPG_ANY
                            indicates no restriction. */
    uint8_t pad2[4]; /* Align to 64 bits. */
    uint64_t cookie; /* Require matching entries to contain this
                        cookie value */
    uint64_t cookie_mask; /* Mask used to restrict the cookie bits that
                            must match. A value of 0 indicates
                            no restriction. */
    struct ofpx_match match; /* Fields to match. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp140_aggregate_stats_request) == 40);

/* Body of reply to OFPMP_TABLE request. */
struct ofp140_table_stats {
    uint8_t table_id; /* Identifier of table. Lower numbered tables
                    are consulted first. */
    uint8_t pad[3]; /* Align to 32-bits. */
    uint32_t active_count; /* Number of active entries. */
    uint64_t lookup_count; /* Number of packets looked up in table. */
    uint64_t matched_count; /* Number of packets that hit table. */
};
OFP_ASSERT(sizeof(struct ofp140_table_stats) == 24);

/* Body for ofp_multipart_request of type OFPMP_PORT. */
struct ofp140_port_stats_request {
    uint32_t port_no; /* OFPMP_PORT message must request statistics
                       * either for a single port (specified in
                       * port_no) or for all ports (if port_no ==
                       * OFPP_ANY). */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp140_port_stats_request) == 8);

/* Body of reply to OFPMP_PORT request. If a counter is unsupported, set
* the field to all ones. */
struct ofp140_port_stats {
    uint32_t port_no;
    uint8_t pad[4]; /* Align to 64-bits. */
    uint64_t rx_packets; /* Number of received packets. */
    uint64_t tx_packets; /* Number of transmitted packets. */
    uint64_t rx_bytes; /* Number of received bytes. */
    uint64_t tx_bytes; /* Number of transmitted bytes. */
    uint64_t rx_dropped; /* Number of packets dropped by RX. */
    uint64_t tx_dropped; /* Number of packets dropped by TX. */
    uint64_t rx_errors; /* Number of receive errors. This is a super-set
                            of more specific receive errors and should be
                            greater than or equal to the sum of all
                            rx_*_err values. */
    uint64_t tx_errors; /* Number of transmit errors. This is a super-set
                            of more specific transmit errors and should be
                            greater than or equal to the sum of all
                            tx_*_err values (none currently defined.) */
    uint64_t rx_frame_err; /* Number of frame alignment errors. */
    uint64_t rx_over_err; /* Number of packets with RX overrun. */
    uint64_t rx_crc_err; /* Number of CRC errors. */
    uint64_t collisions; /* Number of collisions. */
    uint32_t duration_sec; /* Time port has been alive in seconds. */
    uint32_t duration_nsec; /* Time port has been alive in nanoseconds beyond
                                duration_sec. */
};
OFP_ASSERT(sizeof(struct ofp140_port_stats) == 112);

struct ofp140_queue_stats_request {
    uint32_t port_no; /* All ports if OFPP_ANY. */
    uint32_t queue_id; /* All queues if OFPQ_ALL. */
};
OFP_ASSERT(sizeof(struct ofp140_queue_stats_request) == 8);

struct ofp140_queue_stats {
    uint32_t port_no;
    uint32_t queue_id; /* Queue i.d */
    uint64_t tx_bytes; /* Number of transmitted bytes. */
    uint64_t tx_packets; /* Number of transmitted packets. */
    uint64_t tx_errors; /* Number of packets dropped due to overrun. */
    uint32_t duration_sec; /* Time queue has been alive in seconds. */
    uint32_t duration_nsec; /* Time queue has been alive in nanoseconds beyond
                                duration_sec. */
};
OFP_ASSERT(sizeof(struct ofp140_queue_stats) == 40);

/* Send packet (controller -> datapath). */
struct ofp140_packet_out {
    struct ofp_header header;
    uint32_t buffer_id; /* ID assigned by datapath (OFP_NO_BUFFER
                            if none). */
    uint32_t in_port; /* Packet's input port or OFPP_CONTROLLER. */
    uint16_t actions_len; /* Size of action array in bytes. */
    uint8_t pad[6];
    struct ofp_action_header actions[0]; /* Action list. */
    /* uint8_t data[0]; */ /* Packet data. The length is inferred
    from the length field in the header.
    (Only meaningful if buffer_id == -1.) */
};
OFP_ASSERT(sizeof(struct ofp140_packet_out) == 24);

/* Packet received on port (datapath -> controller). */
struct ofp140_packet_in {
    struct ofp_header header;
    uint32_t buffer_id; /* ID assigned by datapath. */
    uint16_t total_len; /* Full length of frame. */
    uint8_t reason; /* Reason packet is being sent (one of OFPR_*) */
    uint8_t table_id; /* ID of the table that was looked up */
    uint64_t cookie; /* Cookie of the flow entry that was looked up. */
    struct ofpx_match match; /* Packet metadata. Variable size. */
    /* Followed by:
    * - Exactly 2 all-zero padding bytes, then
    * - An Ethernet frame whose length is inferred from header.length.
    * The padding bytes preceding the Ethernet frame ensure that the IP
    * header (if any) following the Ethernet header is 32-bit aligned.
    */
    //uint8_t pad[2]; /* Align to 64 bit + 16 bit */
    //uint8_t data[0]; /* Ethernet frame */
};
OFP_ASSERT(sizeof(struct ofp140_packet_in) == 32);

/* Flow removed (datapath -> controller). */
struct ofp140_flow_removed {
    struct ofp_header header;
    uint64_t cookie; /* Opaque controller-issued identifier. */
    uint16_t priority; /* Priority level of flow entry. */
    uint8_t reason; /* One of OFPRR_*. */
    uint8_t table_id; /* ID of the table */
    uint32_t duration_sec; /* Time flow was alive in seconds. */
    uint32_t duration_nsec; /* Time flow was alive in nanoseconds beyond
                               duration_sec. */
    uint16_t idle_timeout; /* Idle timeout from original flow mod. */
    uint16_t hard_timeout; /* Hard timeout from original flow mod. */
    uint64_t packet_count;
    uint64_t byte_count;
    struct ofpx_match match; /* Description of fields. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp140_flow_removed) == 56);

/* A physical port has changed in the datapath */
struct ofp140_port_status {
    struct ofp_header header;
    uint8_t reason; /* One of OFPPR_*. */
    uint8_t pad[7]; /* Align to 64-bits. */
    struct ofp140_port desc;
};
OFP_ASSERT(sizeof(struct ofp140_port_status) == 56);

/* Query for port queue configuration. */
struct ofp140_queue_get_config_request {
    struct ofp_header header;
    uint32_t port; /* Port to be queried. Should refer
                      to a valid physical port (i.e. < OFPP_MAX),
                      or OFPP_ANY to request all configured
                      queues.*/
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp140_queue_get_config_request) == 16);

/* Queue configuration for a given port. */
struct ofp140_queue_get_config_reply {
    struct ofp_header header;
    uint32_t port;
    uint8_t pad[4];
    struct ofp_packet_queue queues[0]; /* List of configured queues. */
};
OFP_ASSERT(sizeof(struct ofp140_queue_get_config_reply) == 16);

/* Values for 'type' in ofp_error_message. These values are immutable: they
* will not change in future versions of the protocol (although new values may
* be added). */
enum ofp140_error_type {
    OFPET140_HELLO_FAILED = 0, /* Hello protocol failed. */
    OFPET140_BAD_REQUEST = 1, /* Request was not understood. */
    OFPET140_BAD_ACTION = 2, /* Error in action description. */
    OFPET140_BAD_INSTRUCTION = 3, /* Error in instruction list. */
    OFPET140_BAD_MATCH = 4, /* Error in match. */
    OFPET140_FLOW_MOD_FAILED = 5, /* Problem modifying flow entry. */
    OFPET140_GROUP_MOD_FAILED = 6, /* Problem modifying group entry. */
    OFPET140_PORT_MOD_FAILED = 7, /* Port mod request failed. */
    OFPET140_TABLE_MOD_FAILED = 8, /* Table mod request failed. */
    OFPET140_QUEUE_OP_FAILED = 9, /* Queue operation failed. */
    OFPET140_SWITCH_CONFIG_FAILED = 10, /* Switch config request failed. */
    OFPET140_ROLE_REQUEST_FAILED = 11, /* Controller Role request failed. */
    OFPET140_METER_MOD_FAILED = 12, /* Error in meter. */
    OFPET140_TABLE_FEATURES_FAILED = 13, /* Setting table features failed. */
    OFPET140_EXPERIMENTER = 0xffff /* Experimenter error messages. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_REQUEST. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp140_bad_request_code {
    OFPBRC140_BAD_VERSION = 0, /* ofp_header.version not supported. */
    OFPBRC140_BAD_TYPE = 1, /* ofp_header.type not supported. */
    OFPBRC140_BAD_MULTIPART = 2, /* ofp_multipart_request.type not supported. */
    OFPBRC140_BAD_EXPERIMENTER = 3, /* Experimenter id not supported
                                  * (in ofp_experimenter_header or
                                  * ofp_multipart_request or
                                  * ofp_multipart_reply). */
    OFPBRC140_BAD_EXP_TYPE = 4, /* Experimenter type not supported. */
    OFPBRC140_EPERM = 5, /* Permissions error. */
    OFPBRC140_BAD_LEN = 6, /* Wrong request length for type. */
    OFPBRC140_BUFFER_EMPTY = 7, /* Specified buffer has already been used. */
    OFPBRC140_BUFFER_UNKNOWN = 8, /* Specified buffer does not exist. */
    OFPBRC140_BAD_TABLE_ID = 9, /* Specified table-id invalid or does not
                              * exist. */
    OFPBRC140_IS_SLAVE = 10, /* Denied because controller is slave. */
    OFPBRC140_BAD_PORT = 11, /* Invalid port. */
    OFPBRC140_BAD_PACKET = 12, /* Invalid packet in packet-out. */
    OFPBRC140_MULTIPART_BUFFER_OVERFLOW = 13, /* ofp_multipart_request
                                              overflowed the assigned buffer. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_ACTION. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp140_bad_action_code {
    OFPBAC140_BAD_TYPE = 0, /* Unknown action type. */
    OFPBAC140_BAD_LEN = 1, /* Length problem in actions. */
    OFPBAC140_BAD_EXPERIMENTER = 2, /* Unknown experimenter id specified. */
    OFPBAC140_BAD_EXP_TYPE = 3, /* Unknown action for experimenter id. */
    OFPBAC140_BAD_OUT_PORT = 4, /* Problem validating output port. */
    OFPBAC140_BAD_ARGUMENT = 5, /* Bad action argument. */
    OFPBAC140_EPERM = 6, /* Permissions error. */
    OFPBAC140_TOO_MANY = 7, /* Can't handle this many actions. */
    OFPBAC140_BAD_QUEUE = 8, /* Problem validating output queue. */
    OFPBAC140_BAD_OUT_GROUP = 9, /* Invalid group id in forward action. */
    OFPBAC140_MATCH_INCONSISTENT = 10, /* Action can't apply for this match,
                                       or Set-Field missing prerequisite. */
    OFPBAC140_UNSUPPORTED_ORDER = 11, /* Action order is unsupported for the
                                      action list in an Apply-Actions instruction */
    OFPBAC140_BAD_TAG = 12, /* Actions uses an unsupported
                            tag/encap. */
    OFPBAC140_BAD_SET_TYPE = 13, /* Unsupported type in SET_FIELD action. */
    OFPBAC140_BAD_SET_LEN = 14, /* Length problem in SET_FIELD action. */
    OFPBAC140_BAD_SET_ARGUMENT = 15, /* Bad argument in SET_FIELD action. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_INSTRUCTION. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp140_bad_instruction_code {
    OFPBIC140_UNKNOWN_INST = 0, /* Unknown instruction. */
    OFPBIC140_UNSUP_INST = 1, /* Switch or table does not support the
                              instruction. */
    OFPBIC140_BAD_TABLE_ID = 2, /* Invalid Table-ID specified. */
    OFPBIC140_UNSUP_METADATA = 3, /* Metadata value unsupported by datapath. */
    OFPBIC140_UNSUP_METADATA_MASK = 4, /* Metadata mask value unsupported by
                                       datapath. */
    OFPBIC140_BAD_EXPERIMENTER = 5, /* Unknown experimenter id specified. */
    OFPBIC140_BAD_EXP_TYPE = 6, /* Unknown instruction for experimenter id. */
    OFPBIC140_BAD_LEN = 7, /* Length problem in instructions. */
    OFPBIC140_EPERM = 8, /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_MATCH. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp140_bad_match_code {
    OFPBMC140_BAD_TYPE = 0, /* Unsupported match type specified by the
                            match */
    OFPBMC140_BAD_LEN = 1, /* Length problem in match. */
    OFPBMC140_BAD_TAG = 2, /* Match uses an unsupported tag/encap. */
    OFPBMC140_BAD_DL_ADDR_MASK = 3, /* Unsupported datalink addr mask - switch
                                    does not support arbitrary datalink
                                    address mask. */
    OFPBMC140_BAD_NW_ADDR_MASK = 4, /* Unsupported network addr mask - switch
                                    does not support arbitrary network
                                    address mask. */
    OFPBMC140_BAD_WILDCARDS = 5, /* Unsupported combination of fields masked
                                 or omitted in the match. */
    OFPBMC140_BAD_FIELD = 6, /* Unsupported field type in the match. */
    OFPBMC140_BAD_VALUE = 7, /* Unsupported value in a match field. */
    OFPBMC140_BAD_MASK = 8, /* Unsupported mask specified in the match,
                            field is not dl-address or nw-address. */
    OFPBMC140_BAD_PREREQ = 9, /* A prerequisite was not met. */
    OFPBMC140_DUP_FIELD = 10, /* A field type was duplicated. */
    OFPBMC140_EPERM = 11, /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_FLOW_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp140_flow_mod_failed_code {
    OFPFMFC140_UNKNOWN = 0, /* Unspecified error. */
    OFPFMFC140_TABLE_FULL = 1, /* Flow not added because table was full. */
    OFPFMFC140_BAD_TABLE_ID = 2, /* Table does not exist */
    OFPFMFC140_OVERLAP = 3, /* Attempted to add overlapping flow with
                            CHECK_OVERLAP flag set. */
    OFPFMFC140_EPERM = 4, /* Permissions error. */
    OFPFMFC140_BAD_TIMEOUT = 5, /* Flow not added because of unsupported
                                idle/hard timeout. */
    OFPFMFC140_BAD_COMMAND = 6, /* Unsupported or unknown command. */
    OFPFMFC140_BAD_FLAGS = 7, /* Unsupported or unknown flags. */
};

/* ofp_error_msg 'code' values for OFPET_GROUP_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp140_group_mod_failed_code {
    OFPGMFC140_GROUP_EXISTS = 0, /* Group not added because a group ADD
                                 attempted to replace an
                                 already-present group. */
    OFPGMFC140_INVALID_GROUP = 1, /* Group not added because Group
                                  specified is invalid. */
    OFPGMFC140_WEIGHT_UNSUPPORTED = 2, /* Switch does not support unequal load
                                        sharing with select groups. */
    OFPGMFC140_OUT_OF_GROUPS = 3, /* The group table is full. */
    OFPGMFC140_OUT_OF_BUCKETS = 4, /* The maximum number of action buckets
                                   for a group has been exceeded. */
    OFPGMFC140_CHAINING_UNSUPPORTED = 5, /* Switch does not support groups that
                                         forward to groups. */
    OFPGMFC140_WATCH_UNSUPPORTED = 6, /* This group cannot watch the watch_port
                                      or watch_group specified. */
    OFPGMFC140_LOOP = 7, /* Group entry would cause a loop. */
    OFPGMFC140_UNKNOWN_GROUP = 8, /* Group not modified because a group
                                    MODIFY attempted to modify a
                                    non-existent group. */
    OFPGMFC140_CHAINED_GROUP = 9, /* Group not deleted because another
                                  group is forwarding to it. */
    OFPGMFC140_BAD_TYPE = 10, /* Unsupported or unknown group type. */
    OFPGMFC140_BAD_COMMAND = 11, /* Unsupported or unknown command. */
    OFPGMFC140_BAD_BUCKET = 12, /* Error in bucket. */
    OFPGMFC140_BAD_WATCH = 13, /* Error in watch port/group. */
    OFPGMFC140_EPERM = 14, /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_PORT_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp140_port_mod_failed_code {
    OFPPMFC140_BAD_PORT = 0, /* Specified port number does not exist. */
    OFPPMFC140_BAD_HW_ADDR = 1, /* Specified hardware address does not
                              * match the port number. */
    OFPPMFC140_BAD_CONFIG = 2, /* Specified config is invalid. */
    OFPPMFC140_BAD_ADVERTISE = 3, /* Specified advertise is invalid. */
    OFPPMFC140_EPERM = 4, /* Permissions error. */
};

/* ofp_error msg 'code' values for OFPET_QUEUE_OP_FAILED. 'data' contains
* at least the first 64 bytes of the failed request */
enum ofp140_queue_op_failed_code {
    OFPQOFC140_BAD_PORT = 0, /* Invalid port (or port does not exist). */
    OFPQOFC140_BAD_QUEUE = 1, /* Queue does not exist. */
    OFPQOFC140_EPERM = 2, /* Permissions error. */
};

/* OFPET_EXPERIMENTER: Error message (datapath -> controller). */
struct ofp140_error_experimenter_msg {
    struct ofp_header header;
    uint16_t type; /* OFPET_EXPERIMENTER. */
    uint16_t exp_type; /* Experimenter defined. */
    uint32_t experimenter; /* Experimenter ID which takes the same form
                              as in struct ofp_experimenter_header. */
    uint8_t data[0]; /* Variable-length data. Interpreted based
                        on the type and code. No padding. */
};
OFP_ASSERT(sizeof(struct ofp140_error_experimenter_msg) == 16);
#endif
