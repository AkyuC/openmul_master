/*
 * openflow_131_.h: MUL openflow 1.3.1 definitions 
 *
 */
#ifndef __OPENFLOW_131_H__
#define __OPENFLOW_131_H__

#include "openflow-common.h"

enum ofp131_type {
    /* Immutable messages. */
    OFPT131_HELLO = 0,              /* Symmetric message */
    OFPT131_ERROR = 1,              /* Symmetric message */
    OFPT131_ECHO_REQUEST = 2,       /* Symmetric message */
    OFPT131_ECHO_REPLY = 3,         /* Symmetric message */
    OFPT131_EXPERIMENTER = 4,       /* Symmetric message */

    /* Switch configuration messages. */
    OFPT131_FEATURES_REQUEST = 5,   /* Controller/switch message */
    OFPT131_FEATURES_REPLY = 6,     /* Controller/switch message */
    OFPT131_GET_CONFIG_REQUEST = 7, /* Controller/switch message */
    OFPT131_GET_CONFIG_REPLY = 8,   /* Controller/switch message */
    OFPT131_SET_CONFIG = 9,         /* Controller/switch message */

    /* Asynchronous messages. */
    OFPT131_PACKET_IN = 10,         /* Async message */
    OFPT131_FLOW_REMOVED = 11,      /* Async message */
    OFPT131_PORT_STATUS = 12,       /* Async message */

    /* Controller command messages. */
    OFPT131_PACKET_OUT = 13,        /* Controller/switch message */
    OFPT131_FLOW_MOD = 14,          /* Controller/switch message */
    OFPT131_GROUP_MOD = 15,         /* Controller/switch message */
    OFPT131_PORT_MOD = 16,          /* Controller/switch message */
    OFPT131_TABLE_MOD = 17,         /* Controller/switch message */

    /* Multipart messages. */
    OFPT131_MULTIPART_REQUEST = 18, /* Controller/switch message */
    OFPT131_MULTIPART_REPLY = 19,   /* Controller/switch message */

    /* Barrier messages. */
    OFPT131_BARRIER_REQUEST = 20,   /* Controller/switch message */
    OFPT131_BARRIER_REPLY = 21,     /* Controller/switch message */

    /* Queue Configuration messages. */
    OFPT131_QUEUE_GET_CONFIG_REQUEST = 22,  /* Controller/switch message */
    OFPT131_QUEUE_GET_CONFIG_REPLY = 23,    /* Controller/switch message */

    /* Controller role change request messages. */
    OFPT131_ROLE_REQUEST = 24,      /* Controller/switch message */
    OFPT131_ROLE_REPLY = 25,        /* Controller/switch message */

    /* Asynchronous message configuration. */
    OFPT131_GET_ASYNC_REQUEST = 26, /* Controller/switch message */
    OFPT131_GET_ASYNC_REPLY = 27,   /* Controller/switch message */
    OFPT131_SET_ASYNC = 28,         /* Controller/switch message */

    /* Meters and rate limiters configuration messages. */
    OFPT131_METER_MOD = 29,         /* Controller/switch message */
};

/* Description of a port */
struct ofp131_port {
    uint32_t port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP_ETH_ALEN];
    uint8_t pad2[2];    /* Align to 64 bits. */
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */
    uint32_t config;    /* Bitmap of OFPPC_* flags. */
    uint32_t state;     /* Bitmap of OFPPS_* flags. */

    /* Bitmaps of OFPPF_* that describe features. All bits zeroed if
     * unsupported or unavailable. */
    uint32_t curr;       /* Current features. */
    uint32_t advertised; /* Features being advertised by the port. */
    uint32_t supported;  /* Features supported by the port. */
    uint32_t peer;       /* Features advertised by peer. */
    uint32_t curr_speed; /* Current port bitrate in kbps. */
    uint32_t max_speed;  /* Max port bitrate in kbps */
};
OFP_ASSERT(sizeof(struct ofp131_port) == 64);

/* Flags to indicate behavior of the physical port. These flags are
* used in ofp_port to describe the current configuration. They are
* used in the ofp_port_mod message to configure the port's behavior.
*/
enum ofp131_port_config {
    OFPPC131_PORT_DOWN = 1 << 0,   /* Port is administratively down. */
    OFPPC131_NO_RECV = 1 << 2,     /* Drop all packets received by port. */
    OFPPC131_NO_FWD = 1 << 5,      /* Drop packets forwarded to port. */
    OFPPC131_NO_PACKET_IN = 1 << 6 /* Do not send packet-in msgs for port. */
};


/* Current state of the physical port. These are not configurable from
* the controller.
*/
enum ofp131_port_state {
    OFPPS131_LINK_DOWN = 1 << 0, /* No physical link present. */
    OFPPS131_BLOCKED = 1 << 1, /* Port is blocked */
    OFPPS131_LIVE = 1 << 2, /* Live for Fast Failover Group. */
};

/* Port numbering. Ports are numbered starting from 1. */
enum ofp131_port_no {
    /* Maximum number of physical and logical switch ports. */
    OFPP131_MAX = 0xffffff00,
    /* Reserved OpenFlow Port (fake output "ports"). */
    OFPP131_IN_PORT = 0xfffffff8, /* Send the packet out the input port. This
                                  reserved port must be explicitly used
                                  in order to send back out of the input
                                  port. */
    OFPP131_TABLE = 0xfffffff9, /* Submit the packet to the first flow table
                                NB: This destination port can only be
                                used in packet-out messages. */
    OFPP131_NORMAL = 0xfffffffa, /* Process with normal L2/L3 switching. */
    OFPP131_FLOOD = 0xfffffffb, /* All physical ports in VLAN, except input
                                port and those blocked or link down. */
    OFPP131_ALL = 0xfffffffc, /* All physical ports except input port. */
    OFPP131_CONTROLLER = 0xfffffffd, /* Send to controller. */
    OFPP131_LOCAL = 0xfffffffe, /* Local openflow "port". */
    OFPP131_ANY = 0xffffffff /* Wildcard port used only for flow mod
                             (delete) and flow stats requests. Selects
                             all flows regardless of output port
                             (including flows with no output port). */
};

/* Features of ports available in a datapath. */
enum ofp131_port_features {
    OFPPF131_10MB_HD = 1 << 0, /* 10 Mb half-duplex rate support. */
    OFPPF131_10MB_FD = 1 << 1, /* 10 Mb full-duplex rate support. */
    OFPPF131_100MB_HD = 1 << 2, /* 100 Mb half-duplex rate support. */
    OFPPF131_100MB_FD = 1 << 3, /* 100 Mb full-duplex rate support. */
    OFPPF131_1GB_HD = 1 << 4, /* 1 Gb half-duplex rate support. */
    OFPPF131_1GB_FD = 1 << 5, /* 1 Gb full-duplex rate support. */
    OFPPF131_10GB_FD = 1 << 6, /* 10 Gb full-duplex rate support. */
    OFPPF131_40GB_FD = 1 << 7, /* 40 Gb full-duplex rate support. */
    OFPPF131_100GB_FD = 1 << 8, /* 100 Gb full-duplex rate support. */
    OFPPF131_1TB_FD = 1 << 9, /* 1 Tb full-duplex rate support. */
    OFPPF131_OTHER = 1 << 10, /* Other rate, not in the list. */
    OFPPF131_COPPER = 1 << 11, /* Copper medium. */
    OFPPF131_FIBER = 1 << 12, /* Fiber medium. */
    OFPPF131_AUTONEG = 1 << 13, /* Auto-negotiation. */
    OFPPF131_PAUSE = 1 << 14, /* Pause. */
    OFPPF131_PAUSE_ASYM = 1 << 15 /* Asymmetric pause. */
};

/* Full description for a queue. */
struct ofp131_packet_queue {
    uint32_t queue_id; /* id for the specific queue. */
    uint32_t port; /* Port this queue is attached to. */
    uint16_t len; /* Length in bytes of this queue desc. */
    uint8_t pad[6]; /* 64-bit alignment. */
    struct ofp_queue_prop_header properties[0]; /* List of properties. */
};
OFP_ASSERT(sizeof(struct ofp131_packet_queue) == 16);

/* Experimenter queue property description. */
struct ofp131_queue_prop_experimenter {
    struct ofp_queue_prop_header prop_header; /* prop: OFPQT_EXPERIMENTER, len: 16. */
    uint32_t experimenter; /* Experimenter ID which takes the same
                              form as in struct
                              ofp_experimenter_header. */
    uint8_t pad[4]; /* 64-bit alignment */
    uint8_t data[0]; /* Experimenter defined data. */
};
OFP_ASSERT(sizeof(struct ofp131_queue_prop_experimenter) == 16);

/* Header for OXM experimenter match fields. */
struct ofp131_oxm_experimenter_header {
    uint32_t oxm_header; /* oxm_class = OFPXMC_EXPERIMENTER */
    uint32_t experimenter; /* Experimenter ID which takes the same
                              form as in struct ofp_experimenter_header. */
};
OFP_ASSERT(sizeof(struct ofp131_oxm_experimenter_header) == 8);

enum ofp131_action_type {
    OFPAT131_OUTPUT = 0, /* Output to switch port. */
    OFPAT131_COPY_TTL_OUT = 11, /* Copy TTL "outwards" -- from next-to-outermost
                                    to outermost */
    OFPAT131_COPY_TTL_IN = 12, /* Copy TTL "inwards" -- from outermost to
                                    next-to-outermost */
    OFPAT131_MPLS_TTL = 15, /* MPLS TTL */
    OFPAT131_DEC_MPLS_TTL = 16, /* Decrement MPLS TTL */
    OFPAT131_PUSH_VLAN = 17, /* Push a new VLAN tag */
    OFPAT131_POP_VLAN = 18, /* Pop the outer VLAN tag */
    OFPAT131_PUSH_MPLS = 19, /* Push a new MPLS tag */
    OFPAT131_POP_MPLS = 20, /* Pop the outer MPLS tag */
    OFPAT131_SET_QUEUE = 21, /* Set queue id when outputting to a port */
    OFPAT131_GROUP = 22, /* Apply group. */
    OFPAT131_SET_NW_TTL = 23, /* IP TTL. */
    OFPAT131_DEC_NW_TTL = 24, /* Decrement IP TTL. */
    OFPAT131_SET_FIELD = 25, /* Set a header field using OXM TLV format. */
    OFPAT131_PUSH_PBB = 26, /* Push a new PBB service tag (I-TAG) */
    OFPAT131_POP_PBB = 27, /* Pop the outer PBB service tag (I-TAG) */
    OFPAT131_EXPERIMENTER = 0xffff
};

/* Action structure for OFPAT_OUTPUT, which sends packets out 'port'.
* When the 'port' is the OFPP_CONTROLLER, 'max_len' indicates the max
* number of bytes to send. A 'max_len' of zero means no bytes of the
* packet should be sent. A 'max_len' of OFPCML_NO_BUFFER means that
* the packet is not buffered and the complete packet is to be sent to
* the controller. */
struct ofp131_action_output {
    uint16_t type; /* OFPAT_OUTPUT. */
    uint16_t len; /* Length is 16. */
    uint32_t port; /* Output port. */
    uint16_t max_len; /* Max length to send to controller. */
    uint8_t pad[6]; /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp131_action_output) == 16);

/* OFPAT_SET_QUEUE action struct: send packets to given queue on port. */
struct ofp131_action_set_queue {
    uint16_t type; /* OFPAT_SET_QUEUE. */
    uint16_t len; /* Len is 8. */
    uint32_t queue_id; /* Queue id for the packets. */
};
OFP_ASSERT(sizeof(struct ofp131_action_set_queue) == 8);

/* Switch features. */
struct ofp131_switch_features {
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
OFP_ASSERT(sizeof(struct ofp131_switch_features) == 32);

/* Capabilities supported by the datapath. */
enum ofp131_capabilities {
    OFPC131_FLOW_STATS = 1 << 0, /* Flow statistics. */
    OFPC131_TABLE_STATS = 1 << 1, /* Table statistics. */
    OFPC131_PORT_STATS = 1 << 2, /* Port statistics. */
    OFPC131_GROUP_STATS = 1 << 3, /* Group statistics. */
    OFPC131_IP_REASM = 1 << 5, /* Can reassemble IP fragments. */
    OFPC131_QUEUE_STATS = 1 << 6, /* Queue statistics. */
    OFPC131_PORT_BLOCKED = 1 << 8 /* Switch will block looping ports. */
};

/* Flow setup and teardown (controller -> datapath). */
struct ofp131_flow_mod {
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
OFP_ASSERT(sizeof(struct ofp131_flow_mod) == 56);

enum ofp131_flow_mod_flags {
    OFPFF131_SEND_FLOW_REM = OFPFF_SEND_FLOW_REM, /* Send flow removed message when flow
                                                   * expires or is deleted. */
    OFPFF131_CHECK_OVERLAP = OFPFF_CHECK_OVERLAP, /* Check for overlapping entries first. */
    OFPFF131_RESET_COUNTS = 1 << 2, /* Reset flow packet and byte counts. */
    OFPFF131_NO_PKT_COUNTS = 1 << 3, /* Don't keep track of packet count. */
    OFPFF131_NO_BYT_COUNTS = 1 << 4, /* Don't keep track of byte count. */
};

/* Modify behavior of the physical port */
struct ofp131_port_mod {
    struct ofp_header header;
    uint32_t port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP_ETH_ALEN]; /* The hardware address is not
                                      configurable. This is used to
                                      sanity-check the request, so it must
                                      be the same as returned in an
                                      ofp_port struct. */
    uint8_t pad2[2]; /* Pad to 64 bits. */
    uint32_t config; /* Bitmap of OFPPC131_* flags. */
    uint32_t mask; /* Bitmap of OFPPC131_* flags to be changed. */
    uint32_t advertise; /* Bitmap of OFPPF131_*. Zero all bits to prevent
                          any action taking place. */
    uint8_t pad3[4]; /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp131_port_mod) == 40);

/* Body for ofp_multipart_request of type OFPMP_FLOW. */
struct ofp131_flow_stats_request {
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
OFP_ASSERT(sizeof(struct ofp131_flow_stats_request) == 40);

/* Body of reply to OFPMP_FLOW request. */
struct ofp131_flow_stats {
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
OFP_ASSERT(sizeof(struct ofp131_flow_stats) == 56);

/* Body for ofp_multipart_request of type OFPMP_AGGREGATE. */
struct ofp131_aggregate_stats_request {
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
OFP_ASSERT(sizeof(struct ofp131_aggregate_stats_request) == 40);

/* Body of reply to OFPMP_TABLE request. */
struct ofp131_table_stats {
    uint8_t table_id; /* Identifier of table. Lower numbered tables
                    are consulted first. */
    uint8_t pad[3]; /* Align to 32-bits. */
    uint32_t active_count; /* Number of active entries. */
    uint64_t lookup_count; /* Number of packets looked up in table. */
    uint64_t matched_count; /* Number of packets that hit table. */
};
OFP_ASSERT(sizeof(struct ofp131_table_stats) == 24);

/* Body for ofp_multipart_request of type OFPMP_PORT. */
struct ofp131_port_stats_request {
    uint32_t port_no; /* OFPMP_PORT message must request statistics
                       * either for a single port (specified in
                       * port_no) or for all ports (if port_no ==
                       * OFPP_ANY). */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp131_port_stats_request) == 8);

/* Body of reply to OFPMP_PORT request. If a counter is unsupported, set
* the field to all ones. */
struct ofp131_port_stats {
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
OFP_ASSERT(sizeof(struct ofp131_port_stats) == 112);

struct ofp131_queue_stats_request {
    uint32_t port_no; /* All ports if OFPP_ANY. */
    uint32_t queue_id; /* All queues if OFPQ_ALL. */
};
OFP_ASSERT(sizeof(struct ofp131_queue_stats_request) == 8);

struct ofp131_queue_stats {
    uint32_t port_no;
    uint32_t queue_id; /* Queue i.d */
    uint64_t tx_bytes; /* Number of transmitted bytes. */
    uint64_t tx_packets; /* Number of transmitted packets. */
    uint64_t tx_errors; /* Number of packets dropped due to overrun. */
    uint32_t duration_sec; /* Time queue has been alive in seconds. */
    uint32_t duration_nsec; /* Time queue has been alive in nanoseconds beyond
                                duration_sec. */
};
OFP_ASSERT(sizeof(struct ofp131_queue_stats) == 40);

/* Send packet (controller -> datapath). */
struct ofp131_packet_out {
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
OFP_ASSERT(sizeof(struct ofp131_packet_out) == 24);

/* Packet received on port (datapath -> controller). */
struct ofp131_packet_in {
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
OFP_ASSERT(sizeof(struct ofp131_packet_in) == 32);

/* Flow removed (datapath -> controller). */
struct ofp131_flow_removed {
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
OFP_ASSERT(sizeof(struct ofp131_flow_removed) == 56);

/* A physical port has changed in the datapath */
struct ofp131_port_status {
    struct ofp_header header;
    uint8_t reason; /* One of OFPPR_*. */
    uint8_t pad[7]; /* Align to 64-bits. */
    struct ofp131_port desc;
};
OFP_ASSERT(sizeof(struct ofp131_port_status) == 80);

/* Query for port queue configuration. */
struct ofp131_queue_get_config_request {
    struct ofp_header header;
    uint32_t port; /* Port to be queried. Should refer
                      to a valid physical port (i.e. < OFPP_MAX),
                      or OFPP_ANY to request all configured
                      queues.*/
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp131_queue_get_config_request) == 16);

/* Queue configuration for a given port. */
struct ofp131_queue_get_config_reply {
    struct ofp_header header;
    uint32_t port;
    uint8_t pad[4];
    struct ofp_packet_queue queues[0]; /* List of configured queues. */
};
OFP_ASSERT(sizeof(struct ofp131_queue_get_config_reply) == 16);

/* Values for 'type' in ofp_error_message. These values are immutable: they
* will not change in future versions of the protocol (although new values may
* be added). */
enum ofp131_error_type {
    OFPET131_HELLO_FAILED = 0, /* Hello protocol failed. */
    OFPET131_BAD_REQUEST = 1, /* Request was not understood. */
    OFPET131_BAD_ACTION = 2, /* Error in action description. */
    OFPET131_BAD_INSTRUCTION = 3, /* Error in instruction list. */
    OFPET131_BAD_MATCH = 4, /* Error in match. */
    OFPET131_FLOW_MOD_FAILED = 5, /* Problem modifying flow entry. */
    OFPET131_GROUP_MOD_FAILED = 6, /* Problem modifying group entry. */
    OFPET131_PORT_MOD_FAILED = 7, /* Port mod request failed. */
    OFPET131_TABLE_MOD_FAILED = 8, /* Table mod request failed. */
    OFPET131_QUEUE_OP_FAILED = 9, /* Queue operation failed. */
    OFPET131_SWITCH_CONFIG_FAILED = 10, /* Switch config request failed. */
    OFPET131_ROLE_REQUEST_FAILED = 11, /* Controller Role request failed. */
    OFPET131_METER_MOD_FAILED = 12, /* Error in meter. */
    OFPET131_TABLE_FEATURES_FAILED = 13, /* Setting table features failed. */
    OFPET131_EXPERIMENTER = 0xffff /* Experimenter error messages. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_REQUEST. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp131_bad_request_code {
    OFPBRC131_BAD_VERSION = 0, /* ofp_header.version not supported. */
    OFPBRC131_BAD_TYPE = 1, /* ofp_header.type not supported. */
    OFPBRC131_BAD_MULTIPART = 2, /* ofp_multipart_request.type not supported. */
    OFPBRC131_BAD_EXPERIMENTER = 3, /* Experimenter id not supported
                                  * (in ofp_experimenter_header or
                                  * ofp_multipart_request or
                                  * ofp_multipart_reply). */
    OFPBRC131_BAD_EXP_TYPE = 4, /* Experimenter type not supported. */
    OFPBRC131_EPERM = 5, /* Permissions error. */
    OFPBRC131_BAD_LEN = 6, /* Wrong request length for type. */
    OFPBRC131_BUFFER_EMPTY = 7, /* Specified buffer has already been used. */
    OFPBRC131_BUFFER_UNKNOWN = 8, /* Specified buffer does not exist. */
    OFPBRC131_BAD_TABLE_ID = 9, /* Specified table-id invalid or does not
                              * exist. */
    OFPBRC131_IS_SLAVE = 10, /* Denied because controller is slave. */
    OFPBRC131_BAD_PORT = 11, /* Invalid port. */
    OFPBRC131_BAD_PACKET = 12, /* Invalid packet in packet-out. */
    OFPBRC131_MULTIPART_BUFFER_OVERFLOW = 13, /* ofp_multipart_request
                                              overflowed the assigned buffer. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_ACTION. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp131_bad_action_code {
    OFPBAC131_BAD_TYPE = 0, /* Unknown action type. */
    OFPBAC131_BAD_LEN = 1, /* Length problem in actions. */
    OFPBAC131_BAD_EXPERIMENTER = 2, /* Unknown experimenter id specified. */
    OFPBAC131_BAD_EXP_TYPE = 3, /* Unknown action for experimenter id. */
    OFPBAC131_BAD_OUT_PORT = 4, /* Problem validating output port. */
    OFPBAC131_BAD_ARGUMENT = 5, /* Bad action argument. */
    OFPBAC131_EPERM = 6, /* Permissions error. */
    OFPBAC131_TOO_MANY = 7, /* Can't handle this many actions. */
    OFPBAC131_BAD_QUEUE = 8, /* Problem validating output queue. */
    OFPBAC131_BAD_OUT_GROUP = 9, /* Invalid group id in forward action. */
    OFPBAC131_MATCH_INCONSISTENT = 10, /* Action can't apply for this match,
                                       or Set-Field missing prerequisite. */
    OFPBAC131_UNSUPPORTED_ORDER = 11, /* Action order is unsupported for the
                                      action list in an Apply-Actions instruction */
    OFPBAC131_BAD_TAG = 12, /* Actions uses an unsupported
                            tag/encap. */
    OFPBAC131_BAD_SET_TYPE = 13, /* Unsupported type in SET_FIELD action. */
    OFPBAC131_BAD_SET_LEN = 14, /* Length problem in SET_FIELD action. */
    OFPBAC131_BAD_SET_ARGUMENT = 15, /* Bad argument in SET_FIELD action. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_INSTRUCTION. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp131_bad_instruction_code {
    OFPBIC131_UNKNOWN_INST = 0, /* Unknown instruction. */
    OFPBIC131_UNSUP_INST = 1, /* Switch or table does not support the
                              instruction. */
    OFPBIC131_BAD_TABLE_ID = 2, /* Invalid Table-ID specified. */
    OFPBIC131_UNSUP_METADATA = 3, /* Metadata value unsupported by datapath. */
    OFPBIC131_UNSUP_METADATA_MASK = 4, /* Metadata mask value unsupported by
                                       datapath. */
    OFPBIC131_BAD_EXPERIMENTER = 5, /* Unknown experimenter id specified. */
    OFPBIC131_BAD_EXP_TYPE = 6, /* Unknown instruction for experimenter id. */
    OFPBIC131_BAD_LEN = 7, /* Length problem in instructions. */
    OFPBIC131_EPERM = 8, /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_MATCH. 'data' contains at least
* the first 64 bytes of the failed request. */
enum ofp131_bad_match_code {
    OFPBMC131_BAD_TYPE = 0, /* Unsupported match type specified by the
                            match */
    OFPBMC131_BAD_LEN = 1, /* Length problem in match. */
    OFPBMC131_BAD_TAG = 2, /* Match uses an unsupported tag/encap. */
    OFPBMC131_BAD_DL_ADDR_MASK = 3, /* Unsupported datalink addr mask - switch
                                    does not support arbitrary datalink
                                    address mask. */
    OFPBMC131_BAD_NW_ADDR_MASK = 4, /* Unsupported network addr mask - switch
                                    does not support arbitrary network
                                    address mask. */
    OFPBMC131_BAD_WILDCARDS = 5, /* Unsupported combination of fields masked
                                 or omitted in the match. */
    OFPBMC131_BAD_FIELD = 6, /* Unsupported field type in the match. */
    OFPBMC131_BAD_VALUE = 7, /* Unsupported value in a match field. */
    OFPBMC131_BAD_MASK = 8, /* Unsupported mask specified in the match,
                            field is not dl-address or nw-address. */
    OFPBMC131_BAD_PREREQ = 9, /* A prerequisite was not met. */
    OFPBMC131_DUP_FIELD = 10, /* A field type was duplicated. */
    OFPBMC131_EPERM = 11, /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_FLOW_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp131_flow_mod_failed_code {
    OFPFMFC131_UNKNOWN = 0, /* Unspecified error. */
    OFPFMFC131_TABLE_FULL = 1, /* Flow not added because table was full. */
    OFPFMFC131_BAD_TABLE_ID = 2, /* Table does not exist */
    OFPFMFC131_OVERLAP = 3, /* Attempted to add overlapping flow with
                            CHECK_OVERLAP flag set. */
    OFPFMFC131_EPERM = 4, /* Permissions error. */
    OFPFMFC131_BAD_TIMEOUT = 5, /* Flow not added because of unsupported
                                idle/hard timeout. */
    OFPFMFC131_BAD_COMMAND = 6, /* Unsupported or unknown command. */
    OFPFMFC131_BAD_FLAGS = 7, /* Unsupported or unknown flags. */
};

/* ofp_error_msg 'code' values for OFPET_GROUP_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp131_group_mod_failed_code {
    OFPGMFC131_GROUP_EXISTS = 0, /* Group not added because a group ADD
                                 attempted to replace an
                                 already-present group. */
    OFPGMFC131_INVALID_GROUP = 1, /* Group not added because Group
                                  specified is invalid. */
    OFPGMFC131_WEIGHT_UNSUPPORTED = 2, /* Switch does not support unequal load
                                        sharing with select groups. */
    OFPGMFC131_OUT_OF_GROUPS = 3, /* The group table is full. */
    OFPGMFC131_OUT_OF_BUCKETS = 4, /* The maximum number of action buckets
                                   for a group has been exceeded. */
    OFPGMFC131_CHAINING_UNSUPPORTED = 5, /* Switch does not support groups that
                                         forward to groups. */
    OFPGMFC131_WATCH_UNSUPPORTED = 6, /* This group cannot watch the watch_port
                                      or watch_group specified. */
    OFPGMFC131_LOOP = 7, /* Group entry would cause a loop. */
    OFPGMFC131_UNKNOWN_GROUP = 8, /* Group not modified because a group
                                    MODIFY attempted to modify a
                                    non-existent group. */
    OFPGMFC131_CHAINED_GROUP = 9, /* Group not deleted because another
                                  group is forwarding to it. */
    OFPGMFC131_BAD_TYPE = 10, /* Unsupported or unknown group type. */
    OFPGMFC131_BAD_COMMAND = 11, /* Unsupported or unknown command. */
    OFPGMFC131_BAD_BUCKET = 12, /* Error in bucket. */
    OFPGMFC131_BAD_WATCH = 13, /* Error in watch port/group. */
    OFPGMFC131_EPERM = 14, /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_PORT_MOD_FAILED. 'data' contains
* at least the first 64 bytes of the failed request. */
enum ofp131_port_mod_failed_code {
    OFPPMFC131_BAD_PORT = 0, /* Specified port number does not exist. */
    OFPPMFC131_BAD_HW_ADDR = 1, /* Specified hardware address does not
                              * match the port number. */
    OFPPMFC131_BAD_CONFIG = 2, /* Specified config is invalid. */
    OFPPMFC131_BAD_ADVERTISE = 3, /* Specified advertise is invalid. */
    OFPPMFC131_EPERM = 4, /* Permissions error. */
};

/* ofp_error msg 'code' values for OFPET_QUEUE_OP_FAILED. 'data' contains
* at least the first 64 bytes of the failed request */
enum ofp131_queue_op_failed_code {
    OFPQOFC131_BAD_PORT = 0, /* Invalid port (or port does not exist). */
    OFPQOFC131_BAD_QUEUE = 1, /* Queue does not exist. */
    OFPQOFC131_EPERM = 2, /* Permissions error. */
};

/* OFPET_EXPERIMENTER: Error message (datapath -> controller). */
struct ofp131_error_experimenter_msg {
    struct ofp_header header;
    uint16_t type; /* OFPET_EXPERIMENTER. */
    uint16_t exp_type; /* Experimenter defined. */
    uint32_t experimenter; /* Experimenter ID which takes the same form
                              as in struct ofp_experimenter_header. */
    uint8_t data[0]; /* Variable-length data. Interpreted based
                        on the type and code. No padding. */
};
OFP_ASSERT(sizeof(struct ofp131_error_experimenter_msg) == 16);
#endif
