/*
 * igmp.h - IGMP header defintions  
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
#ifndef __C_IGMP_H__
#define __C_IGMP_H__

struct igmphdr {
    uint8_t type;
    uint8_t code;      /* For newer IGMP */
    uint16_t csum;
    uint32_t group;
};

#define IGMPV3_MODE_IS_INCLUDE          1
#define IGMPV3_MODE_IS_EXCLUDE          2
#define IGMPV3_CHANGE_TO_INCLUDE        3
#define IGMPV3_CHANGE_TO_EXCLUDE        4
#define IGMPV3_ALLOW_NEW_SOURCES        5
#define IGMPV3_BLOCK_OLD_SOURCES        6
  
struct igmpv3_grec {
    uint8_t grec_type;
    uint8_t grec_auxwords;
    uint16_t grec_nsrcs;
    uint32_t grec_mca;
    uint32_t grec_src[0];
    uint32_t grec_auxdata[0];
};
  
struct igmpv3_report {
    uint8_t type;
    uint8_t resv1;
    uint16_t csum;
    uint16_t resv2;
    uint16_t ngrec;
    struct igmpv3_grec grec[0];
};

struct igmpv3_query {
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint32_t group;
    uint8_t qsr;
    uint8_t qqic;
    uint16_t nsrcs;
    uint32_t srcs[0];
};

#define IGMP_HOST_MEMBERSHIP_QUERY      0x11    /* RFC1112 */
#define IGMP_HOST_MEMBERSHIP_REPORT     0x12    /* RFC1112 */
#define IGMP_DVMRP                      0x13    /* DVMRP routing */
#define IGMP_PIM                        0x14    /* PIM routing */
#define IGMP_TRACE                      0x15
#define IGMPV2_HOST_MEMBERSHIP_REPORT   0x16    /* V2 version of 0x12 */
#define IGMP_HOST_LEAVE_MESSAGE         0x17
#define IGMPV3_HOST_MEMBERSHIP_REPORT   0x22    /* V3 version of 0x12 */

#endif 
