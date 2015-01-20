
#ifndef __MUL_DRONE_H__
#define __MUL_DRONE_H__

#include "mul_common.h"
#include "mul_servlet.h"


/*Drone Context*/
typedef struct drone_struct {
    c_rw_lock_t   lock;
    mul_service_t *mul_service;
    mul_service_t *tr_service;
}drone_struct_t;

/*Information of neighbour switch*/
typedef struct drone_neigh_info{
    struct flow flow;
    uint64_t dpid;
    bool neigh_switch_present;
    bool send_neigh_switch;
}drone_neigh_info_t;

#endif
