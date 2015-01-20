from mul_nbapi import get_switch_all
from mul_nbapi import get_switch_neighbor_all
from mul_nbapi import COFP_NEIGH_SWITCH
from mul_nbapi import add_del_fabric_port_tnid

#get all topology external

#add this to port_tnid with same tnid

switch_list = get_switch_all()
for sw in switch_list:
    dpid = sw.switch_id.datapath_id
    neigh_list = get_switch_neighbor_all(dpid)
    for nei in neigh_list:
	if nei.neigh_present & COFP_NEIGH_SWITCH != True:
 	    port = nei.port_no
	    add_del_fabric_port_tnid(	dpid,
					'01000000-0000-0000-0000-000000000001',
					'01000000-0000-0000-0000-000000000001',
					str(port),
					True)
