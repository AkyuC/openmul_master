#!/usr/bin/python

from mul_nbapi import get_switch_all

switch_list = get_switch_all()

print '--------ACTIVE SWITCH DATAPATHS-----------'
for switch in switch_list:
    print '0x%lx' %switch.switch_id.datapath_id
print '------------------------------------------'
