#!/usr/bin/expect -f
## ARGS 0->dpid 1->range 2->add or not 3->delete or not

# Copyright (C) 2013-2014, OpenMUL Foundation 
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See
#    the
#    License for the specific language governing permissions and limitations
#    under the License.


log_user 0
set del 0
set dpid [lrange $argv 0 0]
set range  [lrange $argv 1 1]
set add  [lrange $argv 2 2]
set del  [lrange $argv 3 3]
set remote_port [lrange $argv 4 4]
if { [llength $argv] <= 3} {
    send_user "\nUsage : $argv0 <DPID> <number-of-items> <Add> <Delete> \[cli-port\]\r\n"
    send_user "DPID             :       Datapath ID\r\n"
    send_user "number-of-items  :       Number of items to be added\r\n"
    send_user "Add              :       0 -No, 1 -Yes\r\n"
    send_user "Delete           :       0 -No, 1 -Yes\r\n\n"
    exit 1
}

if { [llength $argv] == 4} {
        set remote_port 10000
        send_user "Taking cli_port $remote_port as default.\r\n"
}
# Open a telnet session to a remote server, and wait for a username prompt.
spawn telnet localhost $remote_port
expect ">"
# Capture the results of the command into a variable. This can be displayed, or written to disk.

send "enable\r"
expect "#"
send "conf term\r"
expect "#"
send "do show of-switch all\r"
expect "#"
send "mul-conf\r"
expect "#"

if { $add > 0 } {
    for {set i 1} {$i <= $range } {incr i 1} {
#Add groups
    send "of-group add switch $dpid group $i type all\r"
    expect "#"
    send "action-add output 2\r"
    expect "#"
    send "commit-group\r"
    expect "#"
}

#Add flows with meter and group
for {set i 0} {$i <= $range / 255 } {incr i 1} {
    for {set j 0} {$j < 255 && (($i * 255 + $j) < $range) } {incr j 1} {
    send "of-flow add switch $dpid smac 00:01:02:03:04:05 dmac 00:01:02:03:04:06  eth-type 0x0800 vid * vlan-pcp * mpls-label * mpls-tc * mpls-bos * dip 1.1.$i.$j/32 sip 2.1.$i.$j/32 proto * tos * dport * sport * in-port * table 0\r"
    expect "#"
    send "instruction-apply\r"
    expect "#"
    set group "[ expr $i * 255 + $j + 1]"
    send "action-add group-id $group\r"
    expect "#"
    send "action-list-end\r"
    expect "#"
    send "commit\r"
    expect "#"
    }
}
}
if { $del > 0} {
    for {set i 0} {$i <= $range / 255} {incr i 1} {
        for {set j 0} {$j < 255 && (($i * 255 + $j) < $range) } {incr j 1} {
        send "of-flow del switch $dpid smac 00:01:02:03:04:05 dmac 00:01:02:03:04:06  eth-type 0x0800 vid * vlan-pcp * mpls-label * mpls-tc * mpls-bos * dip 1.1.$i.$j/32 sip 2.1.$i.$j/32 proto * tos * dport * sport * in-port * table 0\r"
        expect "#"
        }
    }
#delete meters and groups after deleting flows
    for {set i 1} {$i <= $range} {incr i 1} {
        send "of-group del switch $dpid group $i\r"
        expect "#"
    }
}
send "exit\r"
expect "#"
send "exit\r"
expect "#"
send "exit\r"
expect eof
