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
set length [llength $argv]
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
if { $add > 0} {
for {set i 1} {$i <= $range} {incr i 1} {
    send "of-group add switch $dpid group $i type select\r"
    expect "#"
    send "action-add push-vlan-header\r"
    expect "#"
    send "action-add set-vlan-id 100\r"
    expect "#"
    send "action-add set-nw-dscp 10\r"
    expect "#"
    send "action-add output 2\r"
    expect "#"
    send "group-act-vector weight 999\r"
    expect "#"
    send "group-act-vector-next\r"
    expect "#"
    send "group-act-vector weight 10\r"
    expect "#"
    send "action-add output 1\r"
    expect "#"
    send "commit-group\r"
    expect "#"
}
}
if { $del > 0} {
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
