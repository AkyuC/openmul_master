#!/usr/bin/expect -f

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


log_user 1
set timeout 60
set remote_port [lrange $argv 0 0]
set dpid [lrange $argv 1 1]
#set my_user_id root
#set my_password 123qwe
# Assume $remote_server, $my_user_id, $my_password, and $my_command were read in earlier
# in the script.
# Open a telnet session to a remote server, and wait for a username prompt.
spawn telnet localhost $remote_port
set timeout 60 
#spawn scp ./$conf_file $my_user_id@$remote_server:/kulos/zebos/
#expect "password:"
#send "$my_password\r"
#wait
##sleep 5
#while {1} {
#  expect {
# 
#    "#"                          {break}
#    "The authenticity of host"   {send "yes\r"}
#    "password:"                  {send "$my_password\r"}
#    "*\]"                        {send "exit\r"}
#  }
#}
expect ">"
# Capture the results of the command into a variable. This can be displayed, or written to disk.
#set results $expect_out(buffer)
# Exit the telnet session, and wait for a special end-of-file character.
send "enable\r"
expect "#"
send "conf term\r"
expect "#"
send "do show of-switch all\r"
expect "#"
send "mul-conf\r"
expect "#"
send "of-flow add switch $dpid smac 00:01:02:03:04:05 dmac 00:01:02:03:04:06  eth-type 0x0800 vid * vlan-pcp * mpls-label * mpls-tc * mpls-bos * dip 1.1.1.1/32 sip 2.1.1.1/32 proto * tos * dport * sport * in-port * table 0\r"
expect "#"
send "instruction-write\r"
expect "#"
send "action-add output 2\r"
expect "#"
send "action-list-end\r"
expect "#"
send "commit\r"
expect "#"
send "exit\r"
expect "#"
send "exit\r"
expect "#"
send "exit\r"
expect eof
