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


log_user 0
set dpid [lrange $argv 0 0]
set item [lrange $argv 1 1]
set remote_port [lrange $argv 2 2]
if { [llength $argv] <= 1} {
    send_user "\nUsage : $argv0 <DPID> <Item> \[cli-port\]\r\n"
    send_user "DPID             :       Datapath ID\r\n"
    send_user "Item             :       flow|group|meter\r\n"
    exit 1
}

if { [llength $argv] == 2} {
        set remote_port 10000
        send_user "Taking cli_port $remote_port as default.\r\n"
}

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
send "show of-$item switch $dpid\r"
log_user 1
while {1} {
  expect {
 
    "*-"                         {send "\r\n"}
    "*-*- "                       {send "\r\n"}
    " *-*-More*-*- "                {send "\r\n"}
    "  "                        {send "\r\n"}
    "#"                         { break} 
  }
}
send "exit\r"
expect "#"
expect eof
