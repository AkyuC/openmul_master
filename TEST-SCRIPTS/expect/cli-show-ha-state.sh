#!/usr/bin/expect -f
## ARGS 0->cli_port

# Copyright (C) 2013-2014, OpenMUL foundation
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
set remote_port [lrange $argv 0 0]

if { [llength $argv] == 0} {
        send_user "\nUsage : $argv0 \[cli-port\]\r\n"
        set remote_port 10000
        send_user "Taking cli_port $remote_port as default.\r\n"
}
# Open a telnet session to a remote server, and wait for a username prompt.
spawn telnet localhost $remote_port
expect ">"
# Capture the results of the command into a variable. This can be displayed, or written to disk.
send "enable\r"
expect "#"
send "show ha-state\r"
expect "#"
send "exit\r"
expect eof
