#!/bin/bash -f
## ARGS 0->dpid 1->range

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


if  [ $# -le 3 ] 
then
    echo -e "\nUsage : $0 <DPID> <number-of-items> <add-modify> <delete> \[cli-port\]\r\n"
    echo -e "DPID             :       Datapath ID\r\n"
    echo -e "number-of-items  :       Number of items to be added/modified\r\n"
    echo -e "Add-Modify       :       0 -No, 1 -Yes\r\n"
    echo -e "Delete           :       0 -No, 1 -Yes\r\n"
    exit 1
fi

if [ $# -eq 4 ] 
then
    cli_port=10000
    echo -e "Taking cli_port $cli_port as default.\r\n"
else
    cli_port=$5
fi
if [ $3 -eq 1 ]
then
    add=1
    del=0
    ./cli-1k-flow-add-del-ipv6.sh $1 $2 $add $del $cli_port
    sleep 25
    ./cli-1k-flow-add-del-ipv6-multi-actions.sh $1 $2 $add $del $cli_port
fi

if [ $4 -eq 1 ]
then
    add=0
    del=1
    ./cli-1k-flow-add-del-ipv6.sh $1 $2 $add $del $cli_port
fi
