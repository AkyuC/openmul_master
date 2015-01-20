#!/bin/bash -f

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


final=0
if  [ $# -le 1 ] 
then
    echo -e "\nUsage : $0 <DPID> <Item> \[cli-port\]\r\n"
    echo -e "DPID             :       Datapath ID\r\n"
    echo -e "Item             :       flow|group|meter\r\n"
    exit 1
fi

if [ $# -eq 2 ] 
then
        remort_port=10000
        echo -e "Taking cli_port $remort_port as default.\r\n"
fi

./cli-show-flow-meter-group.sh $1 $2 $remote_port > out
count=`strings out | grep -iwn $2 | wc -l`
one=1
final=`expr $count - $one`
rm -rf out
echo "Total Number of $2: $final"
