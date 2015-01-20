
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


if  [ $# -eq 0 ] 
then
    echo -e "\nUsage : $0 <DPID> \r\n"
    echo -e "DPID             :       Datapath ID\r\n"
    exit 1
fi

dpid=$1
cli_port=10000
range=1000
add=1
del=1
ZERO=0
total_test_case=0
passed_test_case=0
failed_test_case=0
present_items=0

declare -a test_case_flow=(cli-flow-add-del.sh cli-flow-add-del-multi-actions.sh cli-flow-add-del-stats-enabled.sh cli-flow-add-del-mpls.sh cli-flow-mod-test-ipv4.sh cli-flow-add-del-ipv6.sh cli-flow-add-del-ipv6-multi-actions.sh cli-flow-mod-test-ipv6.sh cli-flow-add-del-with-meter.sh cli-flow-add-del-with-group.sh cli-flow-add-del-with-meter-group.sh )
declare -a test_case_group=(cli-group-add-del-type-select.sh cli-group-add-del-type-indirect.sh cli-group-add-del-type-ff.sh cli-group-add-del-type-all.sh cli-group-add-del-stats-enabled.sh cli-group-add-del-multi-action.sh )
declare -a test_case_meter=(cli-meter-add-del.sh cli-meter-add-del-stats-enabled.sh cli-meter-add-del-multi-bands.sh cli-meter-mod-test.sh)

for item in flow group meter
do
test_suite=test_case_$item
eval test_suite=\( \${${test_suite}[@]} \)
for test_case in "${test_suite[@]}"
#for test_case in $test_case_flow
do

##################### Add Item #####################
add=1
del=0
total_test_case=`expr $total_test_case + 1`
echo -e "\n\nTEST CASE: $total_test_case\n"
echo -e "Executing $test_case\n"
. ./cli-count-flow-meter-group.sh $dpid $item $cli_port
present_items=$final

echo -e "Adding $range $item to switch $dpid\n"
./$test_case $dpid $range $add $del $cli_port

sleep 25

. ./cli-count-flow-meter-group.sh $dpid $item $cli_port

total_item=`expr $range + $present_items`

if [ $final -eq $total_item ]
then 
echo -e "Test case $total_test_case PASSED\n\n"
passed_test_case=`expr $passed_test_case + 1`
else
echo -e "Test case $total_test_case FAILED\n\n"
failed_test_case=`expr $failed_test_case + 1`
fi



############################ Delete Item #############################
add=0
del=1
total_test_case=`expr $total_test_case + 1`
echo -e "TEST CASE: $total_test_case\n"
echo -e "Executing $test_case\n"
echo "Existing "
. ./cli-count-flow-meter-group.sh $dpid $item $cli_port
present_items=$final
echo -e "Deleting $range $item from switch $dpid\n"
./$test_case $dpid $range $add $del $cli_port

sleep 2

. ./cli-count-flow-meter-group.sh $dpid $item $cli_port

total_item=`expr $present_items - $range`

if [ $final -eq $total_item ]
then 
echo -e "Test case $total_test_case PASSED\n"
passed_test_case=`expr $passed_test_case + 1`
else
echo -e "Test case $total_test_case FAILED\n"
failed_test_case=`expr $failed_test_case + 1`
fi

done
done

echo -e "*******************************************************************\n\n"
echo -e "Test Suite Result\n\n"
echo -e "*******************************************************************\n\n"
echo -e "Total Test cases  - \t\t$total_test_case\n"
echo -e "Test cases Passed - \t\t$passed_test_case\n"
echo -e "Test cases Failed - \t\t$failed_test_case\n"
echo -e "********************************************************************"
