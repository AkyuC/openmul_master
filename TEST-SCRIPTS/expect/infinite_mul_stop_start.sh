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


while [ 1 ]
do
./cli-show-ha-state.sh $1 > out
strings out | grep -iw master > /dev/null
rm -rf out
if [ $? -eq 0 ]
then

echo -e "\nRestarting Master Controller\n"
cd ../../ >> /dev/null
./mul.sh start-ha standalone $2
cd - >> /dev/null
fi
sleep 15
done
