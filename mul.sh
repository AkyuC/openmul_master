# !/bin/bash

if [ -L $0 ] ; then
    cwd=$(readlink $0)
else
    cwd=$0
fi
curr_dir=$(dirname $cwd)

cd $curr_dir

function cp-pylib-command {
    pushd ./application/nbapi/c-swig >> /dev/null
    ./copy.sh
    popd >> /dev/null
}

function init-command {
    sudo mkdir -p /etc/mul/
    sudo mkdir -p /etc/mul/config/
    sudo touch /etc/mul/config/mulcli.conf
}

function stop-command {
    sudo killall -9 mulcli > /dev/null 2>&1
    sudo killall -9 mull2sw > /dev/null 2>&1
    sudo killall -9 mycontroller > /dev/null 2>&1
    sudo killall -9 mulfab > /dev/null 2>&1
    sudo killall -9 prismapp > /dev/null 2>&1
    sudo killall -9 prismagent > /dev/null 2>&1
    sudo killall -9 mulconx > /dev/null 2>&1
    sudo killall -9 multr > /dev/null 2>&1
    sudo killall -9 mul > /dev/null 2>&1
    sudo killall -9 lt-mulcli > /dev/null 2>&1
    sudo killall -9 lt-mull2sw > /dev/null 2>&1
    sudo killall -9 lt-mycontroller > /dev/null 2>&1
    sudo killall -9 lt-mulfab > /dev/null 2>&1
    sudo killall -9 lt-prismapp > /dev/null 2>&1
    sudo killall -9 lt-prismagent > /dev/null 2>&1
    sudo killall -9 lt-multr > /dev/null 2>&1
    sudo killall -9 lt-mulconx > /dev/null 2>&1
    sudo killall -9 lt-mul > /dev/null 2>&1
    source pythonpath.sh
    pushd  $curr_dir/application/nbapi/py-tornado/ >> /dev/null
    sudo PYTHONPATH=$PYTHONPATH ./mulnbapi stop > /dev/null 2>&1
    popd >> /dev/null
    #pushd  $curr_dir/application/nbapi/py-tornado-prism/ >> /dev/null
    #sudo PYTHONPATH=$PYTHONPATH ./prism_callback.py stop > /dev/null 2>&1
    #popd >> /dev/null

#    pid=`sudo ps -ef | grep "python" | grep "prism" | cut -b 9-16` 
#    sudo kill -9 $pid > /dev/null 2>&1
#    pid=`sudo ps -ef | grep "python" | grep "mulnbapi" | cut -b 9-16`
#    sudo kill -9 $pid > /dev/null 2>&1
    echo "OpenMUL is stopped..."
}

function start-command {
init-command
stop-command
cp-pylib-command
sudo JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64 CATALINA_HOME=/opt/tomcat /opt/tomcat/bin/./startup.sh > /dev/null 2>&1
case "$1" in
"standalone")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -d
    popd >> /dev/null
    pushd  $curr_dir/services/loadable/topo_routing/ >> /dev/null
    sudo ./multr -d -V 8000
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000  -d
    popd >> /dev/null
    source pythonpath.sh
    pushd  $curr_dir/application/nbapi/py-tornado/ >> /dev/null
    sudo PYTHONPATH=$PYTHONPATH ./mulnbapi start > /dev/null 2>&1
    popd >> /dev/null
    echo "OpenMUL standalone mode is running.."
    ;;
"l2switch")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -d
    popd >> /dev/null
    pushd  $curr_dir/application/l2switch/ >> /dev/null
    sudo ./mull2sw -V 6000 -d
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000  -d
    popd >> /dev/null
    source pythonpath.sh
    pushd  $curr_dir/application/nbapi/py-tornado/ >> /dev/null
    sudo PYTHONPATH=$PYTHONPATH ./mulnbapi start > /dev/null 2>&1
    popd >> /dev/null
    echo "OpenMUL l2switch mode is running.."
    ;;
"mycontroller")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -d
    popd >> /dev/null
    pushd  $curr_dir/application/my_controller/ >> /dev/null
    sudo ./mulmy_controller -V 6000
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000  -d
    popd >> /dev/null
    source pythonpath.sh
    pushd  $curr_dir/application/nbapi/py-tornado/ >> /dev/null
    sudo PYTHONPATH=$PYTHONPATH ./mulnbapi start > /dev/null 2>&1
    popd >> /dev/null
    echo "OpenMUL mycontroller mode is running.."
    ;;
"fabric")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -d
    popd >> /dev/null
    pushd  $curr_dir/services/loadable/topo_routing/ >> /dev/null
    sudo ./multr -d -V 8000
    popd >> /dev/null
    pushd  $curr_dir/application/fabric/ >> /dev/null
    sudo ./mulfab -d -V 9000
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000 -d
    popd >> /dev/null
    source pythonpath.sh
    pushd  $curr_dir/application/nbapi/py-tornado/ >> /dev/null
    sudo PYTHONPATH=$PYTHONPATH ./mulnbapi start > /dev/null 2>&1
    popd >> /dev/null
    echo "OpenMUL fabric mode is running.."
    ;;
"prism")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -P 6633 --no-strict-validation -d
    popd >> /dev/null
    pushd  $curr_dir/services/loadable/topo_routing/ >> /dev/null
    sudo ./multr -d -V 8000
    popd >> /dev/null
    sleep 5
    pushd  $curr_dir/services/loadable/conx/ >> /dev/null
    sudo ./mulconx -d -V 8500
    popd >> /dev/null
    pushd  $curr_dir/application/prism/app >> /dev/null
    sudo ./prismapp -d -V 9000 -D 4
    popd >> /dev/null
    pushd  $curr_dir/application/prism/agent >> /dev/null
    sudo ./prismagent -d -D 4
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000 -d
    popd >> /dev/null
    source pythonpath.sh
    pushd  $curr_dir/application/nbapi/py-tornado/ >> /dev/null
    sudo PYTHONPATH=$PYTHONPATH ./mulnbapi start > /dev/null 2>&1
    popd >> /dev/null
    #pushd  $curr_dir/application/nbapi/py-tornado-prism/ >> /dev/null
    #sudo PYTHONPATH=$PYTHONPATH ./prism_callback.py start > /dev/null 2>&1
    #popd >> /dev/null
    echo "OpenMUL prism mode is running.."
    ;;
"prism-fabric")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -P 6633 --no-strict-validation -d
    popd >> /dev/null
    pushd  $curr_dir/services/loadable/topo_routing/ >> /dev/null
    sudo ./multr -d -V 8000
    popd >> /dev/null
    sleep 5
    pushd  $curr_dir/services/loadable/conx/ >> /dev/null
    sudo ./mulconx -d -V 8500 -D 4
    popd >> /dev/null
    pushd  $curr_dir/application/prism/app >> /dev/null
    sudo ./prismapp -d -V 9000 -D 4
    popd >> /dev/null
    pushd  $curr_dir/application/prism/agent >> /dev/null
    sudo ./prismagent -d -D 4
    popd >> /dev/null
    pushd  $curr_dir/application/fabric/ >> /dev/null
    sudo ./mulfab -d -V 9500
    popd >> /dev/null
    sleep 2;
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000 -d
    popd >> /dev/null
    source pythonpath.sh
    pushd  $curr_dir/application/nbapi/py-tornado/ >> /dev/null
    sudo PYTHONPATH=$PYTHONPATH ./mulnbapi start > /dev/null 2>&1
    popd >> /dev/null
    #pushd  $curr_dir/application/nbapi/py-tornado-prism/ >> /dev/null
    #sudo PYTHONPATH=$PYTHONPATH ./prism_callback.py start > /dev/null 2>&1
    #popd >> /dev/null

    echo "OpenMUL prism-fabric mode is running.."
    ;;

*) echo "unknown commmand $1"
    usage mul_startup.sh
esac
}

function start-ha-command {
init-command
stop-command
cp-pylib-command
case "$1" in
"standalone")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -d -H $2
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000 -d
    popd >> /dev/null
    echo "OpenMUL standalone HA mode is running.."
    ;;
"l2switch")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -d -H $2
    popd >> /dev/null
    pushd  $curr_dir/application/l2switch/ >> /dev/null
    sudo ./mull2sw -V 6000 -d
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000  -d
    popd >> /dev/null
    echo "OpenMUL l2switch mode is running.."
    ;;
"fabric")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -d -H $2
    popd >> /dev/null
    pushd  $curr_dir/services/loadable/topo_routing/ >> /dev/null
    sudo ./multr -d -V 8000
    popd >> /dev/null
    pushd  $curr_dir/application/fabric/ >> /dev/null
    sudo ./mulfab -d -V 9000 -H $2
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000 -d
    popd >> /dev/null

    echo "OpenMUL fabric mode is running.."
    ;;
*) echo "unknown commmand $1"
    usage mul_startup.sh
esac
}

function usage {
    echo "Usage :"
    echo "$1 init"
    echo "$1 start standalone"
    echo "$1 start mycontroller"
    echo "$1 start l2switch"
    echo "$1 start fabric"
    echo "$1 start prism"
    echo "$1 start prism-fabric"
    echo "$1 start-ha l2switch <HA-IPaddr>"
    echo "$1 start-ha fabric <HA-IPaddr>"
    echo "$1 stop"
}

if [ $# -lt 1 ]
then
    usage $0 
  exit
fi

echo "[MUL startup script]"

case "$1" in
"init")
    init-command
    ;;
"start")
    start-command $2
    ;;
"start-ha")
    if [ $# -lt 3 ]
    then
        usage $0
        exit
    fi
    start-ha-command $2 $3
    ;;
"stop")
    stop-command
        ;;
*) echo "unknown command"
    usage $0
   ;;
esac
