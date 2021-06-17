#!/usr/bin/env bash

# Mininet install script for Ubuntu (and Debian Lenny)
# Brandon Heller (brandonh@stanford.edu)
# Modified for OpenMUL by Dipjyoti Saikia & Saurabh Jain

# Fail on error
set -e

# Fail on unset var usage
set -o nounset

# Get directory containing mininet folder
OPENMUL_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd -P )"

# Set up build directory, which by default is the working directory
#  unless the working directory is a subdirectory of mininet, 
#  in which case we use the directory containing mininet
BUILD_DIR="$(pwd -P)"
case $BUILD_DIR in
  $OPENMUL_DIR/*) BUILD_DIR=$OPENMUL_DIR;; # currect directory is a subdirectory
  *) BUILD_DIR=$BUILD_DIR;;
esac

# Attempt to identify Linux release

DIST=Unknown
RELEASE=Unknown
CODENAME=Unknown
ARCH=`uname -m`
if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi
if [ "$ARCH" = "i686" ]; then ARCH="i386"; fi

test -e /etc/debian_version && DIST="Debian"
grep Ubuntu /etc/lsb-release &> /dev/null && DIST="Ubuntu"
if [ "$DIST" = "Ubuntu" ] || [ "$DIST" = "Debian" ]; then
    install='sudo apt-get -y install'
    remove='sudo apt-get -y remove'
    pkginst='sudo dpkg -i'
    # Prereqs for this script
    if ! which lsb_release &> /dev/null; then
        $install lsb-release
    fi
fi
test -e /etc/fedora-release && DIST="Fedora"
if [ "$DIST" = "Fedora" ]; then
    install='sudo yum -y install'
    remove='sudo yum -y erase'
    pkginst='sudo rpm -ivh'
    # Prereqs for this script
    if ! which lsb_release &> /dev/null; then
        $install redhat-lsb-core
    fi
fi
if which lsb_release &> /dev/null; then
    DIST=`lsb_release -is`
    RELEASE=`lsb_release -rs`
    CODENAME=`lsb_release -cs`
fi
echo "Detected Linux distribution: $DIST $RELEASE $CODENAME $ARCH"

# Kernel params

KERNEL_NAME=`uname -r`
KERNEL_HEADERS=kernel-headers-${KERNEL_NAME}

if ! echo $DIST | egrep 'Ubuntu|Debian|Fedora'; then
    echo "Install.sh currently only supports Ubuntu, Debian and Fedora."
    exit 1
fi

# More distribution info
DIST_LC=`echo $DIST | tr [A-Z] [a-z]` # as lower case


# Determine whether version $1 >= version $2
# usage: if version_ge 1.20 1.2.3; then echo "true!"; fi
function version_ge {
    # sort -V sorts by *version number*
    latest=`printf "$1\n$2" | sort -V | tail -1`
    # If $1 is latest version, then $1 >= $2
    [ "$1" == "$latest" ]
}

# Install OpenMUL
function openmul {
    echo "Building OpenMUL Controller..."

    #cd $BUILD_DIR/
    #git clone https://github.com/openmul/openmul.git

    # Install MUL Controller deps:
    echo "Install Dependency of MUL Controller..."
    if [ "$DIST" = "Ubuntu" ] || [ "$DIST" = "Debian" ]; then
        $install flex bison build-essential expect g++-multilib \
                 tofrodos zlib1g-dev gawk libffi-dev gettext python python-all-dev \
                 swig libcurl4-gnutls-dev libglib2.0-dev libevent-dev libssl-dev autoconf libtool

        # $install --force-yes python-daemon

    elif [ "$DIST" = "Fedora" ]; then
        $install flex bison yumex expect \
                 tofrodos zlib-devel gawk libffi-devel gettext python python-devel \
                 swig curl-devel glib2-devel libevent-devel openssl-devel autoconf libtool

        $install python-daemon

    else
        echo "Distribution other than Ubuntu/Debian/Fedora..."
    fi

    # Build
    ./autogen.sh
    CFLAGS=`pkg-config --cflags glib-2.0` ./configure --with-vty=yes
    make
    pushd ./application/nbapi/c-swig >> /dev/null
    ./copy.sh
    popd >> /dev/null
    #sudo make install
}

# Install GUI
function gui {
    echo "Installing GUI..."

    # Pre-requisites
    # JDK
    #sudo wget --no-cookies --no-check-certificate --header \
    #"Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" \
    #"http://download.oracle.com/otn-pub/java/jdk/7u72-b14/jdk-7u72-linux-x64.tar.gz"

    #Install JDK
    #sudo tar -xvf jdk-7*.tar.gz
    #sudo mkdir /usr/lib/jvm
    #sudo mv ./jdk1.7* /usr/lib/jvm/jdk1.7.0
    #sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk1.7.0/bin/java" 1
    #sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk1.7.0/bin/javac" 1
    #sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/jdk1.7.0/bin/javaws" 1
    #sudo chmod a+x /usr/bin/java
    #sudo chmod a+x /usr/bin/javac
    #sudo chmod a+x /usr/bin/javaws
    sudo apt-get install openjdk-7-jdk

    #Install Tomcat
    sudo wget http://archive.apache.org/dist/tomcat/tomcat-8/v8.0.24/bin/apache-tomcat-8.0.24.tar.gz
    sudo tar -xvzf apache-tomcat-8*.tar.gz
    sudo mv ./apache-tomcat-8.0*/ /opt/tomcat

    sudo JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64 CATALINA_HOME=/opt/tomcat /opt/tomcat/bin/./startup.sh 

    pushd ./application/gui >> /dev/null
    sudo unzip ROOT.war -d ./ROOT 
    sudo rm -fr /opt/tomcat/webapps/ROOT
    sudo mv ROOT /opt/tomcat/webapps/
    popd >> /dev/null

    sudo JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64 CATALINA_HOME=/opt/tomcat /opt/tomcat/bin/./startup.sh
}


function usage {
    printf '\nUsage: %s [-aMG]\n\n' $(basename $0) >&2

    printf 'This install script attempts to install useful packages\n' >&2
    printf 'for OpenMUL.It should (hopefully) work on Ubuntu 11.10+\n' >&2
    printf 'If you run into trouble, try\n' >&2
    printf 'installing one thing at a time, and looking at the \n' >&2
    printf 'specific installation function in this script.\n\n' >&2

    printf 'options:\n' >&2
    printf -- ' -M: -installs MUL Controller\n' >&2
    printf -- ' -G: -installs GUI\n' >&2
    exit 2
}

if [ $# -eq 0 ]
then
    openmul
else
    while getopts 'aMG' OPTION
    do
      case $OPTION in
      a)    openmul;;
      M)    openmul;;
      G)    gui;;
      ?)    usage;;
      esac
    done
    shift $(($OPTIND - 1))
fi
