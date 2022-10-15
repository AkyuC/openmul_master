./autogen.sh
CFLAGS=`pkg-config --cflags glib-2.0` ./configure --with-vty=yes
make
ldconfig

