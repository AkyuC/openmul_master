ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

pkgconfigdir=$(libdir)/pkgconfig

bin_PROGRAMS = mulmy_controller

LIB_GLIB = @LIB_GLIB@
LIB_EVENT = @LIB_EVENT@
GLIB_INCLUDE = @GLIB_INCLUDE@
LIBEVENT_INCLUDE = @LIBEVENT_INCLUDE@

INCLUDES = -I. -I$(top_srcdir)/mul -I$(top_srcdir)/common/ \
           -I$(top_srcdir)/services/loadable/topo_routing/ \
           -I$(top_srcdir)/common-libs/3rd-party/derived-lib/include/ \
           -I$(top_srcdir)/common-libs/3rd-party/quagga-lib/include/ \
           -I$(top_srcdir)/common-libs/mul-lib/include/ \
           -I$(top_srcdir)/common-libs/util-linux/libuuid/src/

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

mulmy_controller_CFLAGS = -DMUL_APP_V2_MLAPI

if HAVE_MUL_VTY
mulmy_controller_CFLAGS += -DMUL_APP_VTY
endif

mulmy_controller_SOURCES = my_controller.c tp_graph.c tp_route.c LLDP.c ARP.c heap.c redis_interface.c msg_udp.c\
                           $(top_srcdir)/common/mul_app_main.c

LD_FLAGS= @LDFLAGS@ 

if !HAVE_EXT_GLIB
LD_FLAGS += -Wl,-rpath=$(LIB_GLIB) -L$(LIB_GLIB)
INCLUDES += -I$(GLIB_INCLUDE) -I$(GLIB_INCLUDE)/../
endif

if !HAVE_EXT_LIBEVENT
LD_FLAGS += -Wl,-rpath=$(LIB_EVENT) -L$(LIB_EVENT)
INCLUDES += -I$(LIBEVENT_INCLUDE)
endif

mulmy_controller_LDADD = \
                $(top_srcdir)/common-libs/mul-lib/.libs/libmulutil.a  \
                $(top_srcdir)/mul/./.libs/libmul.a  \
                $(top_srcdir)/services/loadable/topo_routing/./.libs/libmultr.a -lrt \
                $(top_srcdir)/application/my_controller/hiredis/libhiredis.a \
                -lcrypto -lssl -lglib-2.0

if HAVE_MUL_VTY
mulmy_controller_LDADD += $(top_srcdir)/common-libs/3rd-party/quagga-lib/.libs/libcli.a
endif

mulmy_controller_LDFLAGS = $(LD_FLAGS) -lpthread -levent -lcrypt -lhiredis

noinst_HEADERS = my_controller.h uthash.h tp_graph.h tp_route.h LLDP.h ARP.h heap.h \
                 redis_interface.h hiredis.h read.h sds.h alloc.h msg_udp.h