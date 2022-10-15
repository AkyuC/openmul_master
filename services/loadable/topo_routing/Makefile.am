ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

pkgconfigdir=$(libdir)/pkgconfig

lib_LTLIBRARIES = libmultr.la
bin_PROGRAMS = multr 

LIB_GLIB = @LIB_GLIB@
LIB_EVENT = @LIB_EVENT@
GLIB_INCLUDE = @GLIB_INCLUDE@
LIBEVENT_INCLUDE = @LIBEVENT_INCLUDE@

INCLUDES = -I. -I$(top_srcdir)/mul -I$(top_srcdir)/common/ \
           -I$(top_srcdir)/common-libs/3rd-party/derived-lib/include/ \
           -I$(top_srcdir)/common-libs/3rd-party/quagga-lib/include/ \
           -I$(top_srcdir)/common-libs/mul-lib/include/ \
           -I$(top_srcdir)/common-libs/util-linux/libuuid/src/

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

multr_CFLAGS = -DMUL_APP_V2_MLAPI

if HAVE_MUL_VTY
multr_CFLAGS += -DMUL_APP_VTY
endif

libmultr_la_SOURCES = \
        mul_route_servlet.c mul_tr_servlet.c
    

multr_SOURCES = mul_lldp.c mul_lldp_vty.c mul_lldp_hash.c \
                mul_lldp_common.c mul_lldp_debug.c \
                mul_route_apsp.c mul_route_vty.c \
                mul_tr.c mul_loop.c \
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

multr_LDADD = \
                $(top_srcdir)/common-libs/mul-lib/.libs/libmulutil.a \
                $(top_srcdir)/services/loadable/topo_routing/.libs/libmultr.a \
                -lcrypto -lssl

if HAVE_MUL_VTY
multr_LDADD += $(top_srcdir)/common-libs/3rd-party/quagga-lib/.libs/libcli.a
endif

multr_LDFLAGS = $(LD_FLAGS) -lpthread -lglib-2.0 -levent -lcrypt -lrt

noinst_HEADERS = mul_lldp_pkt.h mul_lldp_vty.h mul_lldp_hash.h mul_lldp_common.h mul_lldp_debug.h mul_tr.h mul_tr_common.h mul_loop.h
