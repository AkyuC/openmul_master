ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

pkgconfigdir=$(libdir)/pkgconfig

lib_LTLIBRARIES = libfab.la
bin_PROGRAMS = mulfab 

LIB_GLIB = @LIB_GLIB@
LIB_EVENT = @LIB_EVENT@
GLIB_INCLUDE = @GLIB_INCLUDE@
LIBEVENT_INCLUDE = @LIBEVENT_INCLUDE@

INCLUDES = -I. -I$(top_srcdir)/mul -I$(top_srcdir)/common/ \
           -I$(top_srcdir)/services/loadable/topo_routing/ \
           -I$(top_srcdir)/common-libs/3rd-party/derived-lib/include/ \
           -I$(top_srcdir)/common-libs/3rd-party/quagga-lib/include/ \
           -I$(top_srcdir)/common-libs/mul-lib/include/

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

mulfab_CFLAGS = -DMUL_APP_V2_MLAPI

if HAVE_MUL_VTY
mulfab_CFLAGS += -DMUL_APP_VTY
endif

libfab_la_SOURCES = \
            mul_fabric_servlet.c

mulfab_SOURCES = mul_fabric.c mul_fabric_host.c mul_fabric_vty.c  \
                mul_fabric_route.c mul_fabric_switches.c mul_fabric_pkt.c \
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

mulfab_LDADD = \
               $(top_srcdir)/common-libs/mul-lib/.libs/libmulutil.a  \
			   $(top_srcdir)/mul/./.libs/libmul.a \
               $(top_srcdir)/services/loadable/topo_routing/./.libs/libmultr.a -lrt \
               -lcrypto -lssl
if HAVE_MUL_VTY
mulfab_LDADD += $(top_srcdir)/common-libs/3rd-party/quagga-lib/.libs/libcli.a
endif

mulfab_LDFLAGS = $(LD_FLAGS) -lpthread -lglib-2.0 -levent -lcrypt 

noinst_HEADERS = mul_fabric_common.h mul_fabric_util.h mul_fabric.h
