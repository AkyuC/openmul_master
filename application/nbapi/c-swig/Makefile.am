ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS} 

pkgconfigdir=$(libdir)/pkgconfig

BUILT_SOURCES = mul_nbapi_wrap.c
SWIG_SOURCES = mul_nbapi.i
SWIG_DEPEND = mul_nbapi_statistics.h mul_nbapi_topology.h mul_nbapi_flow.h mul_nbapi_fabric.h mul_nbapi_meter.h mul_nbapi_path.h \
	      mul_nbapi_swig_helper.h $(top_srcdir)/common-libs/mul-lib/include//mul_app_interface.h \
	      $(top_srcdir)/common-libs/mul-lib/include/mul_fabric_servlet.h \
	      $(top_srcdir)/common-libs/mul-lib/include/makdi_servlet.h \
	      $(top_srcdir)/common-libs/mul-lib/include/mul_servlet.h \
	      $(top_srcdir)/common-libs/mul-lib/include/mul_tr_servlet.h \
	      $(top_srcdir)/common-libs/mul-lib/include/openflow-10.h \
	      $(top_srcdir)/common-libs/mul-lib/include/openflow-131.h \
          $(top_srcdir)/common-libs/mul-lib/include/openflow-140.h \
	      $(top_srcdir)/common-libs/mul-lib/include/mul_route.h


pkgpython_PYTHON = mul_nbapi.py
pkgpyexec_LTLIBRARIES = _mul_nbapi.la

LIB_GLIB = @LIB_GLIB@
LIB_EVENT = @LIB_EVENT@
GLIB_INCLUDE = @GLIB_INCLUDE@
LIBEVENT_INCLUDE = @LIBEVENT_INCLUDE@

INCLUDES = -I. -I$(top_srcdir)/common/ -I$(top_srcdir)/mul/ \
	   -I$(top_srcdir)/services/loadable/topo_routing/ \
	   -I$(top_srcdir)/application/fabric/ \
	   -I$(top_srcdir)/application/makdi/ \
	   -I$(top_srcdir)/common-libs/3rd-party/quagga-lib/include/ \
	   -I$(top_srcdir)/common-libs/mul-lib/include/ \
	   -I$(top_srcdir)/common-libs/util-linux/libuuid/src/ \
	   $(PYTHON_CPPFLAGS)

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

_mul_nbapi_la_CFLAGS = -DMUL_APP_V2_MLAPI -DSWIG_INFRA

_mul_nbapi_la_SOURCES = mul_nbapi_wrap.c $(SWIG_SOURCES) \
	       mul_nbapi_statistics.c \
	       mul_nbapi_topology.c \
	       mul_nbapi_flow.c \
	       mul_nbapi_meter.c \
	       mul_nbapi_fabric.c \
	       mul_nbapi_path.c \
	       mul_nbapi.c \
	       $(top_srcdir)/common/mul_app_main.c

LD_FLAGS= @LDFLAGS@ 

_mul_nbapi_la_LIBADD = \
		$(top_srcdir)/common-libs/mul-lib/.libs/libmulutil.la  \
		$(top_srcdir)/services/loadable/topo_routing/./.libs/libmultr.la \
		$(top_srcdir)/common-libs/util-linux/libuuid/.libs/libuuid.la \
		$(top_srcdir)/mul/./.libs/libmul.la $(top_srcdir)/application/makdi/libmakdi.la \
		$(top_srcdir)/application/fabric/libfab.la	\
		$(top_srcdir)/common-libs/3rd-party/quagga-lib/.libs/libcli.la \
		-levent -lcrypt -lcrypto -lrt -lssl

_mul_nbapi_la_LDFLAGS = $(LD_FLAGS) -module -lpthread -lglib-2.0 -lcurl

if !HAVE_EXT_GLIB
LD_FLAGS += -Wl,-rpath=$(LIB_GLIB) -L$(LIB_GLIB)
INCLUDES += -I$(GLIB_INCLUDE) -I$(GLIB_INCLUDE)/../
_mul_nbapi_la_LIBADD  += $(LIB_GLIB)/libglib-2.0.la
endif

if !HAVE_EXT_LIBEVENT
LD_FLAGS += -Wl,-rpath=$(LIB_EVENT) -L$(LIB_EVENT)
INCLUDES += -I$(LIBEVENT_INCLUDE)
endif

mul_nbapi_wrap.c : $(SWIG_SOURCES) $(SWIG_DEPEND)
		$(SWIG) $(AX_SWIG_PYTHON_OPT) $(INCLUDES) -o $@ $<
		./nbapi_autocopy.py

noinst_HEADERS = mul_nbapi.h mul_nbapi_common.h

clean-local:
	-rm -fr mul_nbapi_wrap.c mul_nbapi.py
