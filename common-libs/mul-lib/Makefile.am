INCLUDES =  -I./include -I$(top_srcdir)/common -I$(top_srcdir)/common-libs/3rd-party/quagga-lib/include
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

lib_LTLIBRARIES = libmulutil.la

libmulutil_la_CFLAGS = -DMUL_APP_V2_MLAPI

if HAVE_MUL_VTY
libmulutil_la_CFLAGS += -DMUL_APP_VTY
endif


libmulutil_la_SOURCES = \
    ./src/cbuf.c ./src/c_util.c ./src/idx_pool.c ./src/clog.c \
    ./src/rlim.c ./src/random.c ./src/hash.c \
    ./src/mul_service.c ./src/mul_of_msg.c ./src/mul_app_infra.c \
    ./src/dhparams.c ./src/fsync.c ./src/tuntap.c ./src/mul_patricia.c

pkginclude_HEADERS = \
    ./include/atomic.h  ./include/cbuf.h  ./include/compiler.h  ./include/c_util.h  \
    ./include/idx_pool.h  ./include/lock.h ./include/clog.h ./include/rlim.h ./include/hash.h \
    ./include/igmp.h ./include/mul_app_infra.h  ./include/mul_app_interface.h \
    ./include/mul_app_main.h  ./include/mul_common.h  ./include/mul_of_msg.h  \
    ./include/mul_packet.h  ./include/mul_services.h ./include/packets.h  \
    ./include/random.h ./include/mul_route.h \
    ./include/mul_route_apsp.h ./include/mul_tr_servlet.h \
    ./include/mul_servlet.h ./include/mul_fabric_servlet.h \
    ./include/openflow-131.h ./include/openflow-10.h \
    ./include/openflow-140.h \
    ./include/openflow-common.h ./include/xtoxll.h ./include/mul_vty.h \
    ./include/fsync.h ./include/tuntap.h ./include/mul_patricia.h
