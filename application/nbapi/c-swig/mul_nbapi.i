%module mul_nbapi

%{
#define SWIG_FILE_WITH_INIT
#include "mul_common.h"
#include "mul_nbapi_common.h"
#include "mul_nbapi.h"
#include "mul_nbapi_topology.h"
#include "mul_nbapi_init.h"
#include "mul_nbapi_flow.h"
#include "mul_nbapi_meter.h"
#include "mul_nbapi_path.h"
#include "mul_nbapi_statistics.h"
#include "mul_nbapi_fabric.h"
#include "glib.h"
#include "mul_route.h"
#include "uuid.h"

int nbapi_init(int argc, char **argv);

%}

%init %{
    nbapi_worker_entry();
%}

%include "stdint.i"

%include "openflow-common.h"
%include "openflow-10.h"
%include "openflow-131.h"
%include "openflow-140.h"
%include "mul_of_msg.h"
%include "mul_app_interface.h"
%include "mul_app_infra.h"
%include "mul_nbapi_swig_helper.h"
%include "mul_route.h"

%include "mul_nbapi_topology.h"
%include "mul_nbapi_flow.h"
%include "mul_nbapi_meter.h"
%include "mul_nbapi_fabric.h"
%include "mul_nbapi_path.h"
%include "mul_nbapi_statistics.h"
%include "uuid.h"
