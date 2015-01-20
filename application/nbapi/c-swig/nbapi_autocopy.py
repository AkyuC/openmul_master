#!/usr/bin/python

import shutil
import os

#dPath = "../py-tornado/app/lib"

#os.system("mv .libs/_mul_nbapi.so ../py-tornado/app/lib/")
#os.system("mv .libs/_mul_nbapi.so.0 ../py-tornado/app/lib/")
#os.system("mv .libs/_mul_nbapi.so.0.0.0 ../py-tornado/app/lib/")
#os.system("mv mul_nbapi.py ../py-tornado/app/lib/")
SWIG_CLIENT_DATA_LEAK_CODE = """
  Py_XDECREF(data->newraw);
  Py_XDECREF(data->newargs);
  Py_XDECREF(data->destroy);
}"""


SWIG_CLIENT_DATA_SAFE_CODE = """ 
  Py_XDECREF(data->newraw);
  Py_XDECREF(data->newargs);
  Py_XDECREF(data->destroy);
  free(data);
}"""

SWIG_GLOBALS_LEAK_CODE = """
SWIGRUNTIME void
#ifdef SWIGPY_USE_CAPSULE
SWIG_Python_DestroyModule(PyObject *obj)
#else
SWIG_Python_DestroyModule(void *vptr)
#endif
{
#ifdef SWIGPY_USE_CAPSULE
  swig_module_info *swig_module = (swig_module_info *) PyCapsule_GetPointer(obj, SWIGPY_CAPSULE_NAME);
#else
  swig_module_info *swig_module = (swig_module_info *) vptr;
#endif
  swig_type_info **types = swig_module->types;
  size_t i;
  for (i =0; i < swig_module->size; ++i) {
    swig_type_info *ty = types[i];
    if (ty->owndata) {
      SwigPyClientData *data = (SwigPyClientData *) ty->clientdata;
      if (data) SwigPyClientData_Del(data);
    }
  }
  Py_DECREF(SWIG_This());
  swig_this = NULL;
}
"""

SWIG_GLOBALS_SAFE_CODE = """
SWIGINTERN PyObject * SWIG_globals(void);
SWIGRUNTIME void
#ifdef SWIGPY_USE_CAPSULE
SWIG_Python_DestroyModule(PyObject *obj)
#else
SWIG_Python_DestroyModule(void *vptr)
#endif
{   
#ifdef SWIGPY_USE_CAPSULE
  swig_module_info *swig_module = (swig_module_info *) PyCapsule_GetPointer(obj, SWIGPY_CAPSULE_NAME);
#else
  swig_module_info *swig_module = (swig_module_info *) vptr;
#endif
  swig_type_info **types = swig_module->types;
  size_t i;
  for (i =0; i < swig_module->size; ++i) {
    swig_type_info *ty = types[i];
    if (ty->owndata) {
      SwigPyClientData *data = (SwigPyClientData *) ty->clientdata;
      if (data) SwigPyClientData_Del(data);
    }
  }
  Py_DECREF(SWIG_globals());
  Py_DECREF(SWIG_This());
  swig_this = NULL;
}
"""

code = open("mul_nbapi_wrap.c").read()
code = code.replace(SWIG_CLIENT_DATA_LEAK_CODE, SWIG_CLIENT_DATA_SAFE_CODE)
code = code.replace(SWIG_GLOBALS_LEAK_CODE, SWIG_GLOBALS_SAFE_CODE)
open("mul_nbapi_wrap.c", "w").write(code)

