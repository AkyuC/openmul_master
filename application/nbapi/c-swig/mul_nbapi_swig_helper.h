/*
 * mul_nbapi_swig_helper.h: MUL Northbound API SWIG helper headers
 * Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com> 
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#ifndef __MUL_NBAPI_SWIG_HELPER_H__
#define __MUL_NBAPI_SWIG_HELPER_H__

#include "glib.h"

#define MUL_NBAPI_GSLIST_STRUCT(TYPE, STRUCT_NAME)  \
typedef struct mul_nbapi_swig_##TYPE##_list {       \
    GSList *array;                                  \
    size_t length;                                  \
} STRUCT_NAME


#ifdef SWIG

#define MUL_NBAPI_SWIG_TYPEMAP_GLIST_TO_PYLIST(TYPE, STRUCT_NAME)  \
    %typemap(out) STRUCT_NAME {                         \
        PyObject *new_pylist = PyList_New($1.length);   \
        GSList *temp_ptr;                               \
        int i = 0;                                      \
        if ($1.array) {                                 \
            temp_ptr = $1.array;                        \
            while (temp_ptr) {                          \
                PyObject *new_obj =                     \
                        SWIG_NewPointerObj(temp_ptr->data,      \
                                           SWIGTYPE_p_##TYPE##, \
                                           SWIG_POINTER_OWN);   \
                if (new_obj) {                              \
                    PyList_SetItem(new_pylist, i, new_obj); \
                }                                           \
                temp_ptr = temp_ptr->next;                  \
                i++;                                        \
            }                                               \
            g_slist_free($1.array);                         \
        }                                                   \
        $result = new_pylist;                               \
    }                                                        
#else /* !SWIG */

#define MUL_NBAPI_SWIG_TYPEMAP_GLIST_TO_PYLIST(TYPE,STRUCT_NAME)  

#endif

#define MUL_NBAPI_PYLIST_RETURN(TYPE,STRUCT_NAME)                \
        MUL_NBAPI_GSLIST_STRUCT(TYPE,STRUCT_NAME);               \
        MUL_NBAPI_SWIG_TYPEMAP_GLIST_TO_PYLIST(TYPE,STRUCT_NAME)

#endif



