/******************************************************************************
 * Copyright (c) 2010 Joey Degges
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *****************************************************************************/

#ifndef _LIBCCWRAP_H
#define _LIBCCWRAP_H

typedef struct _ccw_context * ccw_context;

typedef int ccw_int;
typedef unsigned int ccw_uint;
typedef char ccw_char;

#define CCW_SUCCESS          0
#define CCW_INVALID_VALUE   -1
#define CCW_INVALID_CONTEXT -2
#define CCW_OUT_OF_MEMORY   -3
#define CCW_COMPILE_ERROR   -4
#define CCW_LINK_ERROR      -5

/* create a new thread safe CCW context */
ccw_context ccw_new (void);

/* free a CCW context */
void ccw_delete (ccw_context context);

/* set output type. needs to be called before any compilation */
#define CCW_OUTPUT_MEMORY   0   /* output will be run in memory. currently the
                                 * only supported output type option */
ccw_int ccw_set_output_type (ccw_context context,
                             ccw_uint output_type);

/* add include path (-I) */
ccw_int ccw_add_include_path (ccw_context context,
                              const ccw_char *string_value,
                              ccw_uint string_size);

/* add library path (-L) */
ccw_int ccw_add_library_path (ccw_context context,
                              const ccw_char *string_value,
                              ccw_uint string_size);

/* add library to link with (-l) */
ccw_int ccw_add_library (ccw_context context,
                         const ccw_char *string_value,
                         ccw_uint string_size);

/* compiles a string, 'string_value', containing a C source. if string_value is
 * not null-terminated then 'string_size' must be used to indicate the size */
ccw_int ccw_compile_string (ccw_context context,
                            const ccw_char *string_value,
                            ccw_uint string_size);

/* return symbol value or NULL if not found. 'errcode' may give a more detailed
 * error message -- if it is set to NULL then no errcode will be set */ 
void *ccw_get_symbol (ccw_context context,
                      const ccw_char *kernel_name,
                      ccw_int *errcode);

#endif
