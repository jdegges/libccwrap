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

#define _XOPEN_SOURCE
#define _ISOC99_SOURCE
#define _BSD_SOURCE

#include <stdlib.h>
#include <pthread.h>
#include <ltdl.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "libccwrap.h"

#define CCW_CC "cc"
#define CCW_SET_ERRCODE(code){if (NULL != errcode) *errcode = code;}

typedef void (*free_func_type)();

typedef struct _ccw_list {
    void **ptr;
    void *buf;
    ccw_uint used;
    ccw_uint size;
    ccw_uint references;
    pthread_mutex_t mutex;
    free_func_type free;
} _ccw_list;

typedef struct _ccw_list * ccw_list;

typedef struct _ccw_context {
    ccw_uint output_type;
    ccw_list include_path_list;
    ccw_list library_path_list;
    ccw_list library_list;
    ccw_list dl_list;
    ccw_uint references;
    pthread_mutex_t mutex;
} _ccw_context;

/* creates a new generic list. registers a free function to be used to delete
 * each element when ccw_delete_list() is called
 */
ccw_list ccw_new_list (free_func_type free_func)
{
    ccw_list list = calloc (1, sizeof(_ccw_list));

    if (NULL == list) {
        return NULL;
    }

    if (NULL == (list->ptr = calloc (1, sizeof(void*)))) {
        free (list);
        return NULL;
    }

    pthread_mutex_init (&list->mutex, NULL);
    list->references++;
    list->free = free_func;

    return list;
}

/* deletes a generic list */
void ccw_delete_list (ccw_list list)
{
    if (NULL == list) {
        return;
    }

    pthread_mutex_lock (&list->mutex);

    if (0 == --list->references) {
        while (list->used--) {
            list->free (list->ptr[list->used]);
        }
        free (list->ptr);

        if (NULL != list->buf) {
            free (list->buf);
        }

        pthread_mutex_unlock (&list->mutex);
        pthread_mutex_destroy (&list->mutex);
        free (list);

        return;
    }

    pthread_mutex_unlock (&list->mutex);
}

/* adds a pointer to a generic list */
ccw_int ccw_add_item (ccw_list list,
                      void *value)
{
    if (NULL == list
        || NULL == value)
    {
        return CCW_INVALID_VALUE;
    }

    pthread_mutex_lock (&list->mutex);
    if (list->size <= list->used+1) {
        if (0 == list->size) {
            list->size = 4;
        }
        if (NULL == (list->ptr = realloc (list->ptr,
                                          sizeof(void*)*list->size*2)))
        {
            pthread_mutex_unlock (&list->mutex);
            return CCW_OUT_OF_MEMORY;
        }
        list->size *= 2;
    }
    
    list->ptr[list->used++] = value;
    pthread_mutex_unlock (&list->mutex);
    return CCW_SUCCESS;
}

/* makes the assumption that each item in the list is a string. returns a
 * string that is the concatenation of all the items separated by 'separator'
 */
ccw_char *ccw_get_string_from_list (ccw_list list,
                                    const ccw_char *separator,
                                    ccw_uint *errcode)
{
    ccw_uint i;
    ccw_uint size = 0;
    ccw_char *buf = NULL;
    ccw_uint sep_len = 0;

    if (NULL == list) {
        return NULL;
    }

    if (NULL != separator) {
        sep_len = strlen (separator);
    }

    pthread_mutex_lock (&list->mutex);

    if (NULL != list->buf) {
        free (list->buf);
    }

    for (i = 0; i < list->used; i++) {
        int len;

        len = strlen (list->ptr[i]);
        fprintf (stderr, "len: %d\n", len);
        fprintf (stderr, "str: %s\n\n", (char*)list->ptr[i]);
        if (NULL == (buf = realloc (buf, sizeof(ccw_char)*(size+sep_len+len)))) {
            free (buf);
            CCW_SET_ERRCODE (CCW_OUT_OF_MEMORY);
            pthread_mutex_unlock (&list->mutex);
            return NULL;
        }

        if (NULL != separator) {
            memcpy (buf+size, separator, sep_len);
            size += sep_len;
        }

        memcpy (buf+size, list->ptr[i], len);
        size += len;
    }

    if (NULL == buf) {
        if (NULL == (buf = calloc (1, sizeof(ccw_char)))) {
            CCW_SET_ERRCODE (CCW_OUT_OF_MEMORY);
            pthread_mutex_unlock (&list->mutex);
            return NULL;
        }
    } else {
        if (NULL == (buf = realloc (buf, sizeof(ccw_char)*(size+1)))) {
            free (buf);
            CCW_SET_ERRCODE (CCW_OUT_OF_MEMORY);
            pthread_mutex_unlock (&list->mutex);
            return NULL;
        }
        buf[size] = '\0';
        size++;
    }

    list->buf = buf;
    pthread_mutex_unlock (&list->mutex);

    return buf;
}

/* deletes a ccw context struct */
void ccw_delete (ccw_context context)
{
    if (NULL == context) {
        return;
    }

    pthread_mutex_lock (&context->mutex);

    if (0 == --context->references) {
        ccw_delete_list (context->include_path_list);
        ccw_delete_list (context->library_path_list);
        ccw_delete_list (context->library_list);
        ccw_delete_list (context->dl_list);

        pthread_mutex_unlock (&context->mutex);
        pthread_mutex_destroy (&context->mutex);

        free (context);
        lt_dlexit ();
        return;
    }

    pthread_mutex_unlock (&context->mutex);
}

/* creates a new ccw context */
ccw_context ccw_new (void)
{
    ccw_context context;

    lt_dlinit ();

    if (NULL == (context = calloc (1, sizeof(_ccw_context)))) {
        return NULL;
    }

    if (NULL == (context->include_path_list = ccw_new_list (free))
        || NULL == (context->library_path_list = ccw_new_list (free))
        || NULL == (context->library_list = ccw_new_list (free))
        || NULL == (context->dl_list = ccw_new_list ((free_func_type)lt_dlclose)))
    {
        ccw_delete (context);
        return NULL;
    }

    pthread_mutex_init (&context->mutex, NULL);
    context->references++;
    context->output_type = CCW_OUTPUT_MEMORY;

    return context;
}

/* sets the output type of the context. currently only memory output is
 * implemented */
ccw_int ccw_set_output_type (ccw_context context,
                             ccw_uint output_type)
{
    if (NULL == context) {
        return CCW_INVALID_CONTEXT;
    }

    switch (output_type) {
        case CCW_OUTPUT_MEMORY:
            context->output_type = output_type;
        default:
            return CCW_INVALID_VALUE;
    }
    return CCW_SUCCESS;
}

/* adds an include path (-I). must be called BEFORE compile() */
ccw_int ccw_add_include_path (ccw_context context,
                              const ccw_char *string_value,
                              ccw_uint string_size)
{
    ccw_char *buf;

    if (NULL == context) {
        return CCW_INVALID_CONTEXT;
    }

    if (NULL == string_value) {
        return CCW_INVALID_VALUE;
    }

    if (0 == string_size) {
        string_size = strlen (string_value) + 1;
    } else {
        string_size++;
    }

    if (NULL == (buf = calloc (1, sizeof(ccw_char)*string_size))) {
        return CCW_OUT_OF_MEMORY;
    }

    memcpy (buf, string_value, string_size);

    return ccw_add_item (context->include_path_list, buf);
}

/* adds a librarary path (-L). must be called BEFORE compile() */
ccw_int ccw_add_library_path (ccw_context context,
                              const ccw_char *string_value,
                              ccw_uint string_size)
{
    ccw_char *buf;

    if (NULL == context) {
        return CCW_INVALID_CONTEXT;
    }
    
    if (NULL == string_value) {
        return CCW_INVALID_VALUE;
    }
    
    if (0 == string_size) {
        string_size = strlen (string_value) + 1;
    } else {
        string_size++;
    }
    
    if (NULL == (buf = calloc (1, sizeof(ccw_char)*string_size))) {
        return CCW_OUT_OF_MEMORY;
    }
    
    memcpy (buf, string_value, string_size);

    return ccw_add_item (context->library_path_list, buf);
}

/* adds a library (-l). must be called BEFORE compile() */
ccw_int ccw_add_library (ccw_context context,
                         const ccw_char *string_value,
                         ccw_uint string_size)
{
    ccw_char *buf;

    if (NULL == context) {
        return CCW_INVALID_CONTEXT;
    }
    
    if (NULL == string_value) {
        return CCW_INVALID_VALUE;
    }
    
    if (0 == string_size) {
        string_size = strlen (string_value) + 1;
    } else {
        string_size++;
    }
    
    if (NULL == (buf = calloc (1, sizeof(ccw_char)*string_size))) {
        return CCW_OUT_OF_MEMORY;
    }
    
    memcpy (buf, string_value, string_size);

    return ccw_add_item (context->library_list, buf);
}

/* adds a previously lt_dlopene'd (or equivalent) dynamic library for symbol
 * resolution. */
ccw_int ccw_add_dl (ccw_context context,
                    void *dl_handle)
{
    if (NULL == context) {
        return CCW_INVALID_CONTEXT;
    }

    if (NULL == dl_handle) {
        return CCW_INVALID_VALUE;
    }

    return ccw_add_item (context->dl_list, dl_handle);
}

/* compiles and links with 'string_value'. all necessary includes/libs must be
 * added prior to calling this function */
ccw_int ccw_compile_string (ccw_context context,
                            const ccw_char *string_value,
                            ccw_uint string_size)
{
    ccw_char exec_cmd[1031] = {0};
    ccw_char *temp_dir_t = NULL;
    ccw_char *temp_dir = NULL;
    ccw_char *temp_source_t = NULL;
    ccw_char *temp_source = NULL;
    ccw_char *temp_module_t = NULL;
    ccw_char *temp_module = NULL;
    int src_fd = -1;
    int mod_fd = -1;
    lt_dladvise advise = NULL;
    ccw_int ret_val = CCW_INVALID_VALUE;

    if (NULL == context) {
        ret_val = CCW_INVALID_CONTEXT;
        goto cleanup;
    }

    if (NULL == string_value) {
        ret_val = CCW_INVALID_VALUE;
        goto cleanup;
    }

    if (0 == string_size) {
        string_size = strlen (string_value);
    }

    /* set up temporary paths */
    if (NULL == (temp_dir_t       = calloc (24, sizeof(ccw_char)))
        || NULL == (temp_source_t = calloc (24+18, sizeof(ccw_char)))
        || NULL == (temp_source   = calloc (24+20, sizeof(ccw_char)))
        || NULL == (temp_module_t = calloc (24+18, sizeof(ccw_char)))
        || NULL == (temp_module   = calloc (24+21, sizeof(ccw_char))))
    {
        ret_val = CCW_OUT_OF_MEMORY;
        goto cleanup;
    }

    /* create temp dir */
    snprintf (temp_dir_t,   24, "/tmp/ccw-tmp-dir-XXXXXX");
    if (NULL == (temp_dir = mkdtemp (temp_dir_t))) {
        ret_val = CCW_OUT_OF_MEMORY;
        goto cleanup;
    }

    /* create tmp source file */
    snprintf (temp_source_t, 24+18, "%s/ccw-source-XXXXXX", temp_dir);
    fprintf (stderr, "mkstemp (%s)\n", temp_source_t);
    if (-1 == (src_fd = mkstemp (temp_source_t))) {
        ret_val = CCW_OUT_OF_MEMORY;
        goto cleanup;
    }
    snprintf (temp_source, 24+20, "%s.c", temp_source_t);
    if (0 != rename (temp_source_t, temp_source)) {
        ret_val = CCW_OUT_OF_MEMORY;
        goto cleanup;
    }

    /* create temp module file */
    snprintf (temp_module_t, 24+18, "%s/ccw-module-XXXXXX", temp_dir);
    fprintf (stderr, "mkstemp (%s)\n", temp_module_t);
    if (-1 == (mod_fd = mkstemp (temp_module_t))) {
        ret_val = CCW_OUT_OF_MEMORY;
        goto cleanup;
    }
    snprintf (temp_module, 24+21, "%s.so", temp_module_t);
    if (0 != rename (temp_module_t, temp_module)) {
        ret_val = CCW_OUT_OF_MEMORY;
        goto cleanup;
    }

    /* write source string to temp source file */
    if (string_size != write (src_fd, string_value, sizeof(ccw_char)*string_size)) {
        ret_val = CCW_OUT_OF_MEMORY;
        goto cleanup;
    }

    /* close the source file to make sure data gets written out */
    close (src_fd);
    src_fd = -1;

    /* construct compile line */
    snprintf (exec_cmd, 1031,
              "%s -shared -fPIC -O3 -ggdb -Wall -Werror %s -o %s %s %s %s",
              CCW_CC,
              temp_source,
              temp_module,
              ccw_get_string_from_list (context->include_path_list, " -I", NULL),
              ccw_get_string_from_list (context->library_path_list, " -L", NULL),
              ccw_get_string_from_list (context->library_list, " -l", NULL));

    /* do the compilation */
    if (0 != system (exec_cmd)) {
        ret_val = CCW_COMPILE_ERROR;
        goto cleanup;
    }

    /* dlopen the compiled so */
    if (lt_dladvise_init (&advise)
        || lt_dladvise_ext (&advise)
        || lt_dladvise_local (&advise))
    {
        ret_val = CCW_LINK_ERROR;
        goto cleanup;
    }

    /* store the dl handle for later calls to get_symbol */
    close (mod_fd);
    mod_fd = -1;
    if (0 != ccw_add_dl (context, lt_dlopenadvise (temp_module, advise))) {
        ret_val = CCW_LINK_ERROR;
        goto cleanup;
    }

    ret_val = CCW_SUCCESS;

    /* clean up resources */
cleanup:
    if (-1 != src_fd) close (src_fd);
    if (-1 != mod_fd) close (mod_fd);

    if (temp_source) {
        if (temp_source[0]) unlink (temp_source);
        else if (temp_source_t[0]) unlink (temp_source_t);

        free (temp_source);
        free (temp_source_t);
    } else if (temp_source_t) {
        free (temp_source_t);
    }

    if (temp_module) {
        if (temp_module[0]) unlink (temp_module);
        else if (temp_module_t[0]) unlink (temp_module_t);

        free (temp_module);
        free (temp_module_t);

        temp_module_t = NULL;
    } else if (temp_module_t) {
        free (temp_module_t);
    }

    if (temp_dir) {
        if (temp_dir[0]) rmdir (temp_dir);
        free (temp_dir);
    } else if (temp_dir_t) {
        free (temp_dir_t);
    }

    if (NULL != advise) lt_dladvise_destroy (&advise);
    return ret_val;
}

/* search through all opened dl's and return a function pointer if
 * 'kernel_name' is found */
void *ccw_get_symbol (ccw_context context,
                      const ccw_char *kernel_name,
                      ccw_int *errcode)
{
    ccw_list dl_list;
    ccw_uint i;
    void *func_ptr = NULL;

    if (NULL == context
        || NULL == (dl_list = context->dl_list))
    {
        CCW_SET_ERRCODE (CCW_INVALID_CONTEXT);
        return NULL;
    }

    if (NULL == kernel_name) {
        CCW_SET_ERRCODE (CCW_INVALID_VALUE);
        return NULL;
    }

    CCW_SET_ERRCODE (CCW_INVALID_VALUE);

    pthread_mutex_lock (&dl_list->mutex);
    for (i = 0; i < dl_list->used; i++) {
        if (NULL != (func_ptr = lt_dlsym ((lt_dlhandle) dl_list->ptr[i],
                                          kernel_name)))
        {
            CCW_SET_ERRCODE (CCW_SUCCESS);
            break;
        }
    }
    pthread_mutex_unlock (&context->dl_list->mutex);

    return func_ptr;
}
