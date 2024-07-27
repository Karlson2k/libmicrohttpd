/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2021-2024 Evgeny Grin (Karlson2k)

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file src/mhd2/response_from.c
 * @brief  The definitions of MHD_response_from_X() functions and related
 *         internal functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "response_from.h"

#include <string.h>

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "compat_calloc.h"
#include "sys_malloc.h"
#include "sys_file_fd.h"

#include "mhd_public_api.h"

#include "mhd_locks.h"
#include "mhd_response.h"
#include "response_options.h"

#include "mhd_assert.h"

#include "mhd_limits.h"

static struct MHD_Response *
response_create_basic (enum MHD_HTTP_StatusCode sc,
                       uint_fast64_t cntn_size,
                       MHD_FreeCallback free_cb,
                       void *free_cb_cls)
{
  struct MHD_Response *restrict r;
  struct ResponseOptions *restrict s;

  if ((100 > sc) || (999 < sc))
    return NULL;

  r = mhd_calloc (1, sizeof(struct MHD_Response));
  if (NULL != r)
  {
    s = mhd_calloc (1, sizeof(struct ResponseOptions));
    if (NULL != s)
    {
#ifndef HAVE_NULL_PTR_ALL_ZEROS
      mhd_DLINKEDL_INIT_LIST (r, headers);
      r->free.cb = NULL;
      r->free.cls = NULL;
      r->special_resp.spec_hdr = NULL;

      s->termination_callback.v_term_cb = NULL;
      s->termination_callback.v_term_cb_cls = NULL;
#endif /* ! HAVE_NULL_PTR_ALL_ZEROS */

      r->sc = sc;
      r->cntn_size = cntn_size;
      r->free.cb = free_cb;
      r->free.cls = free_cb_cls;
      r->settings = s;

      return r; /* Success exit point */
    }
    free (r);
  }
  return NULL; /* Failure exit point */
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) void
mhd_response_deinit_content_data (struct MHD_Response *restrict r)
{
  mhd_assert (mhd_RESPONSE_CONTENT_DATA_INVALID != r->cntn_dtype);
  if (mhd_RESPONSE_CONTENT_DATA_IOVEC == r->cntn_dtype)
    free (r->cntn.iovec.iov);
  else if (mhd_RESPONSE_CONTENT_DATA_FILE == r->cntn_dtype)
    close (r->cntn.file.fd);
  /* For #mhd_RESPONSE_CONTENT_DATA_BUFFER clean-up performed by callback
     for both modes: internal copy and external cleanup */
  if (NULL != r->free.cb)
    r->free.cb (r->free.cls);
}


MHD_EXTERN_ struct MHD_Response *
MHD_response_from_callback (enum MHD_HTTP_StatusCode sc,
                            uint_fast64_t size,
                            MHD_DynamicContentCreator dyn_cont,
                            void *dyn_cont_cls,
                            MHD_FreeCallback dyn_cont_fc)
{
  struct MHD_Response *restrict res;
  res = response_create_basic (sc, size, dyn_cont_fc, dyn_cont_cls);
  if (NULL != res)
  {
    res->cntn_dtype = mhd_RESPONSE_CONTENT_DATA_CALLBACK;
    res->cntn.dyn.cb = dyn_cont;
    res->cntn.dyn.cls = dyn_cont_cls;
  }
  return res;
}


static const unsigned char empty_buf[1] = { 0 };

MHD_EXTERN_
MHD_FN_PAR_IN_SIZE_ (3,2) struct MHD_Response *
MHD_response_from_buffer (
  enum MHD_HTTP_StatusCode sc,
  size_t buffer_size,
  const char buffer[MHD_FN_PAR_DYN_ARR_SIZE_ (buffer_size)],
  MHD_FreeCallback free_cb,
  void *free_cb_cls)
{
  struct MHD_Response *restrict res;

  if (MHD_SIZE_UNKNOWN == buffer_size)
    return NULL;

  res = response_create_basic (sc, buffer_size, free_cb, free_cb_cls);
  if (NULL != res)
  {
    res->cntn_dtype = mhd_RESPONSE_CONTENT_DATA_BUFFER;
    res->cntn.buf = (0 != buffer_size) ?
                    (const unsigned char *) buffer : empty_buf;
  }
  return res;
}


static void
response_cntn_free_buf (void *ptr)
{
  free (ptr);
}


MHD_EXTERN_
MHD_FN_PAR_IN_SIZE_ (3,2) struct MHD_Response *
MHD_response_from_buffer_copy (
  enum MHD_HTTP_StatusCode sc,
  size_t buffer_size,
  const char buffer[MHD_FN_PAR_DYN_ARR_SIZE_ (buffer_size)])
{
  struct MHD_Response *restrict res;
  const unsigned char *buf_copy;

  if (MHD_SIZE_UNKNOWN == buffer_size)
    return NULL;

  if (0 != buffer_size)
  {
    unsigned char *new_buf;
    new_buf = (unsigned char *) malloc (buffer_size);
    if (NULL == new_buf)
      return NULL;
    memcpy (new_buf, buffer, buffer_size);
    res = response_create_basic (sc, buffer_size,
                                 response_cntn_free_buf, new_buf);
    buf_copy = new_buf;
  }
  else
  {
    buf_copy = empty_buf;
    res = response_create_basic (sc, 0, NULL, NULL);
  }

  if (NULL != res)
  {
    res->cntn_dtype = mhd_RESPONSE_CONTENT_DATA_BUFFER;
    res->cntn.buf = buf_copy;
  }
  return res;
}


MHD_EXTERN_ struct MHD_Response *
MHD_response_from_iovec (
  enum MHD_HTTP_StatusCode sc,
  unsigned int iov_count,
  const struct MHD_IoVec iov[MHD_FN_PAR_DYN_ARR_SIZE_ (iov_count)],
  MHD_FreeCallback free_cb,
  void *free_cb_cls)
{
  unsigned int i;
  size_t i_cp = 0;   /**< Index in the copy of iov */
  uint_fast64_t total_size = 0;

  /* Calculate final size, number of valid elements, and check 'iov' */
  for (i = 0; i < iov_count; ++i)
  {
    if (0 == iov[i].iov_len)
      continue;     /* skip zero-sized elements */
    if (NULL == iov[i].iov_base)
      return NULL;  /* NULL pointer with non-zero size */

    total_size += iov[i].iov_len;
    if ((total_size < iov[i].iov_len) || (0 > (ssize_t) total_size)
        || (((size_t) total_size) != total_size))
      return NULL; /* Larger than send function may report as success */
#if defined(MHD_POSIX_SOCKETS) || ! defined(_WIN64)
    i_cp++;
#else  /* ! MHD_POSIX_SOCKETS && _WIN64 */
    if (1)
    {
      size_t i_add;

      i_add = (size_t) (iov[i].iov_len / mhd_IOV_ELMN_MAX_SIZE);
      if (0 != iov[i].iov_len % mhd_IOV_ELMN_MAX_SIZE)
        i_add++;
      i_cp += i_add;
      if (i_cp < i_add)
        return NULL; /* Counter overflow */
    }
#endif /* ! MHD_POSIX_SOCKETS && _WIN64 */
  }
  if (0 == total_size)
  {
    struct MHD_Response *restrict res;

    res = response_create_basic (sc, 0, free_cb, free_cb_cls);
    if (NULL != res)
    {
      res->cntn_dtype = mhd_RESPONSE_CONTENT_DATA_BUFFER;
      res->cntn.buf = empty_buf;
    }
    return res;
  }
  if (MHD_SIZE_UNKNOWN == total_size)
    return NULL;

  mhd_assert (0 < i_cp);
  if (1)
  { /* for local variables local scope only */
    struct MHD_Response *restrict res;
    mhd_iovec *iov_copy;
    size_t num_copy_elements = i_cp;

    iov_copy = mhd_calloc (num_copy_elements, sizeof(mhd_iovec));
    if (NULL == iov_copy)
      return NULL;

    i_cp = 0;
    for (i = 0; i < iov_count; ++i)
    {
      size_t element_size = iov[i].iov_len;
      const unsigned char *buf = (const unsigned char *) iov[i].iov_base;

      if (0 == element_size)
        continue;         /* skip zero-sized elements */
#if defined(MHD_WINSOCK_SOCKETS) && defined(_WIN64)
      while (mhd_IOV_ELMN_MAX_SIZE < element_size)
      {
        iov_copy[i_cp].iov_base = (char *) mhd_DROP_CONST (buf);
        iov_copy[i_cp].iov_len = mhd_IOV_ELMN_MAX_SIZE;
        buf += mhd_IOV_ELMN_MAX_SIZE;
        element_size -= mhd_IOV_ELMN_MAX_SIZE;
        i_cp++;
      }
#endif /* MHD_WINSOCK_SOCKETS && _WIN64 */
      iov_copy[i_cp].iov_base = mhd_DROP_CONST (buf);
      iov_copy[i_cp].iov_len = (mhd_iov_elmn_size) element_size;
      i_cp++;
    }
    mhd_assert (num_copy_elements == i_cp);
    mhd_assert (0 < i_cp);

    res = response_create_basic (sc, total_size, free_cb, free_cb_cls);
    if (NULL != res)
    {
      res->cntn_dtype = mhd_RESPONSE_CONTENT_DATA_IOVEC;
      res->cntn.iovec.iov = iov_copy;
      res->cntn.iovec.cnt = i_cp;
      return res; /* Success exit point */
    }

    /* Below is a cleanup path */
    free (iov_copy);
  }
  return NULL;
}


MHD_EXTERN_
MHD_FN_PAR_FD_READ_ (2) struct MHD_Response *
MHD_response_from_fd (enum MHD_HTTP_StatusCode sc,
                      int fd,
                      uint_fast64_t offset,
                      uint_fast64_t size)
{
  struct MHD_Response *restrict res;
  if (offset == MHD_SIZE_UNKNOWN)
    return NULL;
  if (size != MHD_SIZE_UNKNOWN)
  {
    if (size > ((size + offset) & 0xFFFFFFFFFFFFFFFFU))
      return NULL;
  }
  res = response_create_basic (sc, size, NULL, NULL);
  if (NULL != res)
  {
    res->cntn_dtype = mhd_RESPONSE_CONTENT_DATA_FILE;
    res->cntn.file.fd = fd;
    res->cntn.file.offset = offset;
#ifdef MHD_USE_SENDFILE
    res->cntn.file.use_sf = (size < MHD_SIZE_UNKNOWN);
#endif
    res->cntn.file.is_pipe = false; /* Not necessary */
  }
  return res;
}


MHD_EXTERN_
MHD_FN_PAR_FD_READ_ (2) struct MHD_Response *
MHD_response_from_pipe (enum MHD_HTTP_StatusCode sc,
                        int fd)
{
  struct MHD_Response *restrict res;
  res = response_create_basic (sc, MHD_SIZE_UNKNOWN, NULL, NULL);
  if (NULL != res)
  {
    res->cntn_dtype = mhd_RESPONSE_CONTENT_DATA_FILE;
    res->cntn.file.fd = fd;
    res->cntn.file.offset = 0; /* Not necessary */
#ifdef MHD_USE_SENDFILE
    res->cntn.file.use_sf = false; /* Not necessary */
#endif
    res->cntn.file.is_pipe = true;
  }
  return res;
}


/**
 * Create special internal response for sending error reply
 * @param sc the HTTP status code
 * @param cntn_len the length of the @a cntn
 * @param cntn the content of the response, could be NULL
 * @param spec_hdr_len the length of the @a spec_hdr
 * @param spec_hdr the special header line, without last CRLF,
 *                 if not NULL it will be deallocated by free().
 * @return
 */
MHD_INTERNAL
MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_CSTR_ (5) struct MHD_Response *
mhd_response_special_for_error (unsigned int sc,
                                size_t cntn_len,
                                const char *cntn,
                                size_t spec_hdr_len,
                                char *spec_hdr)
{
  struct MHD_Response *restrict res;

  mhd_assert (100 <= sc);
  mhd_assert (600 > sc);
  mhd_assert ((NULL != cntn) || (0 == cntn_len));
  mhd_assert ((NULL != spec_hdr) || (0 == spec_hdr_len));

  res = mhd_calloc (1, sizeof(struct MHD_Response));
  if (NULL == res)
    return NULL;

#ifndef HAVE_NULL_PTR_ALL_ZEROS
  mhd_DLINKEDL_INIT_LIST (res, headers);
  res->free.cb = NULL;
  res->free.cls = NULL;
  res->special_resp.spec_hdr = NULL;
#endif /* ! HAVE_NULL_PTR_ALL_ZEROS */
  res->sc = (enum MHD_HTTP_StatusCode) sc;
  res->cntn_size = cntn_len;
  res->cntn_dtype = mhd_RESPONSE_CONTENT_DATA_BUFFER;
  res->cntn.buf = (const unsigned char *) ((0 != cntn_len) ? cntn : "");
  res->cfg.close_forced = true;
  res->cfg.int_err_resp = true;
  res->special_resp.spec_hdr_len = spec_hdr_len;
  res->special_resp.spec_hdr = spec_hdr;
  res->frozen = true;

  return res;
}
