/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/auth_basic.c
 * @brief  The implementation of the Basic Authorization header parser
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include <string.h>

#include "mhd_cntnr_ptr.h"

#include "mhd_assert.h"

#include "mhd_str_types.h"
#include "mhd_connection.h"

#include "mhd_str.h"
#include "stream_funcs.h"
#include "request_auth_get.h"

#include "auth_basic.h"

static MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
enum MHD_StatusCode
find_and_parse_auth_basic (struct MHD_Request *restrict req)
{
  struct MHD_String token68;
  size_t alloc_size;
  size_t dec_size;
  char *dec_buf;
  char *colon_ptr;

  mhd_assert (NULL == req->auth.basic.intr.username.cstr);

  if (! mhd_request_get_auth_header_value (req,
                                           mhd_AUTH_HDR_BASIC,
                                           &token68))
    return MHD_SC_AUTH_ABSENT;

  mhd_assert (NULL != token68.cstr);

  if (0 == token68.len)
  {
    /* Zero-length token68 */
    req->auth.basic.intr.username.cstr = token68.cstr;
    mhd_assert (0 == req->auth.basic.intr.username.len);
    mhd_assert (NULL == req->auth.basic.intr.password.cstr);
    mhd_assert (0 == req->auth.basic.intr.password.len);
    return MHD_SC_OK;
  }

  alloc_size = mhd_base64_max_dec_size (token68.len) + 1;
  dec_buf = (char *)
            mhd_stream_alloc_memory (mhd_CNTNR_PTR (req, \
                                                    struct MHD_Connection, \
                                                    rq),
                                     alloc_size);
  if (NULL == dec_buf)
    return MHD_SC_CONNECTION_POOL_NO_MEM_AUTH_DATA;

  /* The 'dec_buf' remains allocated until start of sending reply or until
     end of the request processing. */

  dec_size = mhd_base64_to_bin_n (token68.cstr,
                                  token68.len,
                                  dec_buf,
                                  alloc_size);
  if (0 == dec_size)
    return MHD_SC_REQ_AUTH_DATA_BROKEN;

  dec_buf[dec_size] = 0; /* Zero-terminate the result */
  req->auth.basic.intr.username.cstr = dec_buf;
  colon_ptr = memchr (dec_buf, ':', dec_size);
  if (NULL == colon_ptr)
  {
    /* No password provided. Only username. */
    req->auth.basic.intr.username.len = dec_size;
    mhd_assert (NULL == req->auth.basic.intr.password.cstr);
    mhd_assert (0 == req->auth.basic.intr.password.len);
    return MHD_SC_OK;
  }
  *colon_ptr = 0; /* Zero-terminate the username */
  req->auth.basic.intr.username.len = (size_t) (colon_ptr - dec_buf);
  req->auth.basic.intr.password.cstr = colon_ptr + 1;
  mhd_assert ((req->auth.basic.intr.username.len + 1) <= dec_size);
  req->auth.basic.intr.password.len =
    dec_size - (req->auth.basic.intr.username.len + 1);
  return MHD_SC_OK;
}


MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) enum MHD_StatusCode
mhd_request_get_auth_basic_creds (
  struct MHD_Request *restrict req,
  const struct MHD_BasicAuthInfo **restrict v_auth_basic_creds)
{
  enum MHD_StatusCode res;
  mhd_assert (mhd_HTTP_STAGE_HEADERS_PROCESSED <=
              mhd_CNTNR_CPTR (req, struct MHD_Connection, rq)->stage);
  mhd_assert (mhd_HTTP_STAGE_REQ_RECV_FINISHED >=
              mhd_CNTNR_CPTR (req, struct MHD_Connection, rq)->stage);

  if (NULL != req->auth.basic.intr.username.cstr)
    res = MHD_SC_OK;
  else
    res = find_and_parse_auth_basic (req);

  if (MHD_SC_OK != res)
    return res; /* Failure exit point */

  *v_auth_basic_creds = &(req->auth.basic.extr);

  return MHD_SC_OK; /* Success exit point */
}
