/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2022-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/request_auth_get.c
 * @brief  The implementation of the request Authorization header parsing helper
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_assert.h"
#include "mhd_unreachable.h"
#include "mhd_cntnr_ptr.h"
#include "mhd_str_macros.h"

#include "mhd_str_types.h"
#include "mhd_request.h"
#include "mhd_connection.h"
#include "mhd_daemon.h"

#include "mhd_str.h"

#include "request_auth_get.h"

MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (3) bool
mhd_request_get_auth_header_value (struct MHD_Request *restrict request,
                                   enum mhd_AuthHeaderKind auth_type,
                                   struct MHD_String *restrict header_value)
{
  static const struct MHD_String hdr_name = mhd_MSTR_INIT ("Authorization");
#ifdef MHD_SUPPORT_AUTH_BASIC
  static const struct MHD_String prefix_basic = mhd_MSTR_INIT ("Basic");
#endif
  const int strict_lvl =
    mhd_CNTNR_PTR (request, \
                   struct MHD_Connection, rq)->daemon->req_cfg.strictness;
  const bool allow_tab_as_sep = (-2 >= strict_lvl);
  const char *prefix_str;
  size_t prefix_len;
  struct mhd_RequestField *f;
  size_t p_start;

  mhd_assert (mhd_HTTP_STAGE_HEADERS_PROCESSED <= \
              mhd_CNTNR_PTR (request, struct MHD_Connection, rq)->stage);

  switch (auth_type)
  {
#ifdef MHD_SUPPORT_AUTH_BASIC
  case mhd_AUTH_HDR_BASIC:
    prefix_str = prefix_basic.cstr;
    prefix_len = prefix_basic.len;
    break;
#endif
#ifdef MHD_ENUMS_NEED_TRAILING_VALUE
  case mhd_AUTH_HDR_KIND_SENTINEL:
#endif
  default:
    mhd_UNREACHABLE ();
    return false;
  }

  for (f = mhd_DLINKEDL_GET_FIRST (request, fields); NULL != f;
       f = mhd_DLINKEDL_GET_NEXT (f, fields))
  {
    if (hdr_name.len != f->field.nv.name.len)
      continue;
    if (MHD_VK_HEADER != f->field.kind)
      continue;
    if (prefix_len > f->field.nv.name.len)
      continue;
    if (! mhd_str_equal_caseless_bin_n (hdr_name.cstr,
                                        f->field.nv.name.cstr,
                                        hdr_name.len))
      continue;
    if (! mhd_str_equal_caseless_bin_n (prefix_str,
                                        f->field.nv.value.cstr,
                                        prefix_len))
      continue;
    /* Match only if the search token string is the full header value or
       the search token is followed by space */
    if (prefix_len == f->field.nv.name.len)
    {
      header_value->cstr = f->field.nv.value.cstr + f->field.nv.name.len;
      header_value->len = 0;
      return true; /* Success exit point */
    }
    if (' ' == f->field.nv.value.cstr[prefix_len])
      break;
    /* Note: RFC 7235 (Section 2.1) only allows the space character.
       However, as a slight violation of the specifications, a tab character
       is also recognised here for additional flexibility and
       uniformity (tabs are supported as separators between parameters). */
    if (allow_tab_as_sep &&
        ('\t' == f->field.nv.value.cstr[prefix_len]))
      break;
  }
  if (NULL == f)
    return false; /* Failure exit point */

  mhd_assert (prefix_len + 1 <= f->field.nv.name.len);
  /* Skip leading whitespaces */
  for (p_start = prefix_len + 1; p_start < f->field.nv.name.len; ++p_start)
  {
    if ((' ' != f->field.nv.value.cstr[p_start]) &&
        ('\t' != f->field.nv.value.cstr[p_start]))
      break;
  }
  header_value->cstr = f->field.nv.value.cstr + p_start;
  header_value->len = f->field.nv.value.len - p_start;

  mhd_assert (0 == header_value->cstr[header_value->len]);
  mhd_assert ((0 != header_value->len) && \
              "Trailing header whitespaces must be already stripped");

  return true; /* Success exit point */
}
