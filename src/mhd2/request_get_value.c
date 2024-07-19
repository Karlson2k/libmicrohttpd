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
 * @file src/mhd2/request_get_value.c
 * @brief  The implementation of MHD_request_get_value*() functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"
#include "request_get_value.h"
#include "sys_base_types.h"
#include <string.h>

#include "mhd_request.h"

#include "mhd_connection.h"

#include "mhd_dlinked_list.h"
#include "mhd_assert.h"
#include "mhd_str.h"

#include "mhd_public_api.h"


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (4) MHD_FN_PAR_CSTR_ (4) const struct MHD_StringNullable *
mhd_request_get_value_n (struct MHD_Request *restrict request,
                         enum MHD_ValueKind kind,
                         size_t key_len,
                         const char *restrict key)
{
  struct mhd_RequestField *f;

  mhd_assert (strlen (key) == key_len);

  for (f = mhd_DLINKEDL_GET_FIRST (request, fields); NULL != f;
       f = mhd_DLINKEDL_GET_NEXT (f, fields))
  {
    if ((key_len == f->field.nv.name.len) &&
        (kind == f->field.kind) &&
        (0 == memcmp (key, f->field.nv.name.cstr, key_len)))
      return &(f->field.nv.value);
  }
  return NULL;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_ (3) const struct MHD_StringNullable *
MHD_request_get_value (struct MHD_Request *MHD_RESTRICT request,
                       enum MHD_ValueKind kind,
                       const char *MHD_RESTRICT key)
{
  size_t len;
  len = strlen (key);
  return mhd_request_get_value_n (request, kind, len, key);
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (3)
MHD_FN_PAR_CSTR_ (5) bool
mhd_stream_has_header_token (const struct MHD_Connection *restrict c,
                             size_t header_len,
                             const char *restrict header,
                             size_t token_len,
                             const char *restrict token)
{
  struct mhd_RequestField *f;

  mhd_assert (MHD_CONNECTION_START_REPLY >= c->state);

  for (f = mhd_DLINKEDL_GET_FIRST (&(c->rq), fields);
       NULL != f;
       f = mhd_DLINKEDL_GET_NEXT (f, fields))
  {
    if ((MHD_VK_HEADER == f->field.kind) &&
        (header_len == f->field.nv.name.len) &&
        (mhd_str_equal_caseless_bin_n (header,
                                       f->field.nv.name.cstr,
                                       header_len)) &&
        (mhd_str_has_token_caseless (f->field.nv.value.cstr,
                                     token,
                                     token_len)))
      return true;
  }

  return false;
}
