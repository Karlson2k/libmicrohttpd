/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Christian Grothoff
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

  mhd_assert (strlen (key) == key_len);

  if (MHD_VK_POSTDATA != kind)
  {
    struct mhd_RequestField *f;

    for (f = mhd_DLINKEDL_GET_FIRST (request, fields); NULL != f;
         f = mhd_DLINKEDL_GET_NEXT (f, fields))
    {
      if ((key_len == f->field.nv.name.len) &&
          (0 != (kind & f->field.kind)) &&
          mhd_str_equal_caseless_bin_n (key,
                                        f->field.nv.name.cstr,
                                        key_len))
        return &(f->field.nv.value);
    }
  }

#if MHD_SUPPORT_POST_PARSER
  if (0 != (MHD_VK_POSTDATA & kind))
  {
    struct mhd_RequestPostField *f;
    char *const buf = request->cntn.lbuf.data; // TODO: support processing in connection buffer
    for (f = mhd_DLINKEDL_GET_FIRST (request, post_fields); NULL != f;
         f = mhd_DLINKEDL_GET_NEXT (f, post_fields))
    {
      if ((key_len == f->field.name.len) &&
          mhd_str_equal_caseless_bin_n (key,
                                        buf + f->field.name.pos,
                                        key_len))
      {
        f->field_for_app.value.cstr =
          (0 == f->field.value.pos) ?
          NULL : (buf + f->field.value.pos);
        f->field_for_app.value.len = f->field.value.len;

        mhd_assert ((NULL != f->field_for_app.value.cstr) || \
                    (0 == f->field_for_app.value.len));

        return &(f->field_for_app.value);
      }
    }
  }
#endif /* MHD_SUPPORT_POST_PARSER */

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

  mhd_assert (mhd_HTTP_STAGE_START_REPLY >= c->stage);

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


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) size_t
MHD_request_get_values_cb (struct MHD_Request *request,
                           enum MHD_ValueKind kind,
                           MHD_NameValueIterator iterator,
                           void *iterator_cls)
{
  size_t count;

  count = 0;
  if (MHD_VK_POSTDATA != kind)
  {
    struct mhd_RequestField *f;

    for (f = mhd_DLINKEDL_GET_FIRST (request, fields); NULL != f;
         f = mhd_DLINKEDL_GET_NEXT (f, fields))
    {
      if (0 == (kind & f->field.kind))
        continue;

      ++count;
      if (NULL != iterator)
      {
        if (MHD_NO ==
            iterator (iterator_cls,
                      f->field.kind,
                      &(f->field.nv)))
          return count;
      }
    }
  }

#if MHD_SUPPORT_POST_PARSER
  if (0 != (MHD_VK_POSTDATA & kind))
  {
    struct mhd_RequestPostField *f;
    char *const buf = request->cntn.lbuf.data; // TODO: support processing in connection buffer
    for (f = mhd_DLINKEDL_GET_FIRST (request, post_fields); NULL != f;
         f = mhd_DLINKEDL_GET_NEXT (f, post_fields))
    {
      ++count;
      if (NULL != iterator)
      {
        if (f->field_for_app.name.cstr != buf + f->field.name.pos)
        {
          f->field_for_app.name.cstr = buf + f->field.name.pos;
          f->field_for_app.name.len = f->field.name.len;
          f->field_for_app.value.cstr =
            (0 == f->field.value.pos) ?
            NULL : (buf + f->field.value.pos);
          f->field_for_app.value.len = f->field.value.len;
        }

        if (MHD_NO ==
            iterator (iterator_cls,
                      MHD_VK_POSTDATA,
                      &(f->field_for_app)))
          return count;
      }
    }
  }
#endif /* MHD_SUPPORT_POST_PARSER */

  return count;
}


#if MHD_SUPPORT_POST_PARSER

MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) size_t
MHD_request_get_post_data_cb (struct MHD_Request *request,
                              MHD_PostDataIterator iterator,
                              void *iterator_cls)
{
  struct mhd_RequestPostField *f;
  char *const buf = request->cntn.lbuf.data; // TODO: support processing in connection buffer
  size_t count;

  count = 0;
  for (f = mhd_DLINKEDL_GET_FIRST (request, post_fields); NULL != f;
       f = mhd_DLINKEDL_GET_NEXT (f, post_fields))
  {
    ++count;
    if (NULL != iterator)
    {
      struct MHD_PostField field;

      if (f->field_for_app.name.cstr != buf + f->field.name.pos)
      {
        f->field_for_app.name.cstr = buf + f->field.name.pos;
        f->field_for_app.name.len = f->field.name.len;
        if (0 == f->field.value.pos)
          f->field_for_app.value.cstr = NULL;
        else
          f->field_for_app.value.cstr = buf + f->field.value.pos;
        f->field_for_app.value.len = f->field.value.len;
      }

      field.name = f->field_for_app.name;
      field.value = f->field_for_app.value;

      if (0 == f->field.filename.pos)
        field.filename.cstr = NULL;
      else
        field.filename.cstr = buf + f->field.filename.pos;
      field.filename.len = f->field.filename.len;

      if (0 == f->field.content_type.pos)
        field.content_type.cstr = NULL;
      else
        field.content_type.cstr = buf + f->field.content_type.pos;
      field.content_type.len = f->field.content_type.len;

      if (0 == f->field.transfer_encoding.pos)
        field.transfer_encoding.cstr = NULL;
      else
        field.transfer_encoding.cstr = buf + f->field.transfer_encoding.pos;
      field.transfer_encoding.len = f->field.transfer_encoding.len;

      mhd_assert ((NULL != field.value.cstr) || (0 == field.value.len));
      mhd_assert ((NULL != field.filename.cstr) || (0 == field.filename.len));
      mhd_assert ((NULL != field.content_type.cstr) || \
                  (0 == field.content_type.len));
      mhd_assert ((NULL != field.transfer_encoding.cstr) || \
                  (0 == field.transfer_encoding.len));

      if (MHD_NO ==
          iterator (iterator_cls,
                    &field))
        return count;
    }
  }
  return count;
}


#endif /* MHD_SUPPORT_POST_PARSER */
