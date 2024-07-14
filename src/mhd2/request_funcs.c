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
 * @file src/mhd2/request_funcs.c
 * @brief  The definition of the request internal functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"
#include "mhd_request.h"
#include "mhd_connection.h"
#include "request_funcs.h"
#include "stream_funcs.h"
#include "mhd_dlinked_list.h"


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_add_field_nullable (struct MHD_Connection *restrict c,
                               enum MHD_ValueKind kind,
                               const struct MHD_String *restrict name,
                               const struct MHD_StringNullable *restrict value)
{
  struct mhd_RequestField *f;

  f = (struct mhd_RequestField *)
      mhd_stream_alloc_memory (c, sizeof(struct mhd_RequestField));
  if (NULL == f)
    return false;

  f->field.nv.name = *name;
  f->field.nv.value = *value;
  f->field.kind = kind;
  mhd_DLINKEDL_INIT_LINKS (f, fields);

  mhd_DLINKEDL_INS_LAST (&(c->rq),f,fields);

  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_add_field (struct MHD_Connection *restrict c,
                      enum MHD_ValueKind kind,
                      const struct MHD_String *restrict name,
                      const struct MHD_String *restrict value)
{
  struct MHD_StringNullable value2;

  value2.len = value->len;
  value2.cstr = value->cstr;

  return mhd_stream_add_field_nullable (c, kind, name, &value2);
}
