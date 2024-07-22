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
 * @file src/mhd2/response_add_header.c
 * @brief  The definitions of MHD_response_add_*header() functions
 * @author Karlson2k (Evgeny Grin)
 * @author Christian Grothoff
 */

#include "mhd_sys_options.h"

#include "response_add_header.h"
#include "mhd_response.h"
#include "mhd_locks.h"

#include <string.h>
#include "sys_malloc.h"

#include "mhd_public_api.h"


static
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_IN_SIZE_ (3,2)
MHD_FN_PAR_NONNULL_ (5) MHD_FN_PAR_CSTR_ (5) MHD_FN_PAR_IN_SIZE_ (5,4) bool
response_add_header_no_check (
  struct MHD_Response *response,
  size_t name_len,
  const char name[MHD_FN_PAR_DYN_ARR_SIZE_ (name_len)],
  size_t value_len,
  const char value[MHD_FN_PAR_DYN_ARR_SIZE_ (value_len)])
{
  char *buf;
  struct mhd_ResponseHeader *new_hdr;

  new_hdr = (struct mhd_ResponseHeader *)
            malloc (sizeof(struct mhd_ResponseHeader) + name_len
                    + value_len + 2);
  if (NULL == new_hdr)
    return false;

  buf = ((char *) new_hdr) + sizeof(struct mhd_ResponseHeader);
  memcpy (buf, name, name_len);
  buf[name_len] = 0;
  new_hdr->name.cstr = buf;
  new_hdr->name.len = name_len;
  buf += name_len + 1;
  memcpy (buf, value, value_len);
  buf[value_len] = 0;
  new_hdr->value.cstr = buf;
  new_hdr->value.len = value_len;

  mhd_DLINKEDL_INIT_LINKS (new_hdr, headers);
  mhd_DLINKEDL_INS_LAST (response, new_hdr, headers);
  return true;
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) void
mhd_response_remove_all_headers (struct MHD_Response *restrict r)
{
  struct mhd_ResponseHeader *hdr;

  for (hdr = mhd_DLINKEDL_GET_LAST (r, headers); NULL != hdr;
       hdr = mhd_DLINKEDL_GET_LAST (r, headers))
  {
    mhd_DLINKEDL_DEL (r, hdr, headers);
    free (hdr);
  }
}


static enum MHD_StatusCode
response_add_header_int (struct MHD_Response *response,
                         const char *name,
                         const char *value)
{
  const size_t name_len = strlen (name);
  const size_t value_len = strlen (value);

  if (response->frozen) /* Re-check with the lock held */
    return MHD_SC_TOO_LATE;

  if ((NULL != memchr (name, ' ', name_len)) ||
      (NULL != memchr (name, '\t', name_len)) ||
      (NULL != memchr (name, ':', name_len)) ||
      (NULL != memchr (name, '\n', name_len)) ||
      (NULL != memchr (name, '\r', name_len)))
    return MHD_SC_RESP_HEADER_NAME_INVALID;
  if ((NULL != memchr (value, '\n', value_len)) ||
      (NULL != memchr (value, '\r', value_len)))
    return MHD_SC_RESP_HEADER_VALUE_INVALID;

  if (! response_add_header_no_check (response, name_len, name,
                                      value_len, value))
    return MHD_SC_RESPONSE_HEADER_MALLOC_FAILED;

  return MHD_SC_OK;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_ (3) enum MHD_StatusCode
MHD_response_add_header (struct MHD_Response *response,
                         const char *name,
                         const char *value)
{
  bool need_unlock;
  enum MHD_StatusCode res;

  if (response->frozen)
    return MHD_SC_TOO_LATE;

  if (response->reuse.reusable)
  {
    need_unlock = true;
    if (! mhd_mutex_lock (&(response->reuse.settings_lock)))
      return MHD_SC_RESPONSE_MUTEX_LOCK_FAILED;
    mhd_assert (1 == mhd_atomic_counter_get (&(response->reuse.counter)));
  }
  else
    need_unlock = false;

  // TODO: add special processing for "Date", "Connection", "Content-Length", "Transfer-Encoding"

  res = response_add_header_int (response, name, value);

  if (need_unlock)
    mhd_mutex_unlock_chk (&(response->reuse.settings_lock));

  return res;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_CSTR_ (3) enum MHD_StatusCode
MHD_response_add_predef_header (struct MHD_Response *response,
                                enum MHD_PredefinedHeader stk,
                                const char *content)
{
  (void) response; (void) stk; (void) content;
  return MHD_SC_FEATURE_DISABLED;
}
