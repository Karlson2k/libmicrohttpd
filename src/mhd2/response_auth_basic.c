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
 * @file src/mhd2/response_auth_basic.c
 * @brief  The definitions of MHD_response_add_basic_auth_challenge() function
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "mhd_response.h"
#include "mhd_locks.h"
#include "mhd_str_types.h"

#include <string.h>
#include "sys_malloc.h"

#include "mhd_str_macros.h"
#include "mhd_str.h"

#include "mhd_public_api.h"


static MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2) enum MHD_StatusCode
response_add_basic_auth_challenge_int (struct MHD_Response *restrict response,
                                       const char *restrict realm,
                                       enum MHD_Bool prefer_utf8)
{
  static const struct MHD_String hdr_name =
    mhd_MSTR_INIT (MHD_HTTP_HEADER_WWW_AUTHENTICATE);
  static const struct MHD_String prefix =
    mhd_MSTR_INIT ("Basic realm=\"");
  static const struct MHD_String add_charset =
    mhd_MSTR_INIT (", charset=\"UTF-8\"");
  const size_t realm_len = strlen (realm);
  char *val_str;
  size_t hval_maxlen;
  size_t suffix_len;
  size_t realm_quoted_len;
  size_t pos;
  struct mhd_ResponseHeader *new_hdr;

  if ((NULL != memchr (realm, '\n', realm_len)) ||
      (NULL != memchr (realm, '\r', realm_len)))
    return MHD_SC_RESP_HEADER_VALUE_INVALID;
  if (0 == realm_len)
    return MHD_SC_RESP_HEADER_VALUE_INVALID;

  suffix_len = 1; /* for (closing) quote char */
  if (MHD_NO != prefer_utf8)
    suffix_len += add_charset.len;
  hval_maxlen = prefix.len + realm_len * 2 + suffix_len;

  new_hdr = (struct mhd_ResponseHeader *)
            malloc (sizeof(struct mhd_ResponseHeader)
                    + hdr_name.len + 1 + hval_maxlen + 1);

  if (NULL == new_hdr)
    return MHD_SC_RESPONSE_HEADER_MEM_ALLOC_FAILED;

  /* Set the name of the header */
  memcpy ((char *) (new_hdr + 1),
          hdr_name.cstr,
          hdr_name.len + 1);

  /* Set the value of the header */
  val_str = ((char *) (new_hdr + 1)) + hdr_name.len + 1;
  memcpy (val_str, prefix.cstr, prefix.len);
  pos = prefix.len;
  realm_quoted_len = mhd_str_quote (realm,
                                    realm_len,
                                    val_str + pos,
                                    hval_maxlen - prefix.len - suffix_len);
  mhd_assert (0 != realm_quoted_len);
  pos += realm_quoted_len;
  val_str[pos++] = '\"';
  mhd_assert (pos + suffix_len <= hval_maxlen);

  if (MHD_NO != prefer_utf8)
  {
    mhd_assert (pos + add_charset.len <= hval_maxlen);
    memcpy (val_str + pos, add_charset.cstr, add_charset.len);
    pos += add_charset.len;
  }
  val_str[pos] = 0; /* Zero terminate the result */
  mhd_assert (pos <= hval_maxlen);

  if (1)
  { /* Try to shrink malloc'ed area */
    void *new_ptr;
    new_ptr = realloc (new_hdr,
                       sizeof(struct mhd_ResponseHeader)
                       + hdr_name.len + 1 + pos + 1);
    /* Just use the old pointer if realloc() failed */
    if (NULL != new_ptr)
      new_hdr = (struct mhd_ResponseHeader *) new_ptr;
  }

  new_hdr->name.cstr = (char *) (new_hdr + 1);
  new_hdr->name.len = hdr_name.len;
  mhd_assert (0 == memcmp (hdr_name.cstr, \
                           new_hdr->name.cstr, \
                           new_hdr->name.len + 1));

  new_hdr->value.cstr = ((char *) (new_hdr + 1)) + hdr_name.len + 1;
  new_hdr->value.len = pos;
  mhd_assert (0 == memcmp (prefix.cstr, \
                           new_hdr->value.cstr, \
                           prefix.len));
  mhd_assert (0 == new_hdr->value.cstr[new_hdr->value.len]);

  mhd_DLINKEDL_INIT_LINKS (new_hdr, headers);
  mhd_DLINKEDL_INS_LAST (response, new_hdr, headers);

  response->cfg.has_bauth = true;

  return MHD_SC_OK;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (2)
MHD_FN_PAR_CSTR_ (2) enum MHD_StatusCode
MHD_response_add_basic_auth_challenge (
  struct MHD_Response *MHD_RESTRICT response,
  const char *realm,
  enum MHD_Bool prefer_utf8)
{
  bool need_unlock;
  enum MHD_StatusCode res;

  if (NULL == response)
    return MHD_SC_RESP_POINTER_NULL;
  if (response->frozen)
    return MHD_SC_TOO_LATE;
  if (MHD_HTTP_STATUS_UNAUTHORIZED != response->sc)
    return MHD_SC_RESP_HTTP_CODE_NOT_SUITABLE;

  if (response->reuse.reusable)
  {
    need_unlock = true;
    if (! mhd_mutex_lock (&(response->reuse.settings_lock)))
      return MHD_SC_RESPONSE_MUTEX_LOCK_FAILED;
    mhd_assert (1 == mhd_atomic_counter_get (&(response->reuse.counter)));
  }
  else
    need_unlock = false;

  if (response->frozen) /* Re-check with the lock held */
    res = MHD_SC_TOO_LATE;
  else if (response->cfg.has_bauth)
    res = MHD_SC_RESP_HEADERS_CONFLICT;
  else
    res = response_add_basic_auth_challenge_int (response,
                                                 realm,
                                                 prefer_utf8);

  if (need_unlock)
    mhd_mutex_unlock_chk (&(response->reuse.settings_lock));

  return res;
}
