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
 * @file src/mhd2/response_auth_digest.c
 * @brief  The definitions of MHD_response_add_auth_basic_challenge() function
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

#include "mhd_unreachable.h"
#include "mhd_assert.h"

#include "mhd_digest_auth_data.h"

#include "mhd_response.h"
#include "mhd_locks.h"
#include "mhd_str_types.h"
#include <string.h>
#include "sys_malloc.h"

#include "mhd_str_macros.h"
#include "mhd_str.h"

#include "mhd_public_api.h"

#include "response_auth_digest.h"
#include "mhd_auth_digest_hdr.h"


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) void
mhd_response_remove_auth_digest_headers (struct MHD_Response*response)
{
  struct mhd_RespAuthDigestHeader *hdr_d;

  for (hdr_d = mhd_DLINKEDL_GET_LAST (response, auth_d_hdrs);
       NULL != hdr_d;
       hdr_d = mhd_DLINKEDL_GET_LAST (response, auth_d_hdrs))
  {
    mhd_DLINKEDL_DEL (response, hdr_d, auth_d_hdrs);
    free (hdr_d);
  }
}


/**
 * Create and add Digest Auth challenge header with specified algorithm
 * @param response the response to update
 * @param rlm the realm to use
 * @param opq the "opaque" string to use
 * @param dmn the "domain" string to use
 * @param indicate_stale whether to indicate "stale" nonce
 * @param qop_none whether to use RFC 2069 subset only
 * @param algo the algorithm to use
 * @param userhash_support whether to indicate support for "userhash"
 * @param prefer_utf8 whether to indicate UTF-8 support
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ enum MHD_StatusCode
response_add_auth_digest_challenge_alg (
  struct MHD_Response *restrict response,
  const struct MHD_String *restrict rlm,
  const struct MHD_StringNullable *restrict opq,
  const struct MHD_StringNullable *restrict dmn,
  enum MHD_Bool indicate_stale,
  bool qop_none,
  enum MHD_DigestAuthAlgo algo,
  enum MHD_Bool userhash_support,
  enum MHD_Bool prefer_utf8)
{
  static const struct MHD_String empty_str =
    mhd_MSTR_INIT ("");
  static const struct MHD_String hdr_pref_realm_pref =
    mhd_MSTR_INIT (MHD_HTTP_HEADER_WWW_AUTHENTICATE ": " \
                   mhd_AUTH_DIGEST_SCHEME " realm=\"");
  static const struct MHD_String qop_str =
    mhd_MSTR_INIT (", qop=\"auth\"");
#ifdef MHD_SUPPORT_MD5
  static const struct MHD_String algo_mh5_str =
    mhd_MSTR_INIT (", algorithm=MD5");
#endif
#ifdef MHD_SUPPORT_SHA256
  static const struct MHD_String algo_sha256_str =
    mhd_MSTR_INIT (", algorithm=SHA-256");
#endif
#ifdef MHD_SUPPORT_SHA512_256
  static const struct MHD_String algo_sha512_256_str =
    mhd_MSTR_INIT (", algorithm=SHA-512-256");
#endif
  static const struct MHD_String nonce_str =
    mhd_MSTR_INIT (", nonce=\"" \
                   "00000000000000000000000000000000" \
                   "00000000000000000000000000000000" \
                   "00000000" \
                   "\"");
  static size_t nonce_off = 9; /* Position of nonce value in the nonce_str */
  static const struct MHD_String opaque_pref =
    mhd_MSTR_INIT (", opaque=\"");
  static const struct MHD_String domain_pref =
    mhd_MSTR_INIT (", domain=\"");
  static const struct MHD_String stale_str =
    mhd_MSTR_INIT (", stale=true");
  static const struct MHD_String charset_str =
    mhd_MSTR_INIT (", charset=UTF-8");
  static const struct MHD_String userhash_str =
    mhd_MSTR_INIT (", userhash=true");

  /* Header content:
     + Scheme name and space;
     + realm, quoted;
     + qop="auth", quoted (optional);
     + algorithm, NOT quoted (optional);
     + nonce (placeholder), quoted;
     + opaque, quoted (optional);
     + domain, quoted (optional);
     + stale=true (optional);
     + charset=UTF-8 (optional);
     + userhash=true (optional).
   */

  struct MHD_String algo_str;
  char *hdr_str;
  size_t hdr_maxlen;
  struct mhd_RespAuthDigestHeader *new_hdr;
  size_t pos;
  size_t elm_len;

  mhd_assert ('0' == nonce_str.cstr[nonce_off]);
  mhd_assert ('0' == nonce_str.cstr[nonce_off + mhd_AUTH_DIGEST_NONCE_LEN]);
  mhd_assert ('"' == nonce_str.cstr[nonce_off - 1]);
  mhd_assert ('"' == nonce_str.cstr[nonce_off + mhd_AUTH_DIGEST_NONCE_LEN + 1]);

#ifdef MHD_SUPPORT_MD5
  if (MHD_DIGEST_AUTH_ALGO_MD5 == algo)
    algo_str = qop_none ? empty_str : algo_mh5_str;
#endif
#ifdef MHD_SUPPORT_SHA256
  else if (MHD_DIGEST_AUTH_ALGO_SHA256 == algo)
    algo_str = algo_sha256_str;
#endif
#ifdef MHD_SUPPORT_SHA512_256
  else if (MHD_DIGEST_AUTH_ALGO_SHA512_256 == algo)
    algo_str = algo_sha512_256_str;
#endif
  else
    mhd_UNREACHABLE ();

  /* ** Calculate the maximum length of the header string ** */
  hdr_maxlen = 0;

  /* realm */
  hdr_maxlen += hdr_pref_realm_pref.len;
  hdr_maxlen += rlm->len * 2; /* Double length for quoting */
  hdr_maxlen += 1; /* closing quote (") */

  /* qop */
  hdr_maxlen += qop_str.len;

  /* algorithm */
  hdr_maxlen += algo_str.len;

  /* nonce */
  hdr_maxlen += nonce_str.len;

  /* opaque */
  hdr_maxlen += opaque_pref.len;
  hdr_maxlen += opq->len * 2; /* Double length for quoting */
  hdr_maxlen += 1; /* closing quote (") */

  /* domain */
  hdr_maxlen += domain_pref.len;
  hdr_maxlen += dmn->len;
  hdr_maxlen += 1; /* closing quote (") */

  /* stale */
  hdr_maxlen += stale_str.len;

  /* charset */
  hdr_maxlen += charset_str.len;

  /* userhash */
  hdr_maxlen += userhash_str.len;

  /* CRLF */
  hdr_maxlen += 2;

  /* ** Allocate ** */
  new_hdr = (struct mhd_RespAuthDigestHeader *)
            malloc (sizeof(struct mhd_RespAuthDigestHeader *)
                    + hdr_maxlen + 1);
  if (NULL == new_hdr)
    return MHD_SC_RESPONSE_HEADER_MEM_ALLOC_FAILED;
  hdr_str = (char *) (new_hdr + 1);

  /* ** Build the header ** */
  pos = 0;

  /* realm */
  memcpy (hdr_str + pos,
          hdr_pref_realm_pref.cstr,
          hdr_pref_realm_pref.len);
  pos += hdr_pref_realm_pref.len;
  elm_len = mhd_str_quote (rlm->cstr,
                           rlm->len,
                           hdr_str + pos,
                           hdr_maxlen - pos);
  mhd_assert (0 != elm_len);
  pos += elm_len;
  hdr_str[pos++] = '"';

  /* qop */
  if (! qop_none)
  {
    memcpy (hdr_str + pos,
            qop_str.cstr,
            qop_str.len);
    pos += qop_str.len;
  }

  /* algorithm */
  if (0 != algo_str.len)
  {
    memcpy (hdr_str + pos,
            algo_str.cstr,
            algo_str.len);
    pos += algo_str.len;
  }

  /* nonce */
  memcpy (hdr_str + pos,
          nonce_str.cstr,
          nonce_str.len);
  new_hdr->nonce_pos = pos + nonce_off;
  pos += nonce_str.len;

  /* opaque */
  if (0 != opq->len)
  {
    memcpy (hdr_str + pos,
            opaque_pref.cstr,
            opaque_pref.len);
    pos += opaque_pref.len;
    elm_len = mhd_str_quote (opq->cstr,
                             opq->len,
                             hdr_str + pos,
                             hdr_maxlen - pos);
    mhd_assert (0 != elm_len);
    pos += elm_len;
    hdr_str[pos++] = '"';
  }

  /* domain */
  if (0 != dmn->len)
  {
    memcpy (hdr_str + pos,
            domain_pref.cstr,
            domain_pref.len);
    pos += domain_pref.len;
    memcpy (hdr_str + pos,
            dmn->cstr,
            dmn->len);
    pos += dmn->len;
    hdr_str[pos++] = '"';
  }

  /* stale */
  if (MHD_NO != indicate_stale)
  {
    memcpy (hdr_str + pos,
            stale_str.cstr,
            stale_str.len);
    pos += stale_str.len;
  }

  /* charset */
  if ((! qop_none) &&
      (MHD_NO != prefer_utf8))
  {
    memcpy (hdr_str + pos,
            charset_str.cstr,
            charset_str.len);
    pos += charset_str.len;
  }

  /* userhash */
  if ((! qop_none) &&
      (MHD_NO != userhash_support))
  {
    memcpy (hdr_str + pos,
            userhash_str.cstr,
            userhash_str.len);
    pos += userhash_str.len;
  }

  /* CRLF */
  hdr_str[pos++] = '\r';
  hdr_str[pos++] = '\n';

  mhd_assert (pos <= hdr_maxlen);
  hdr_str[pos] = 0; /* Zero-terminate the string */

  if (1)
  { /* Try to shrink malloc'ed area */
    void *new_ptr;
    new_ptr = realloc (new_hdr,
                       sizeof(struct mhd_RespAuthDigestHeader)
                       + pos);
    /* Just use the old pointer if realloc() failed */
    if (NULL != new_ptr)
      new_hdr = (struct mhd_RespAuthDigestHeader *) new_ptr;
  }

  new_hdr->hdr.cstr = (char *) (new_hdr + 1);
  new_hdr->hdr.len = pos;
  mhd_assert (0 == \
              memcmp (new_hdr->hdr.cstr, \
                      MHD_HTTP_HEADER_WWW_AUTHENTICATE ": ", \
                      mhd_SSTR_LEN (MHD_HTTP_HEADER_WWW_AUTHENTICATE ": ")));
  mhd_assert (0 == new_hdr->hdr.cstr[new_hdr->hdr.len]);

  mhd_DLINKEDL_INIT_LINKS (new_hdr, auth_d_hdrs);
  mhd_DLINKEDL_INS_LAST (response, new_hdr, auth_d_hdrs);

  return MHD_SC_OK;
}


/**
 * Create and add Digest Auth challenge headers for all specified algorithms
 * @param response the response to update
 * @param realm the real to use
 * @param opaque the "opaque" string, could be NULL
 * @param domain the "domain" string, could be NULL
 * @param indicate_stale whether to indicate "stale" nonce
 * @param mqop the QOP values to use
 * @param malgo the algorithms to use
 * @param userhash_support whether to indicate support for "userhash"
 * @param prefer_utf8 whether to indicate UTF-8 support
 * @return #MHD_SC_OK on success,
 *         error code otherwise
 */
static MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_CSTR_ (4) enum MHD_StatusCode
response_add_auth_digest_challenge_int (struct MHD_Response *restrict response,
                                        const char *restrict realm,
                                        const char *restrict opaque,
                                        const char *restrict domain,
                                        enum MHD_Bool indicate_stale,
                                        enum MHD_DigestAuthMultiQOP mqop,
                                        enum MHD_DigestAuthMultiAlgo malgo,
                                        enum MHD_Bool userhash_support,
                                        enum MHD_Bool prefer_utf8)
{
  const struct MHD_String rlm = { strlen (realm), realm };
  const struct MHD_StringNullable opq =
  { (NULL != opaque ? strlen (opaque) : 0), opaque };
  const struct MHD_StringNullable dmn =
  { (NULL != domain ? strlen (domain) : 0), domain };
  const bool qop_none =
    (0 != (MHD_DIGEST_AUTH_QOP_NONE & ((unsigned int) mqop)));
  enum MHD_StatusCode res;

  /* Check validity of the input data */

  if (0 == rlm.len)
    return MHD_SC_RESP_HEADER_VALUE_INVALID;   /* Failure exit point */
  if ((NULL != memchr (rlm.cstr, '\n', rlm.len)) ||
      (NULL != memchr (rlm.cstr, '\r', rlm.len)))
    return MHD_SC_RESP_HEADER_VALUE_INVALID; /* Failure exit point */

  if ((0 != opq.len) &&
      ((NULL != memchr (opq.cstr, '\n', opq.len)) ||
       (NULL != memchr (opq.cstr, '\r', opq.len))))
    return MHD_SC_RESP_HEADER_VALUE_INVALID; /* Failure exit point */

  if ((0 != dmn.len) &&
      ((NULL != memchr (dmn.cstr, '\n', dmn.len)) ||
       (NULL != memchr (dmn.cstr, '\r', dmn.len)) ||
       (NULL != memchr (dmn.cstr, '"', dmn.len))))
    return MHD_SC_RESP_HEADER_VALUE_INVALID; /* Failure exit point */

  if (0 == (MHD_DIGEST_AUTH_ALGO_NON_SESSION & ((unsigned int) malgo)))
    return MHD_SC_AUTH_DIGEST_ALGO_NOT_SUPPORTED; /* Failure exit point */

  if (0 == ((MHD_DIGEST_AUTH_QOP_NONE | MHD_DIGEST_AUTH_QOP_AUTH)
            & ((unsigned int) mqop)))
    return MHD_SC_AUTH_DIGEST_QOP_NOT_SUPPORTED; /* Failure exit point */

  res = MHD_SC_OK;

#ifdef MHD_SUPPORT_MD5
  if ((MHD_SC_OK == res) &&
      (0 == (MHD_DIGEST_BASE_ALGO_MD5 & ((unsigned int) malgo))))
    res = response_add_auth_digest_challenge_alg (response,
                                                  &rlm,
                                                  &opq,
                                                  &dmn,
                                                  indicate_stale,
                                                  qop_none,
                                                  MHD_DIGEST_AUTH_ALGO_MD5,
                                                  userhash_support,
                                                  prefer_utf8);
#endif
#ifdef MHD_SUPPORT_SHA256
  if ((MHD_SC_OK == res) &&
      (0 == (MHD_DIGEST_BASE_ALGO_SHA256 & ((unsigned int) malgo))))
    res = response_add_auth_digest_challenge_alg (response,
                                                  &rlm,
                                                  &opq,
                                                  &dmn,
                                                  indicate_stale,
                                                  qop_none,
                                                  MHD_DIGEST_AUTH_ALGO_SHA256,
                                                  userhash_support,
                                                  prefer_utf8);
#endif
#ifdef MHD_SUPPORT_SHA512_256
  if ((MHD_SC_OK == res) &&
      (0 == (MHD_DIGEST_BASE_ALGO_SHA256 & ((unsigned int) malgo))))
    res = response_add_auth_digest_challenge_alg (
      response,
      &rlm,
      &opq,
      &dmn,
      indicate_stale,
      qop_none,
      MHD_DIGEST_AUTH_ALGO_SHA512_256,
      userhash_support,
      prefer_utf8);
#endif

  if (MHD_SC_OK != res)
  {
    mhd_response_remove_auth_digest_headers (response);
    return res; /* Failure exit point */
  }

  if (NULL == mhd_DLINKEDL_GET_FIRST (response, auth_d_hdrs))
    return MHD_SC_AUTH_DIGEST_ALGO_NOT_SUPPORTED;  /* Failure exit point */

  return MHD_SC_OK; /* Success exit point */
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_CSTR_ (4) enum MHD_StatusCode
MHD_response_add_auth_digest_challenge (
  struct MHD_Response *MHD_RESTRICT response,
  const char *MHD_RESTRICT realm,
  const char *MHD_RESTRICT opaque,
  const char *MHD_RESTRICT domain,
  enum MHD_Bool indicate_stale,
  enum MHD_DigestAuthMultiQOP mqop,
  enum MHD_DigestAuthMultiAlgo malgo,
  enum MHD_Bool userhash_support,
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
  else if (NULL != mhd_DLINKEDL_GET_FIRST (response, auth_d_hdrs))
    res = MHD_SC_RESP_HEADERS_CONFLICT;
  else
    res = response_add_auth_digest_challenge_int (response,
                                                  realm,
                                                  opaque,
                                                  domain,
                                                  indicate_stale,
                                                  mqop,
                                                  malgo,
                                                  userhash_support,
                                                  prefer_utf8);

  if (need_unlock)
    mhd_mutex_unlock_chk (&(response->reuse.settings_lock));

  return res;
}
