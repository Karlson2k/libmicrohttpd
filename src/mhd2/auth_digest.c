/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2014-2025 Evgeny Grin (Karlson2k)
  Copyright (C) 2010, 2011, 2012, 2015, 2018 Christian Grothoff

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
 * @file src/mhd2/auth_digest.c
 * @brief  The implementation of the Digest Authorization internal functions
 * @author Karlson2k (Evgeny Grin)
 * Based on the MHD v0.xx code by Amr Ali, Matthieu Speder, Christian Grothoff,
 * Dirk Brinkmeier and Evgeny Grin.
 */

#include "mhd_sys_options.h"

#include "mhd_digest_auth_data.h"

#include "mhd_assert.h"
#include "mhd_unreachable.h"

#include "mhd_str_macros.h"
#include "mhd_bithelpers.h"
#include "mhd_arr_num_elems.h"
#include "mhd_cntnr_ptr.h"
#include "mhd_limits.h"

#include "mhd_str_types.h"
#include "mhd_buffer.h"
#include "mhd_daemon.h"
#include "mhd_request.h"
#include "mhd_connection.h"

#ifdef MHD_SUPPORT_SHA512_256
#  include "mhd_sha512_256.h"
#endif /* MHD_SUPPORT_SHA512_256 */
#ifdef MHD_SUPPORT_SHA256
#  include "mhd_sha256.h"
#endif
#ifdef MHD_SUPPORT_MD5
#  include "mhd_md5.h"
#endif

#include "mhd_str.h"
#include "mhd_mono_clock.h"
#include "mhd_atomic_counter.h"
#include "mhd_locks.h"

#include "request_auth_get.h"
#include "daemon_funcs.h"
#include "stream_funcs.h"
#include "stream_process_request.h"

#include "auth_digest.h"

/*
 * The maximum size of the hash digest, in bytes
 */
#if defined(MHD_SUPPORT_SHA512_256)
#  define mhd_MAX_DIGEST mhd_SHA512_256_DIGEST_SIZE
#elif defined(MHD_SUPPORT_SHA256)
#  define mhd_MAX_DIGEST mhd_SHA256_DIGEST_SIZE
#else
#  define mhd_MAX_DIGEST mhd_MD5_DIGEST_SIZE
#endif

/**
 * MD5 algorithm identifier for Digest Auth headers
 */
#define mhd_MD5_TOKEN "MD5"

/**
 * SHA-256 algorithm identifier for Digest Auth headers
 */
#define mhd_SHA256_TOKEN "SHA-256"

/**
 * SHA-512/256 algorithm for Digest Auth headers.
 */
#define mhd_SHA512_256_TOKEN "SHA-512-256"

/**
 * The suffix token for "session" algorithms for Digest Auth headers.
 */
#define mhd_SESS_TOKEN "-sess"

/**
 * The "auth" token for QOP for Digest Auth headers.
 */
#define mhd_TOKEN_AUTH "auth"

/**
 * The "auth-int" token for QOP for Digest Auth headers.
 */
#define mhd_TOKEN_AUTH_INT "auth-int"


/**
 * The required prefix of parameter with the extended notation
 */
#define mhd_DAUTH_EXT_PARAM_PREFIX "UTF-8'"

/**
 * The minimal size of the prefix for parameter with the extended notation
 */
#define mhd_DAUTH_EXT_PARAM_MIN_LEN \
        mhd_SSTR_LEN (mhd_DAUTH_EXT_PARAM_PREFIX "'")

/**
 * The maximum supported size for Digest Auth parameters, like "realm",
 * "username" etc.
 * This limitation is used only for quoted parameters.
 * Parameters without quoted backslash character will be processed as long
 * as they fit connection memory pool (buffer) size.
 */
#define mhd_AUTH_DIGEST_MAX_PARAM_SIZE (65535)

/**
 * Parameter of request's Digest Authorization header
 */
struct mhd_RqDAuthParam
{
  /**
   * The string with length, NOT zero-terminated
   */
  struct MHD_StringNullable value;
  /**
   * True if string must be "unquoted" before processing.
   * This member is false if the string is used in DQUOTE marks, but no
   * backslash-escape is used in the string.
   */
  bool quoted;
};

/**
 * Client's Digest Authorization header parameters
 */
struct mhd_AuthDigesReqParams
{
  struct mhd_RqDAuthParam nonce;
  struct mhd_RqDAuthParam opaque;
  struct mhd_RqDAuthParam response;
  struct mhd_RqDAuthParam username;
  struct mhd_RqDAuthParam username_ext;
  struct mhd_RqDAuthParam realm;
  struct mhd_RqDAuthParam uri;
  /* The raw QOP value, used in the 'response' calculation */
  struct mhd_RqDAuthParam qop_raw;
  struct mhd_RqDAuthParam cnonce;
  struct mhd_RqDAuthParam nc;

  /* Decoded values are below */
  bool userhash; /* True if 'userhash' parameter has value 'true'. */
  enum MHD_DigestAuthAlgo algo;
  enum MHD_DigestAuthQOP qop;
};

/**
 * Digest context data
 */
union DigestCtx
{
#ifdef MHD_SUPPORT_SHA512_256
  struct mhd_Sha512_256Ctx sha512_256_ctx;
#endif /* MHD_SUPPORT_SHA512_256 */
#ifdef MHD_SUPPORT_SHA256
  struct mhd_Sha256Ctx sha256_ctx;
#endif /* MHD_SUPPORT_SHA256 */
#ifdef MHD_SUPPORT_MD5
  struct mhd_Md5Ctx md5_ctx;
#endif /* MHD_SUPPORT_MD5 */
};

mhd_DATA_TRUNCATION_RUNTIME_CHECK_DISABLE

/**
 * Generate simple hash.
 * Very limited avalanche effect. To be used mainly for the table slot choice.
 * @param data_size the size of the data to hash
 * @param data the data to hash
 * @return the hash value
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (2, 1) uint_fast64_t
simple_hash (size_t data_size,
             const uint8_t *restrict data)
{
  static const uint_fast64_t c[] = { /* Some fractional parts of Euler's number */
    UINT64_C (0xCC64D3484C3475A1),
    UINT64_C (0xCF4DEBCB9ED801F2),
    UINT64_C (0x0C8737A803CF46AD),
    UINT64_C (0x294C9E0E0F9F14AB),
    UINT64_C (0xAD786D855D4EBB1A)
  };
  uint_fast64_t res;
  size_t i;

  res = UINT64_C (0x8316A8FE31A2228E); /* Some fractional part of Pi */
  i = 0;
  while (1)
  {
    uint_fast64_t a = 0;

    if (8 <= data_size)
      memcpy (&a, data, 8);
    else
      memcpy (&a, data, data_size);
    a ^= c[(i++) % mhd_ARR_NUM_ELEMS (c)];
    a = (uint_fast64_t) mhd_ROTR64 ((uint64_t) a, \
                                    (int) (res >> 58u));
    res ^= a;
    if (8 > data_size)
      break;
    data_size -= 8;
    data += 8;
  }
  return res;
}


/**
 * Find index of the provided nonce in the nonces table
 * @param nonce the nonce to use
 * @param arr_size the size of the nonces table
 * @return the index
 */
static MHD_FN_PAR_NONNULL_ALL_ size_t
nonce_to_index (const uint8_t nonce[mhd_AUTH_DIGEST_NONCE_BIN_SIZE],
                size_t arr_size)
{
  uint_fast64_t hash;
  hash = simple_hash (mhd_AUTH_DIGEST_NONCE_BIN_SIZE,
                      nonce);
  if (arr_size == (arr_size & UINT32_C (0xFFFFFFFF)))
  { /* 'arr_size' <=32-bit */
    hash = (hash ^ (hash >> 32)) & UINT32_C (0xFFFFFFFF); /* Fold hash */
    if (arr_size == (arr_size & UINT16_C (0xFFFF)))
    { /* 'arr_size' <=16-bit */
      hash = (hash ^ (hash >> 16)) & UINT16_C (0xFFFF); /* Fold hash */
      if (arr_size == (arr_size & 0xFFu))
        hash = (hash ^ (hash >> 8)) & 0xFFu; /* 'arr_size' <=8-bit, fold hash */
    }
  }
  return ((size_t) hash) % arr_size;
}


mhd_DATA_TRUNCATION_RUNTIME_CHECK_RESTORE


/**
 * Generate a new nonce
 * @param d the daemon to use (must match @a c connection)
 * @param c the connection to generate nonce for
 * @param[out] out_buf the output buffer to pull full nonce, including
 *                     "expiration" tail
 * @param[out] expir the expiration mark, duplicated for convenience
 * @return 'true' if succeed,
 *         'false' if failed
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (3)
MHD_FN_PAR_OUT_ (4) bool
gen_new_nonce (struct MHD_Daemon *restrict d,
               struct MHD_Connection *restrict c,
               uint8_t out_buf[mhd_AUTH_DIGEST_NONCE_BIN_SIZE],
               uint_fast32_t *restrict expir)
{
  uint_fast64_t expiration;
  size_t gen_num;
  union DigestCtx d_ctx;

  mhd_assert (! mhd_D_HAS_MASTER (d)); /* only master daemon should be used */
  mhd_assert (d == c->daemon);
  mhd_assert (0 != d->auth_dg.cfg.nonce_tmout);

  gen_num = mhd_atomic_counter_inc_wrap_get (&(d->auth_dg.num_gen_nonces));

  expiration = mhd_monotonic_msec_counter ()
               + d->auth_dg.cfg.nonce_tmout * (uint_fast64_t) 1000;

  // TODO: replace with pure random number

#if defined(MHD_SUPPORT_SHA512_256)
  mhd_SHA512_256_init_one_time (&(d_ctx.sha512_256_ctx));
  mhd_SHA512_256_update (&(d_ctx.sha512_256_ctx),
                         d->auth_dg.entropy.size,
                         (const void*) d->auth_dg.entropy.data);
  mhd_SHA512_256_update (&(d_ctx.sha512_256_ctx),
                         sizeof(gen_num),
                         (const void*) &gen_num);
  if (0 != c->sk.addr.size)
    mhd_SHA512_256_update (&(d_ctx.sha512_256_ctx),
                           c->sk.addr.size,
                           (const void*) c->sk.addr.data);
  mhd_SHA512_256_update (&(d_ctx.sha512_256_ctx),
                         sizeof(expiration),
                         (const void*) &expiration);
  mhd_SHA512_256_finish_deinit (&(d_ctx.sha512_256_ctx), \
                                out_buf);
  if (mhd_SHA512_256_has_err (&(d_ctx.sha512_256_ctx)))
    return false;
#elif defined(MHD_SUPPORT_SHA256)
  mhd_SHA256_init_one_time (&(d_ctx.sha256_ctx));
  mhd_SHA256_update (&(d_ctx.sha256_ctx),
                     d->auth_dg.entropy.size,
                     (const void*) d->auth_dg.entropy.data);
  mhd_SHA256_update (&(d_ctx.sha256_ctx),
                     sizeof(gen_num),
                     (const void*) &gen_num);
  if (0 != c->sk.addr.size)
    mhd_SHA256_update (&(d_ctx.sha256_ctx),
                       c->sk.addr.size,
                       (const void*) c->sk.addr.data);
  mhd_SHA256_update (&(d_ctx.sha256_ctx),
                     sizeof(expiration),
                     (const void*) &expiration);
  mhd_SHA256_finish_deinit (&(d_ctx.sha256_ctx), \
                            out_buf);
  if (mhd_SHA256_has_err (&(d_ctx.sha256_ctx)))
    return false;
#else  /* MHD_SUPPORT_MD5 */
#ifndef MHD_SUPPORT_MD5
#error At least one hashing algorithm must be enabled
#endif
  mhd_MD5_init_one_time (&(d_ctx.md5_ctx));
  mhd_MD5_update (&(d_ctx.md5_ctx),
                  d->auth_dg.entropy.size,
                  (const void*) d->auth_dg.entropy.data);
  mhd_MD5_update (&(d_ctx.md5_ctx),
                  sizeof(gen_num),
                  (const void*) &gen_num);
  if (0 != c->sk.addr.size)
    mhd_MD5_update (&(d_ctx.md5_ctx),
                    c->sk.addr.size,
                    (const void*) c->sk.addr.data);
  mhd_MD5_update (&(d_ctx.md5_ctx),
                  sizeof(expiration),
                  (const void*) &expiration);
  mhd_MD5_finish_deinit (&(d_ctx.md5_ctx), \
                         out_buf);
  if (mhd_MD5_has_err (&(d_ctx.md5_ctx)))
    return false;

  /* One more hash, for the second part */
  gen_num = mhd_atomic_counter_inc_wrap_get (&(d->auth_dg.num_gen_nonces));

  mhd_MD5_init_one_time (&(d_ctx.md5_ctx));
  mhd_MD5_update (&(d_ctx.md5_ctx),
                  d->auth_dg.entropy.size,
                  (const void*) d->auth_dg.entropy.data);
  mhd_MD5_update (&(d_ctx.md5_ctx),
                  sizeof(gen_num),
                  (const void*) &gen_num);
  if (0 != c->sk.addr.size)
    mhd_MD5_update (&(d_ctx.md5_ctx),
                    c->sk.addr.size,
                    (const void*) c->sk.addr.data);
  mhd_MD5_update (&(d_ctx.md5_ctx),
                  sizeof(expiration),
                  (const void*) &expiration);
  mhd_MD5_finish_deinit (&(d_ctx.md5_ctx), \
                         out_buf + mhd_MD5_DIGEST_SIZE);
  if (mhd_MD5_has_err (&(d_ctx.md5_ctx)))
    return false;
#endif /* MHD_SUPPORT_MD5 */

  *expir = (uint_fast32_t) (expiration / 1000u);
  mhd_PUT_32BIT_LE_UNALIGN (out_buf + mhd_AUTH_DIGEST_NONCE_RAND_BIN_SIZE, \
                            (uint32_t) (*expir & UINT32_C (0xFFFFFFFF)));

  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) bool
mhd_auth_digest_get_new_nonce (struct MHD_Connection *restrict c,
                               char out_buf[mhd_AUTH_DIGEST_NONCE_LEN])
{
  static const int max_retries = 3;
  struct MHD_Daemon *restrict d = mhd_daemon_get_master_daemon (c->daemon);
  uint8_t nonce_bin[mhd_AUTH_DIGEST_NONCE_BIN_SIZE];
  uint_fast32_t expir;
  bool nonce_generated;
  int i;

  mhd_assert (0 != d->auth_dg.cfg.nonces_num);
  mhd_assert (NULL != d->auth_dg.nonces);

  nonce_generated = false;
  for (i = 0; i < max_retries; ++i)
  {
    bool good_nonce;
    struct mhd_DaemonAuthDigestNonceData *nonce_slot;
    if (! gen_new_nonce (d,
                         c,
                         nonce_bin,
                         &expir))
      continue; /* Failed, re-try */

    nonce_generated = true;
    nonce_slot = d->auth_dg.nonces
                 + nonce_to_index (nonce_bin,
                                   d->auth_dg.cfg.nonces_num);
    if (! mhd_mutex_lock (&(d->auth_dg.nonces_lock)))
      return false; /* Failure exit point */
    /* Check whether the same nonce has been used before */
    good_nonce = (0 != memcmp (nonce_slot->nonce,
                               nonce_bin,
                               sizeof(nonce_slot->nonce)));
    if (good_nonce)
    {
      memcpy (nonce_slot->nonce,
              nonce_bin,
              sizeof(nonce_slot->nonce));
      nonce_slot->valid_time = expir;
      nonce_slot->max_recvd_nc = 0;
      nonce_slot->nmask = 0;
    }
    else
    {
      /* Check whether the same nonce has been used with different expiration
         time. */
      nonce_generated = (nonce_slot->valid_time == expir);
    }
    mhd_mutex_unlock_chk (&(d->auth_dg.nonces_lock));
    if (good_nonce)
      break;
  }
  if (! nonce_generated)
    return false; /* Failure exit point */

  /* Use the generated nonce even if it is duplicated.
     One of the clients will just get "nonce stale" response with
     the new nonce. */
  (void) mhd_bin_to_hex (nonce_bin,
                         sizeof(nonce_bin),
                         out_buf);
  return true; /* Success exit point */
}


/**
 * Get client's Digest Authorization algorithm type.
 * If no algorithm is specified by client, MD5 is assumed.
 * @param params the Digest Authorization 'algorithm' parameter
 * @return the algorithm type
 */
static enum MHD_DigestAuthAlgo
get_rq_dauth_algo (const struct mhd_RqDAuthParam *const algo_param)
{
  if (NULL == algo_param->value.cstr)
    return MHD_DIGEST_AUTH_ALGO_MD5; /* Assume MD5 by default */

  if (algo_param->quoted)
  {
    if (mhd_str_equal_caseless_quoted_s_bin_n (algo_param->value.cstr, \
                                               algo_param->value.len, \
                                               mhd_MD5_TOKEN))
      return MHD_DIGEST_AUTH_ALGO_MD5;
    if (mhd_str_equal_caseless_quoted_s_bin_n (algo_param->value.cstr, \
                                               algo_param->value.len, \
                                               mhd_SHA256_TOKEN))
      return MHD_DIGEST_AUTH_ALGO_SHA256;
    if (mhd_str_equal_caseless_quoted_s_bin_n (algo_param->value.cstr, \
                                               algo_param->value.len, \
                                               mhd_MD5_TOKEN mhd_SESS_TOKEN))
      return MHD_DIGEST_AUTH_ALGO_SHA512_256;
    if (mhd_str_equal_caseless_quoted_s_bin_n (algo_param->value.cstr, \
                                               algo_param->value.len, \
                                               mhd_SHA512_256_TOKEN \
                                               mhd_SESS_TOKEN))

      /* Algorithms below are not supported by MHD for authentication */

      return MHD_DIGEST_AUTH_ALGO_MD5_SESSION;
    if (mhd_str_equal_caseless_quoted_s_bin_n (algo_param->value.cstr, \
                                               algo_param->value.len, \
                                               mhd_SHA256_TOKEN \
                                               mhd_SESS_TOKEN))
      return MHD_DIGEST_AUTH_ALGO_SHA256_SESSION;
    if (mhd_str_equal_caseless_quoted_s_bin_n (algo_param->value.cstr, \
                                               algo_param->value.len, \
                                               mhd_SHA512_256_TOKEN))
      return MHD_DIGEST_AUTH_ALGO_SHA512_256_SESSION;

    /* No known algorithm has been detected */
    return MHD_DIGEST_AUTH_ALGO_INVALID;
  }
  /* The algorithm value is not quoted */
  if (mhd_str_equal_caseless_n_st (mhd_MD5_TOKEN, \
                                   algo_param->value.cstr, \
                                   algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO_MD5;
  if (mhd_str_equal_caseless_n_st (mhd_SHA256_TOKEN, \
                                   algo_param->value.cstr, \
                                   algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO_SHA256;
  if (mhd_str_equal_caseless_n_st (mhd_SHA512_256_TOKEN, \
                                   algo_param->value.cstr, \
                                   algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO_SHA512_256;

  /* Algorithms below are not supported by MHD for authentication */

  if (mhd_str_equal_caseless_n_st (mhd_MD5_TOKEN mhd_SESS_TOKEN, \
                                   algo_param->value.cstr, \
                                   algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO_MD5_SESSION;
  if (mhd_str_equal_caseless_n_st (mhd_SHA256_TOKEN mhd_SESS_TOKEN, \
                                   algo_param->value.cstr, \
                                   algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO_SHA256_SESSION;
  if (mhd_str_equal_caseless_n_st (mhd_SHA512_256_TOKEN mhd_SESS_TOKEN, \
                                   algo_param->value.cstr, \
                                   algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO_SHA512_256_SESSION;

  /* No known algorithm has been detected */
  return MHD_DIGEST_AUTH_ALGO_INVALID;
}


/**
 * Get QOP ('quality of protection') type.
 * @param qop_param the Digest Authorization 'QOP' parameter
 * @return detected QOP ('quality of protection') type.
 */
static enum MHD_DigestAuthQOP
get_rq_dauth_qop (const struct mhd_RqDAuthParam *const qop_param)
{
  if (NULL == qop_param->value.cstr)
    return MHD_DIGEST_AUTH_QOP_NONE;
  if (qop_param->quoted)
  {
    if (mhd_str_equal_caseless_quoted_s_bin_n (qop_param->value.cstr, \
                                               qop_param->value.len, \
                                               mhd_TOKEN_AUTH))
      return MHD_DIGEST_AUTH_QOP_AUTH;
    if (mhd_str_equal_caseless_quoted_s_bin_n (qop_param->value.cstr, \
                                               qop_param->value.len, \
                                               mhd_TOKEN_AUTH_INT))
      return MHD_DIGEST_AUTH_QOP_AUTH_INT;
  }
  else
  {
    if (mhd_str_equal_caseless_n_st (mhd_TOKEN_AUTH, \
                                     qop_param->value.cstr, \
                                     qop_param->value.len))
      return MHD_DIGEST_AUTH_QOP_AUTH;
    if (mhd_str_equal_caseless_n_st (mhd_TOKEN_AUTH_INT, \
                                     qop_param->value.cstr, \
                                     qop_param->value.len))
      return MHD_DIGEST_AUTH_QOP_AUTH_INT;
  }
  /* No know QOP has been detected */
  return MHD_DIGEST_AUTH_QOP_INVALID;
}


/**
 * Parse request Authorization header parameters for Digest Authentication
 * @param str the header string, everything after "Digest " substring
 * @param str_len the length of @a str in characters
 * @param[out] pdauth the pointer to the structure with Digest Authentication
 *               parameters
 * @return true if parameters has been successfully parsed,
 *         false if format of the @a str is invalid
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) bool
parse_dauth_params (const struct MHD_String *restrict val,
                    struct mhd_AuthDigesReqParams *restrict pdauth)
{
  /* The tokens */
  static const struct MHD_String nonce_tk = mhd_MSTR_INIT ("nonce");
  static const struct MHD_String opaque_tk = mhd_MSTR_INIT ("opaque");
  static const struct MHD_String algorithm_tk = mhd_MSTR_INIT ("algorithm");
  static const struct MHD_String response_tk = mhd_MSTR_INIT ("response");
  static const struct MHD_String username_tk = mhd_MSTR_INIT ("username");
  static const struct MHD_String username_ext_tk = mhd_MSTR_INIT ("username*");
  static const struct MHD_String realm_tk = mhd_MSTR_INIT ("realm");
  static const struct MHD_String uri_tk = mhd_MSTR_INIT ("uri");
  static const struct MHD_String qop_tk = mhd_MSTR_INIT ("qop");
  static const struct MHD_String cnonce_tk = mhd_MSTR_INIT ("cnonce");
  static const struct MHD_String nc_tk = mhd_MSTR_INIT ("nc");
  static const struct MHD_String userhash_tk = mhd_MSTR_INIT ("userhash");
  /* The locally processed parameters */
  struct mhd_RqDAuthParam userhash = { {0, NULL}, false};
  struct mhd_RqDAuthParam algorithm = { {0, NULL}, false};
  /* Indexes */
  size_t i;
  size_t p;
  /* The list of the tokens.
     The order of the elements matches the next array. */
  static const struct MHD_String *const tk_names[] = {
    &nonce_tk,          /* 0 */
    &opaque_tk,         /* 1 */
    &algorithm_tk,      /* 2 */
    &response_tk,       /* 3 */
    &username_tk,       /* 4 */
    &username_ext_tk,   /* 5 */
    &realm_tk,          /* 6 */
    &uri_tk,            /* 7 */
    &qop_tk,            /* 8 */
    &cnonce_tk,         /* 9 */
    &nc_tk,             /* 10 */
    &userhash_tk        /* 11 */
  };
  /* The list of the parameters.
     The order of the elements matches the previous array. */
  struct mhd_RqDAuthParam *params[sizeof(tk_names) / sizeof(tk_names[0])];

  params[0 ] = &(pdauth->nonce);           /* 0 */
  params[1 ] = &(pdauth->opaque);          /* 1 */
  params[2 ] = &algorithm;                 /* 2 */
  params[3 ] = &(pdauth->response);        /* 3 */
  params[4 ] = &(pdauth->username);        /* 4 */
  params[5 ] = &(pdauth->username_ext);    /* 5 */
  params[6 ] = &(pdauth->realm);           /* 6 */
  params[7 ] = &(pdauth->uri);             /* 7 */
  params[8 ] = &(pdauth->qop_raw);         /* 8 */
  params[9 ] = &(pdauth->cnonce);          /* 9 */
  params[10] = &(pdauth->nc);              /* 10 */
  params[11] = &userhash;                  /* 11 */

  mhd_assert (mhd_ARR_NUM_ELEMS (tk_names) == \
              mhd_ARR_NUM_ELEMS (params));
  i = 0;

  mhd_assert (' ' != val->cstr[0]);
  mhd_assert ('\t' != val->cstr[0]);

  while (val->len > i)
  {
    size_t left;
    mhd_assert (' ' != val->cstr[i]);
    mhd_assert ('\t' != val->cstr[i]);

    left = val->len - i;
    if ('=' == val->cstr[i])
      return false; /* The equal sign is not allowed as the first character */
    for (p = 0; p < mhd_ARR_NUM_ELEMS (tk_names); ++p)
    {
      const struct MHD_String *const tk_name = tk_names[p];
      struct mhd_RqDAuthParam *const param = params[p];
      if ( (tk_name->len <= left) &&
           mhd_str_equal_caseless_bin_n (val->cstr + i, tk_name->cstr,
                                         tk_name->len) &&
           ((tk_name->len == left) ||
            ('=' == val->cstr[i + tk_name->len]) ||
            (' ' == val->cstr[i + tk_name->len]) ||
            ('\t' == val->cstr[i + tk_name->len]) ||
            (',' == val->cstr[i + tk_name->len]) ||
            (';' == val->cstr[i + tk_name->len])) )
      {
        size_t value_start;
        size_t value_len;
        bool quoted; /* Only mark as "quoted" if backslash-escape used */

        if (tk_name->len == left)
          return false; /* No equal sign after parameter name, broken data */

        quoted = false;
        i += tk_name->len;
        /* Skip all whitespaces before '=' */
        while (val->len > i && (' ' == val->cstr[i] || '\t' == val->cstr[i]))
          i++;
        if ((i == val->len) || ('=' != val->cstr[i]))
          return false; /* No equal sign, broken data */
        i++;
        /* Skip all whitespaces after '=' */
        while (val->len > i && (' ' == val->cstr[i] || '\t' == val->cstr[i]))
          i++;
        if ((val->len > i) && ('"' == val->cstr[i]))
        { /* Value is in quotation marks */
          i++; /* Advance after the opening quote */
          value_start = i;
          while (val->len > i && '"' != val->cstr[i])
          {
            if ('\\' == val->cstr[i])
            {
              i++;
              quoted = true; /* Have escaped chars */
            }
            if (0 == val->cstr[i])
              return false; /* Binary zero in parameter value */
            i++;
          }
          if (val->len <= i)
            return false; /* No closing quote */
          mhd_assert ('"' == val->cstr[i]);
          value_len = i - value_start;
          i++; /* Advance after the closing quote */
        }
        else
        {
          value_start = i;
          while ((val->len > i) && (',' != val->cstr[i])
                 && (' ' != val->cstr[i]) && ('\t' != val->cstr[i])
                 && (';' != val->cstr[i]))
          {
            if (0 == val->cstr[i])
              return false;  /* Binary zero in parameter value */
            i++;
          }
          if (';' == val->cstr[i])
            return false;  /* Semicolon in parameter value */
          value_len = i - value_start;
        }
        /* Skip all whitespaces after parameter value */
        while (val->len > i && (' ' == val->cstr[i] || '\t' == val->cstr[i]))
          i++;
        if ((val->len > i) && (',' != val->cstr[i]))
          return false; /* Garbage after parameter value */

        /* Have valid parameter name and value */
        mhd_assert (! quoted || 0 != value_len);
        param->value.cstr = val->cstr + value_start;
        param->value.len = value_len;
        param->quoted = quoted;

        break; /* Found matching parameter name */
      }
    }
    if (p == mhd_ARR_NUM_ELEMS (tk_names))
    {
      /* No matching parameter name */
      while (val->len > i && ',' != val->cstr[i])
      {
        if ((0 == val->cstr[i]) || (';' == val->cstr[i]))
          return false; /* Not allowed characters */
        if ('"' == val->cstr[i])
        { /* Skip quoted part */
          i++; /* Advance after the opening quote */
          while (val->len > i && '"' != val->cstr[i])
          {
            if (0 == val->cstr[i])
              return false;  /* Binary zero is not allowed */
            if ('\\' == val->cstr[i])
              i++;           /* Skip escaped char */
            i++;
          }
          if (val->len <= i)
            return false; /* No closing quote */
          mhd_assert ('"' == val->cstr[i]);
        }
        i++;
      }
    }
    mhd_assert (val->len == i || ',' == val->cstr[i]);
    if (val->len > i)
      i++; /* Advance after ',' */
    /* Skip all whitespaces before next parameter name */
    while (i < val->len && (' ' == val->cstr[i] || '\t' == val->cstr[i]))
      i++;
  }

  /* Postprocess values */

  if (NULL != userhash.value.cstr)
  {
    if (userhash.quoted)
      pdauth->userhash =
        mhd_str_equal_caseless_quoted_s_bin_n (userhash.value.cstr, \
                                               userhash.value.len, \
                                               "true");
    else
      pdauth->userhash =
        mhd_str_equal_caseless_n_st ("true", userhash.value.cstr, \
                                     userhash.value.len);

  }
  else
    pdauth->userhash = false;

  pdauth->algo = get_rq_dauth_algo (&algorithm);
  pdauth->qop = get_rq_dauth_qop (&pdauth->qop_raw);

  return true;
}


/**
 * Find and pre-parse request's Digest Authorisation parameters.
 *
 * Function returns result of pre-parsing of the request's "Authorization"
 * header or returns cached result if the header has been already pre-parsed for
 * the current request.
 * @param req the request to process
 * @return #MHD_SC_OK if succeed,
 *         #MHD_SC_AUTH_ABSENT if request has no Digest Authorisation,
 *         #MHD_SC_CONNECTION_POOL_NO_MEM_AUTH_DATA if not enough memory,
 *         #MHD_SC_REQ_AUTH_DATA_BROKEN if the header is broken.
 */
static MHD_FN_PAR_NONNULL_ALL_ enum MHD_StatusCode
get_rq_auth_digest_params (struct MHD_Request *restrict req)
{
  struct MHD_String h_auth_value;
  struct mhd_AuthDigesReqParams *dauth;

  mhd_assert (mhd_HTTP_STAGE_HEADERS_PROCESSED <= \
              mhd_CNTNR_CPTR (req, struct MHD_Connection, rq)->stage);
  mhd_assert (mhd_HTTP_STAGE_REQ_RECV_FINISHED >= \
              mhd_CNTNR_CPTR (req, struct MHD_Connection, rq)->stage);

  if (NULL != req->auth.digest.rqp)
    return MHD_SC_OK;

  if (! mhd_request_get_auth_header_value (req,
                                           mhd_AUTH_HDR_DIGEST,
                                           &h_auth_value))
    return MHD_SC_AUTH_ABSENT;

  dauth =
    (struct mhd_AuthDigesReqParams *)
    mhd_stream_alloc_memory (mhd_CNTNR_PTR (req, \
                                            struct MHD_Connection, \
                                            rq),
                             sizeof (struct mhd_AuthDigesReqParams));

  if (NULL == dauth)
    return MHD_SC_CONNECTION_POOL_NO_MEM_AUTH_DATA;

  memset (dauth, 0, sizeof(struct mhd_AuthDigesReqParams));
  if (! parse_dauth_params (&h_auth_value,
                            dauth))
    return MHD_SC_REQ_AUTH_DATA_BROKEN;

  req->auth.digest.rqp = dauth;

  return MHD_SC_OK;
}


/**
 * Get username type used by the client.
 * This function does not check whether userhash can be decoded or
 * extended notation (if used) is valid.
 * @param params the Digest Authorization parameters
 * @return the type of username
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ enum MHD_DigestAuthUsernameType
get_rq_uname_type (const struct mhd_AuthDigesReqParams *params)
{
  if (NULL != params->username.value.cstr)
  {
    if (NULL == params->username_ext.value.cstr)
      return params->userhash ?
             MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH :
             MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD;
    else  /* Both 'username' and 'username*' are used */
      return MHD_DIGEST_AUTH_UNAME_TYPE_INVALID;
  }
  else if (NULL != params->username_ext.value.cstr)
  {
    if (! params->username_ext.quoted && ! params->userhash &&
        (mhd_DAUTH_EXT_PARAM_MIN_LEN <= params->username_ext.value.len) )
      return MHD_DIGEST_AUTH_UNAME_TYPE_EXTENDED;
    else
      return MHD_DIGEST_AUTH_UNAME_TYPE_INVALID;
  }

  return MHD_DIGEST_AUTH_UNAME_TYPE_MISSING;
}


/**
 * Get total size required for 'username' and 'userhash_bin'
 * @param params the Digest Authorization parameters
 * @param uname_type the type of username
 * @return the total size required for 'username' and
 *         'userhash_bin' is userhash is used
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ size_t
get_rq_unames_size (const struct mhd_AuthDigesReqParams *params,
                    enum MHD_DigestAuthUsernameType uname_type)
{
  size_t s;

  mhd_assert (get_rq_uname_type (params) == uname_type);
  s = 0;
  if ((MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD == uname_type) ||
      (MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH == uname_type) )
  {
    s += params->username.value.len + 1; /* Add one byte for zero-termination */
    if (MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH == uname_type)
      s += (params->username.value.len + 1) / 2;
  }
  else if (MHD_DIGEST_AUTH_UNAME_TYPE_EXTENDED == uname_type)
    s += params->username_ext.value.len
         - mhd_DAUTH_EXT_PARAM_MIN_LEN + 1; /* Add one byte for zero-termination */
  return s;
}


/**
 * Get unquoted version of Digest Authorization parameter.
 * This function automatically zero-teminate the result.
 * @param param the parameter to extract
 * @param[out] buf the output buffer, must have enough size to hold the result,
 *                 the recommended size is 'param->value.len + 1'
 * @return the size of the result, not including the terminating zero
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) size_t
get_rq_param_unquoted_copy_z (const struct mhd_RqDAuthParam *restrict param,
                              char *restrict buf)
{
  size_t len;
  mhd_assert (NULL != param->value.cstr);
  if (! param->quoted)
  {
    memcpy (buf, param->value.cstr, param->value.len);
    buf [param->value.len] = 0;
    return param->value.len;
  }

  len = mhd_str_unquote (param->value.cstr, param->value.len, buf);
  mhd_assert (0 != len);
  mhd_assert (len < param->value.len);
  buf[len] = 0;
  return len;
}


/**
 * Get decoded version of username from extended notation.
 * This function automatically zero-teminate the result.
 * @param uname_ext the string of client's 'username*' parameter value
 * @param uname_ext_len the length of @a uname_ext in chars
 * @param[out] buf the output buffer to put decoded username value
 * @param buf_size the size of @a buf
 * @return the number of characters copied to the output buffer or
 *         -1 if wrong extended notation is used.
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (1,2)
MHD_FN_PAR_OUT_SIZE_ (3,4) ssize_t
get_rq_extended_uname_copy_z (const char *restrict uname_ext,
                              size_t uname_ext_len,
                              char *restrict buf,
                              size_t buf_size)
{
  size_t r;
  size_t w;
  if ((size_t) SSIZE_MAX < uname_ext_len)
    return -1; /* Too long input string */

  if (mhd_DAUTH_EXT_PARAM_MIN_LEN > uname_ext_len)
    return -1; /* Required prefix is missing */

  if (! mhd_str_equal_caseless_bin_n (
        uname_ext,
        mhd_DAUTH_EXT_PARAM_PREFIX,
        mhd_SSTR_LEN (mhd_DAUTH_EXT_PARAM_PREFIX)))
    return -1; /* Only UTF-8 is supported, as it is implied by RFC 7616 */

  r = mhd_SSTR_LEN (mhd_DAUTH_EXT_PARAM_PREFIX);
  /* Skip language tag */
  while (r < uname_ext_len && '\'' != uname_ext[r])
  {
    const char chr = uname_ext[r];
    if ((' ' == chr) || ('\t' == chr) || ('\"' == chr) || (',' == chr) ||
        (';' == chr) )
      return -1; /* Wrong char in language tag */
    r++;
  }
  if (r >= uname_ext_len)
    return -1; /* The end of the language tag was not found */
  r++; /* Advance to the next char */

  w = mhd_str_pct_decode_strict_n (uname_ext + r, uname_ext_len - r,
                                   buf, buf_size);
  if ((0 == w) && (0 != uname_ext_len - r))
    return -1; /* Broken percent encoding */
  buf[w] = 0; /* Zero terminate the result */
  mhd_assert (SSIZE_MAX > w);
  return (ssize_t) w;
}


/**
 * Get copy of username used by the client.
 * @param params the Digest Authorization parameters
 * @param uname_type the type of username
 * @param[out] uname_info the pointer to the structure to be filled
 * @param buf the buffer to be used for usernames
 * @param buf_size the size of the @a buf
 * @return the size of the @a buf used by pointers in @a unames structure
 */
static size_t
get_rq_uname (const struct mhd_AuthDigesReqParams *restrict params,
              enum MHD_DigestAuthUsernameType uname_type,
              struct MHD_AuthDigestUsernameInfo *restrict uname_info,
              uint8_t *restrict buf,
              size_t buf_size)
{
  size_t buf_used;

  buf_used = 0;
  mhd_assert (get_rq_uname_type (params) == uname_type);
  mhd_assert (MHD_DIGEST_AUTH_UNAME_TYPE_INVALID != uname_type);
  mhd_assert (MHD_DIGEST_AUTH_UNAME_TYPE_MISSING != uname_type);

  uname_info->username.cstr = NULL;
  uname_info->username.len = 0;
  uname_info->userhash_hex.cstr = NULL;
  uname_info->userhash_hex.len = 0;
  uname_info->userhash_bin = NULL;

  if (MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD == uname_type)
  {
    // TODO: Avoid copying string if not quoted
    uname_info->username.cstr = (char *) (buf + buf_used);
    uname_info->username.len =
      get_rq_param_unquoted_copy_z (&params->username,
                                    (char *) (buf + buf_used));
    buf_used += uname_info->username.len + 1;
    uname_info->uname_type = MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD;
  }
  else if (MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH == uname_type)
  {
    size_t res;

    uname_info->userhash_hex.cstr = (char *) (buf + buf_used);
    uname_info->userhash_hex.len =
      get_rq_param_unquoted_copy_z (&params->username,
                                    (char *) (buf + buf_used));
    buf_used += uname_info->userhash_hex.len + 1;
    uname_info->userhash_bin = (uint8_t *) (buf + buf_used);
    res = mhd_hex_to_bin (uname_info->userhash_hex.cstr,
                          uname_info->userhash_hex.len,
                          (uint8_t *) (buf + buf_used));
    if (res != uname_info->userhash_hex.len / 2)
    {
      uname_info->userhash_bin = NULL;
      uname_info->uname_type = MHD_DIGEST_AUTH_UNAME_TYPE_INVALID;
    }
    else
    {
      /* Avoid pointers outside allocated region when the size is zero */
      if (0 == res)
        uname_info->userhash_bin = (const uint8_t *) uname_info->username.cstr;
      uname_info->uname_type = MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH;
      buf_used += res;
    }
  }
  else if (MHD_DIGEST_AUTH_UNAME_TYPE_EXTENDED == uname_type)
  {
    ssize_t res;
    res = get_rq_extended_uname_copy_z (params->username_ext.value.cstr,
                                        params->username_ext.value.len,
                                        (char *) (buf + buf_used),
                                        buf_size - buf_used);
    if (0 > res)
      uname_info->uname_type = MHD_DIGEST_AUTH_UNAME_TYPE_INVALID;
    else
    {
      uname_info->username.cstr = (char *) (buf + buf_used);
      uname_info->username.len = (size_t) res;
      uname_info->uname_type = MHD_DIGEST_AUTH_UNAME_TYPE_EXTENDED;
      buf_used += uname_info->username.len + 1;
    }
  }
  else
  {
    mhd_assert (0);
    uname_info->uname_type = MHD_DIGEST_AUTH_UNAME_TYPE_INVALID;
  }
  mhd_assert (buf_size >= buf_used);
  return buf_used;
}


/**
 * Result of request's Digest Authorization 'nc' value extraction
 */
enum MHD_FIXED_ENUM_ mhd_GetRqNCResult
{
  mhd_GET_RQ_NC_NONE = MHD_DIGEST_AUTH_NC_NONE,    /**< No 'nc' value */
  mhd_GET_RQ_NC_VALID = MHD_DIGEST_AUTH_NC_NUMBER, /**< Readable 'nc' value */
  mhd_GET_RQ_NC_TOO_LONG = MHD_DIGEST_AUTH_NC_TOO_LONG, /**< The 'nc' value is too long */
  mhd_GET_RQ_NC_TOO_LARGE = MHD_DIGEST_AUTH_NC_TOO_LARGE, /**< The 'nc' value is too big to fit uint32_t */
  mhd_GET_RQ_NC_BROKEN = 0                         /**< The 'nc' value is not a number */
};


/**
 * Get 'nc' value from request's Authorization header
 * @param params the request digest authentication
 * @param[out] nc the pointer to put nc value to
 * @return enum value indicating the result
 */
static enum mhd_GetRqNCResult
get_rq_nc (const struct mhd_AuthDigesReqParams *params,
           uint_fast32_t *nc)
{
  const struct mhd_RqDAuthParam *const nc_param =
    &params->nc;
  char unq[16];
  const char *val;
  size_t val_len;
  size_t res;
  uint64_t nc_val;

  if (NULL == nc_param->value.cstr)
    return mhd_GET_RQ_NC_NONE;

  if (0 == nc_param->value.len)
    return mhd_GET_RQ_NC_BROKEN;

  if (! nc_param->quoted)
  {
    val = nc_param->value.cstr;
    val_len = nc_param->value.len;
  }
  else
  {
    /* Actually no backslashes must be used in 'nc' */
    if (sizeof(unq) < params->nc.value.len)
      return mhd_GET_RQ_NC_TOO_LONG;
    val_len = mhd_str_unquote (nc_param->value.cstr, nc_param->value.len, unq);
    if (0 == val_len)
      return mhd_GET_RQ_NC_BROKEN;
    val = unq;
  }

  res = mhd_strx_to_uint64_n (val,
                              val_len,
                              &nc_val);
  if (0 == res)
  {
    const char f = val[0];
    if ( (('9' >= f) && ('0' <= f)) ||
         (('F' >= f) && ('A' <= f)) ||
         (('a' <= f) && ('f' >= f)) )
      return mhd_GET_RQ_NC_TOO_LARGE;
    else
      return mhd_GET_RQ_NC_BROKEN;
  }
  if (val_len != res)
    return mhd_GET_RQ_NC_BROKEN;
  if (nc_val != (nc_val & UINT64_C (0xFFFFFFFF)))
    return mhd_GET_RQ_NC_TOO_LARGE;
  *nc = (uint_fast32_t) nc_val;
  return mhd_GET_RQ_NC_VALID;
}


static MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
enum MHD_StatusCode
find_and_parse_auth_digest_uname (struct MHD_Request *restrict req)
{
  enum MHD_StatusCode res;
  struct MHD_AuthDigestUsernameInfo *uname_info;
  enum MHD_DigestAuthUsernameType uname_type;
  size_t unif_buf_size;
  uint8_t *unif_buf_ptr;
  size_t unif_buf_used;

  mhd_assert (NULL == req->auth.digest.info);
  mhd_assert (NULL == req->auth.digest.uname);

  res = get_rq_auth_digest_params (req);
  if (MHD_SC_OK != res)
    return res;

  mhd_assert (NULL != req->auth.digest.rqp);

  uname_type = get_rq_uname_type (req->auth.digest.rqp);
  if ( (MHD_DIGEST_AUTH_UNAME_TYPE_MISSING == uname_type) ||
       (MHD_DIGEST_AUTH_UNAME_TYPE_INVALID == uname_type) )
    return MHD_SC_REQ_AUTH_DATA_BROKEN;

  unif_buf_size = get_rq_unames_size (req->auth.digest.rqp, uname_type);

  uname_info =
    (struct MHD_AuthDigestUsernameInfo *)
    mhd_stream_alloc_memory (mhd_CNTNR_PTR (req, struct MHD_Connection, rq),
                             (sizeof(struct MHD_AuthDigestUsernameInfo))
                             + unif_buf_size);
  if (NULL == uname_info)
    return MHD_SC_CONNECTION_POOL_NO_MEM_AUTH_DATA;
  memset (uname_info,
          0,
          (sizeof(struct MHD_AuthDigestUsernameInfo)) + unif_buf_size);
#ifndef HAVE_NULL_PTR_ALL_ZEROS
  uname_info->username.cstr = NULL;
  uname_info->userhash_hex.cstr = NULL;
  uname_info->userhash_bin = NULL;
#endif

  uname_info->algo = req->auth.digest.rqp->algo;
  unif_buf_ptr = (uint8_t *) (uname_info + 1);
  unif_buf_used = get_rq_uname (req->auth.digest.rqp,
                                uname_type, uname_info,
                                unif_buf_ptr,
                                unif_buf_size);
  mhd_assert (unif_buf_size >= unif_buf_used);
  (void) unif_buf_used; /* Mute compiler warning on non-debug builds */
  mhd_assert (MHD_DIGEST_AUTH_UNAME_TYPE_MISSING != uname_info->uname_type);

  req->auth.digest.uname = uname_info;
  if (MHD_DIGEST_AUTH_UNAME_TYPE_INVALID == uname_info->uname_type)
    return MHD_SC_REQ_AUTH_DATA_BROKEN;
  mhd_assert (uname_type == uname_info->uname_type);

  return MHD_SC_OK;
}


MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) enum MHD_StatusCode
mhd_request_get_auth_digest_username (
  struct MHD_Request *restrict req,
  const struct MHD_AuthDigestUsernameInfo **restrict v_auth_digest_uname)
{
  mhd_assert (mhd_HTTP_STAGE_HEADERS_PROCESSED <= \
              mhd_CNTNR_CPTR (req, struct MHD_Connection, rq)->stage);
  mhd_assert (mhd_HTTP_STAGE_REQ_RECV_FINISHED >= \
              mhd_CNTNR_CPTR (req, struct MHD_Connection, rq)->stage);

  if (MHD_SC_OK != req->auth.digest.parse_result)
    return req->auth.digest.parse_result;

  if (NULL == req->auth.digest.uname)
    req->auth.digest.parse_result = find_and_parse_auth_digest_uname (req);

  if (MHD_SC_OK != req->auth.digest.parse_result)
    return req->auth.digest.parse_result; /* Failure exit point */

  mhd_assert (NULL != req->auth.digest.uname);
  *v_auth_digest_uname = req->auth.digest.uname;

  return MHD_SC_OK; /* Success exit point */
}


static MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
enum MHD_StatusCode
find_and_parse_auth_digest_info (struct MHD_Request *restrict req)
{
  enum MHD_StatusCode res;
  struct MHD_AuthDigestInfo *info;
  enum MHD_DigestAuthUsernameType uname_type;
  size_t unif_buf_size;
  uint8_t *unif_buf_ptr;
  size_t unif_buf_used;
  enum mhd_GetRqNCResult nc_res;

  mhd_assert (NULL == req->auth.digest.info);

  res = get_rq_auth_digest_params (req);
  if (MHD_SC_OK != res)
    return res;

  unif_buf_size = 0;

  uname_type = get_rq_uname_type (req->auth.digest.rqp);

  unif_buf_size += get_rq_unames_size (req->auth.digest.rqp,
                                       uname_type);

  if (NULL != req->auth.digest.rqp->opaque.value.cstr)
    unif_buf_size += req->auth.digest.rqp->opaque.value.len + 1;  /* Add one for zero-termination */
  if (NULL != req->auth.digest.rqp->realm.value.cstr)
    unif_buf_size += req->auth.digest.rqp->realm.value.len + 1;   /* Add one for zero-termination */
  info =
    (struct MHD_AuthDigestInfo *)
    mhd_stream_alloc_memory (mhd_CNTNR_PTR (req, struct MHD_Connection, rq),
                             (sizeof(struct MHD_AuthDigestInfo))
                             + unif_buf_size);
  if (NULL == info)
    return MHD_SC_CONNECTION_POOL_NO_MEM_AUTH_DATA;

  memset (info,
          0,
          (sizeof(struct MHD_AuthDigestInfo)) + unif_buf_size);
#ifndef HAVE_NULL_PTR_ALL_ZEROS
  info->username.cstr = NULL;
  info->userhash_hex.cstr = NULL;
  info->userhash_bin = NULL;
  info->opaque.cstr = NULL;
  info->realm.cstr = NULL;
#endif

  unif_buf_ptr = (uint8_t *) (info + 1);
  unif_buf_used = 0;

  info->algo = req->auth.digest.rqp->algo;

  if ( (MHD_DIGEST_AUTH_UNAME_TYPE_MISSING != uname_type) &&
       (MHD_DIGEST_AUTH_UNAME_TYPE_INVALID != uname_type) )
    unif_buf_used +=
      get_rq_uname (req->auth.digest.rqp, uname_type,
                    (struct MHD_AuthDigestUsernameInfo *) info,
                    unif_buf_ptr + unif_buf_used,
                    unif_buf_size - unif_buf_used);
  else
    info->uname_type = uname_type;

  if (NULL != req->auth.digest.rqp->opaque.value.cstr)
  {
    info->opaque.cstr = (char *) (unif_buf_ptr + unif_buf_used);
    info->opaque.len =
      get_rq_param_unquoted_copy_z (&(req->auth.digest.rqp->opaque),
                                    (char *) (unif_buf_ptr + unif_buf_used));
    unif_buf_used += info->opaque.len + 1;
  }
  if (NULL != req->auth.digest.rqp->realm.value.cstr)
  {
    info->realm.cstr = (char *) (unif_buf_ptr + unif_buf_used);
    info->realm.len =
      get_rq_param_unquoted_copy_z (&(req->auth.digest.rqp->realm),
                                    (char *) (unif_buf_ptr + unif_buf_used));
    unif_buf_used += info->realm.len + 1;
  }

  mhd_assert (unif_buf_size >= unif_buf_used);

  info->qop = req->auth.digest.rqp->qop;

  if (NULL != req->auth.digest.rqp->cnonce.value.cstr)
    info->cnonce_len = req->auth.digest.rqp->cnonce.value.len;
  else
    info->cnonce_len = 0;

  nc_res = get_rq_nc (req->auth.digest.rqp, &info->nc);
  if (mhd_GET_RQ_NC_VALID == nc_res)
  {
    if (0 == info->nc)
      info->nc_type = MHD_DIGEST_AUTH_NC_ZERO;
    else
      info->nc_type = MHD_DIGEST_AUTH_NC_NUMBER;
  }
  else
  {
    info->nc = 0;
    if (mhd_GET_RQ_NC_BROKEN == nc_res)
      info->nc_type = MHD_DIGEST_AUTH_NC_NONE;
    else
      info->nc_type = (enum MHD_DigestAuthNC) nc_res;
  }

  req->auth.digest.info = info;
  if (NULL == req->auth.digest.uname)
    req->auth.digest.uname = (struct MHD_AuthDigestUsernameInfo *) info;

  mhd_assert (uname_type == info->uname_type);
  mhd_assert (uname_type == req->auth.digest.uname->uname_type);

  if ((MHD_DIGEST_AUTH_UNAME_TYPE_MISSING == uname_type) ||
      (MHD_DIGEST_AUTH_UNAME_TYPE_INVALID == uname_type) ||
      ((mhd_GET_RQ_NC_BROKEN == nc_res)))
    return MHD_SC_REQ_AUTH_DATA_BROKEN;

  return MHD_SC_OK;
}


MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) enum MHD_StatusCode
mhd_request_get_auth_digest_info (
  struct MHD_Request *restrict req,
  const struct MHD_AuthDigestInfo **restrict v_auth_digest_info)
{
  mhd_assert (mhd_HTTP_STAGE_HEADERS_PROCESSED <= \
              mhd_CNTNR_CPTR (req, struct MHD_Connection, rq)->stage);
  mhd_assert (mhd_HTTP_STAGE_REQ_RECV_FINISHED >= \
              mhd_CNTNR_CPTR (req, struct MHD_Connection, rq)->stage);

  if (MHD_SC_OK != req->auth.digest.parse_result)
    return req->auth.digest.parse_result;

  if (NULL == req->auth.digest.info)
    req->auth.digest.parse_result = find_and_parse_auth_digest_info (req);

  if (MHD_SC_OK != req->auth.digest.parse_result)
    return req->auth.digest.parse_result; /* Failure exit point */

  mhd_assert (NULL != req->auth.digest.info);
  mhd_assert (NULL != req->auth.digest.uname);
  *v_auth_digest_info = req->auth.digest.info;

  return MHD_SC_OK; /* Success exit point */
}


/**
 * Get base hash calculation algorithm from #MHD_DigestAuthAlgo value.
 * @param algo the MHD_DigestAuthAlgo value
 * @return the base hash calculation algorithm
 */
MHD_static_inline_ enum MHD_DigestBaseAlgo
get_base_digest_algo (enum MHD_DigestAuthAlgo algo)
{
  unsigned int base_algo;

  base_algo =
    ((unsigned int) algo)
    & ~((unsigned int)
        (MHD_DIGEST_AUTH_ALGO_NON_SESSION
         | MHD_DIGEST_AUTH_ALGO_SESSION));
  return (enum MHD_DigestBaseAlgo) base_algo;
}


/**
 * Get digest size in bytes for specified algorithm.
 *
 * Internal inline version.
 * @param algo the algorithm to check
 * @return the size of the digest (in bytes) or zero if the input value is not
 *         supported/valid
 */
MHD_static_inline_ size_t
digest_get_hash_size (enum MHD_DigestAuthAlgo algo)
{
#ifdef MHD_SUPPORT_MD5
  mhd_assert (MHD_MD5_DIGEST_SIZE == mhd_MD5_DIGEST_SIZE);
#endif /* MHD_SUPPORT_MD5 */
#ifdef MHD_SUPPORT_SHA256
  mhd_assert (MHD_SHA256_DIGEST_SIZE == mhd_SHA256_DIGEST_SIZE);
#endif /* MHD_SUPPORT_SHA256 */
#ifdef MHD_SUPPORT_SHA512_256
  mhd_assert (MHD_SHA512_256_DIGEST_SIZE == mhd_SHA512_256_DIGEST_SIZE);
#ifdef MHD_SUPPORT_SHA256
  mhd_assert (mhd_SHA256_DIGEST_SIZE == mhd_SHA512_256_DIGEST_SIZE);
#endif /* MHD_SUPPORT_SHA256 */
#endif /* MHD_SUPPORT_SHA512_256 */
  /* Only one algorithm must be specified */
  mhd_assert (1 == \
              (((0 != (algo & MHD_DIGEST_BASE_ALGO_MD5)) ? 1 : 0)   \
               + ((0 != (algo & MHD_DIGEST_BASE_ALGO_SHA256)) ? 1 : 0)   \
               + ((0 != (algo & MHD_DIGEST_BASE_ALGO_SHA512_256)) ? 1 : 0)));
#ifdef MHD_SUPPORT_MD5
  if (0 != (((unsigned int) algo)
            & ((unsigned int) MHD_DIGEST_BASE_ALGO_MD5)))
    return MHD_MD5_DIGEST_SIZE;
  else
#endif /* MHD_SUPPORT_MD5 */
#if defined(MHD_SUPPORT_SHA256) && defined(MHD_SUPPORT_SHA512_256)
  if (0 != (((unsigned int) algo)
            & ( ((unsigned int) MHD_DIGEST_BASE_ALGO_SHA256)
                | ((unsigned int) MHD_DIGEST_BASE_ALGO_SHA512_256))))
    return MHD_SHA256_DIGEST_SIZE; /* The same as mhd_SHA512_256_DIGEST_SIZE */
  else
#elif defined(MHD_SUPPORT_SHA256)
  if (0 != (((unsigned int) algo)
            & ((unsigned int) MHD_DIGEST_BASE_ALGO_SHA256)))
    return MHD_SHA256_DIGEST_SIZE;
  else
#elif defined(MHD_SUPPORT_SHA512_256)
  if (0 != (((unsigned int) algo)
            & ((unsigned int) MHD_DIGEST_BASE_ALGO_SHA512_256)))
    return MHD_SHA512_256_DIGEST_SIZE;
  else
#endif /* MHD_SUPPORT_SHA512_256 */
    (void) 0; /* Unsupported algorithm */

  return 0; /* Wrong input or unsupported algorithm */
}


/**
 * Get digest size for specified algorithm.
 *
 * The size of the digest specifies the size of the userhash, userdigest
 * and other parameters which size depends on used hash algorithm.
 * @param algo the algorithm to check
 * @return the size of the digest (either #MHD_MD5_DIGEST_SIZE or
 *         #MHD_SHA256_DIGEST_SIZE/MHD_SHA512_256_DIGEST_SIZE)
 *         or zero if the input value is not supported or not valid
 * @sa #MHD_digest_auth_calc_userdigest()
 * @sa #MHD_digest_auth_calc_userhash(), #MHD_digest_auth_calc_userhash_hex()
 * @note Available since #MHD_VERSION 0x00097701
 * @ingroup authentication
 */
MHD_EXTERN_ MHD_FN_CONST_ size_t
MHD_digest_get_hash_size (enum MHD_DigestAuthAlgo algo)
{
  return digest_get_hash_size (algo);
}


/**
 * The digest calculation structure.
 */
struct DigestAlgorithm
{
  /**
   * A context for the digest algorithm, already initialized to be
   * useful for @e init, @e update and @e digest.
   */
  union DigestCtx ctx;

  /**
   * The hash calculation algorithm.
   */
  enum MHD_DigestBaseAlgo algo;

  /**
   * Buffer for hex-print of the final digest.
   */
#ifdef _DEBUG
  bool uninitialised; /**< The structure has been not set-up */
  bool algo_selected; /**< The algorithm has been selected */
  bool ready_for_hashing; /**< The structure is ready to hash data */
  bool hashing; /**< Some data has been hashed, but the digest has not finalised yet */
#endif /* _DEBUG */
};


/**
 * Return the size of the digest.
 * @param da the digest calculation structure to identify
 * @return the size of the digest.
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ unsigned int
digest_get_size (struct DigestAlgorithm *da)
{
  mhd_assert (! da->uninitialised);
  mhd_assert (da->algo_selected);
#ifdef MHD_SUPPORT_MD5
  if (MHD_DIGEST_BASE_ALGO_MD5 == da->algo)
    return mhd_MD5_DIGEST_SIZE;
#endif /* MHD_SUPPORT_MD5 */
#ifdef MHD_SUPPORT_SHA256
  if (MHD_DIGEST_BASE_ALGO_SHA256 == da->algo)
    return mhd_SHA256_DIGEST_SIZE;
#endif /* MHD_SUPPORT_SHA256 */
#ifdef MHD_SUPPORT_SHA512_256
  if (MHD_DIGEST_BASE_ALGO_SHA512_256 == da->algo)
    return mhd_SHA512_256_DIGEST_SIZE;
#endif /* MHD_SUPPORT_SHA512_256 */
  mhd_UNREACHABLE ();
  return 0;
}


#if defined(mhd_MD5_HAS_DEINIT) \
  || defined(mhd_SHA256_HAS_DEINIT) \
  || defined(mhd_SHA512_256_HAS_DEINIT)
/**
 * Indicates presence of digest_deinit() function
 */
#define mhd_DIGEST_HAS_DEINIT 1
#endif /* mhd_MD5_HAS_DEINIT || mhd_SHA256_HAS_DEINIT */

#ifdef mhd_DIGEST_HAS_DEINIT
/**
 * Zero-initialise digest calculation structure.
 *
 * This initialisation is enough to safely call #digest_deinit() only.
 * To make any real digest calculation, #digest_setup_and_init() must be called.
 * @param da the digest calculation
 */
MHD_static_inline_ void
digest_setup_zero (struct DigestAlgorithm *da)
{
#ifdef _DEBUG
  da->uninitialised = false;
  da->algo_selected = false;
  da->ready_for_hashing = false;
  da->hashing = false;
#endif /* _DEBUG */
  da->algo = MHD_DIGEST_BASE_ALGO_INVALID;
}


/**
 * De-initialise digest calculation structure.
 *
 * This function must be called if #digest_setup_and_init() was called for
 * @a da.
 * This function must not be called if @a da was not initialised by
 * #digest_setup_and_init() or by #digest_setup_zero().
 * @param da the digest calculation
 */
MHD_static_inline_ void
digest_deinit (struct DigestAlgorithm *da)
{
  mhd_assert (! da->uninitialised);
#ifdef mhd_MD5_HAS_DEINIT
  if (MHD_DIGEST_BASE_ALGO_MD5 == da->algo)
    mhd_MD5_deinit (&(da->ctx.md5_ctx));
  else
#endif /* mhd_MD5_HAS_DEINIT */
#ifdef mhd_SHA256_HAS_DEINIT
  if (MHD_DIGEST_BASE_ALGO_SHA256 == da->algo)
    mhd_SHA256_deinit (&(da->ctx.sha256_ctx));
  else
#endif /* mhd_SHA256_HAS_DEINIT */
#ifdef mhd_SHA512_256_HAS_DEINIT
  if (MHD_DIGEST_BASE_ALGO_SHA512_256 == da->algo)
    mhd_SHA512_256_deinit (&(da->ctx.sha256_ctx));
  else
#endif /* mhd_SHA512_256_HAS_DEINIT */
  (void) 0;
  digest_setup_zero (da);
}


#else  /* ! mhd_DIGEST_HAS_DEINIT */
#define digest_setup_zero(da) ((void) 0)
#define digest_deinit(da) ((void) 0)
#endif /* ! mhd_DIGEST_HAS_DEINIT */


/**
 * Set-up the digest calculation structure and initialise with initial values.
 *
 * If @a da was successfully initialised, #digest_deinit() must be called
 * after finishing using of the @a da.
 *
 * This function must not be called more than once for any @a da.
 *
 * @param da the structure to set-up
 * @param algo the algorithm to use for digest calculation
 * @return boolean 'true' if successfully set-up,
 *         false otherwise.
 */
MHD_static_inline_ MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_ bool
digest_init_one_time (struct DigestAlgorithm *da,
                      enum MHD_DigestBaseAlgo algo)
{
#ifdef _DEBUG
  da->uninitialised = false;
  da->algo_selected = false;
  da->ready_for_hashing = false;
  da->hashing = false;
#endif /* _DEBUG */
  switch (algo)
  {
  case MHD_DIGEST_BASE_ALGO_MD5:
#ifdef MHD_SUPPORT_MD5
    da->algo = MHD_DIGEST_BASE_ALGO_MD5;
#  ifdef _DEBUG
    da->algo_selected = true;
#  endif
    mhd_MD5_init_one_time (&(da->ctx.md5_ctx));
#  ifdef _DEBUG
    da->ready_for_hashing = true;
#  endif
    return true;
#endif /* MHD_SUPPORT_MD5 */
    break;

  case MHD_DIGEST_BASE_ALGO_SHA256:
#ifdef MHD_SUPPORT_SHA256
    da->algo = MHD_DIGEST_BASE_ALGO_SHA256;
#  ifdef _DEBUG
    da->algo_selected = true;
#  endif
    mhd_SHA256_init_one_time (&(da->ctx.sha256_ctx));
#  ifdef _DEBUG
    da->ready_for_hashing = true;
#  endif
    return true;
#endif /* MHD_SUPPORT_SHA256 */
    break;

  case MHD_DIGEST_BASE_ALGO_SHA512_256:
#ifdef MHD_SUPPORT_SHA512_256
    da->algo = MHD_DIGEST_BASE_ALGO_SHA512_256;
#  ifdef _DEBUG
    da->algo_selected = true;
#  endif
    mhd_SHA512_256_init_one_time (&(da->ctx.sha512_256_ctx));
#  ifdef _DEBUG
    da->ready_for_hashing = true;
#  endif
    return true;
#endif /* MHD_SUPPORT_SHA512_256 */
    break;

  case MHD_DIGEST_BASE_ALGO_INVALID:
  default:
    mhd_UNREACHABLE ();
    break;
  }
  da->algo = MHD_DIGEST_BASE_ALGO_INVALID;
  return false; /* Unsupported or bad algorithm */
}


/**
 * Hash more data for digest calculation.
 * @param da the digest calculation
 * @param size the size of the @a data in bytes
 * @param data the data to process
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3, 2) void
digest_update (struct DigestAlgorithm *restrict da,
               size_t size,
               const void *restrict data)
{
  mhd_assert (! da->uninitialised);
  mhd_assert (da->algo_selected);
  mhd_assert (da->ready_for_hashing);
  switch (da->algo)
  {
  case MHD_DIGEST_BASE_ALGO_MD5:
#ifdef MHD_SUPPORT_MD5
    mhd_MD5_update (&da->ctx.md5_ctx,
                    size,
                    (const uint8_t *) data);
#else
    mhd_UNREACHABLE ();
#endif
    break;
  case MHD_DIGEST_BASE_ALGO_SHA256:
#ifdef MHD_SUPPORT_SHA256
    mhd_SHA256_update (&da->ctx.sha256_ctx,
                       size,
                       (const uint8_t *) data);
#else
    mhd_UNREACHABLE ();
#endif
    break;
  case MHD_DIGEST_BASE_ALGO_SHA512_256:
#ifdef MHD_SUPPORT_SHA512_256
    mhd_SHA512_256_update (&da->ctx.sha512_256_ctx,
                           size,
                           (const uint8_t *) data);
#else
    mhd_UNREACHABLE ();
#endif
    break;
  case MHD_DIGEST_BASE_ALGO_INVALID:
  default:
    mhd_UNREACHABLE ();
    break;
  }
#ifdef _DEBUG
  da->hashing = true;
#endif
}


/**
 * Feed digest calculation with more data from string.
 * @param da the digest calculation
 * @param str the zero-terminated string to process
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2) void
digest_update_str (struct DigestAlgorithm *restrict da,
                   const char *restrict str)
{
  digest_update (da,
                 strlen (str),
                 (const uint8_t *) str);
}


/**
 * Feed digest calculation with more data from string.
 * @param da the digest calculation
 * @param buf the sized buffer with the data
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2) void
digest_update_cbuf (struct DigestAlgorithm *restrict da,
                    const struct mhd_BufferConst *restrict buf)
{
  digest_update (da,
                 buf->size,
                 (const uint8_t *) buf->data);
}


/**
 * Feed digest calculation with more data from string.
 * @param da the digest calculation
 * @param buf the sized buffer with the data
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2) void
digest_update_buf (struct DigestAlgorithm *restrict da,
                   const struct mhd_Buffer *restrict buf)
{
  digest_update (da,
                 buf->size,
                 (const uint8_t *) buf->data);
}


/**
 * Feed digest calculation with single colon ':' character.
 * @param da the digest calculation
 * @param str the zero-terminated string to process
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ void
digest_update_with_colon (struct DigestAlgorithm *da)
{
  static const uint8_t colon = (uint8_t) ':';
  digest_update (da,
                 1,
                 &colon);
}


/**
 * Finally calculate hash (the digest).
 * @param da the digest calculation
 * @param[out] digest the pointer to the buffer to put calculated digest,
 *                    must be at least digest_get_size(da) bytes large
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) void
digest_calc_hash (struct DigestAlgorithm *da,
                  uint8_t *digest)
{
  mhd_assert (! da->uninitialised);
  mhd_assert (da->algo_selected);
  mhd_assert (da->ready_for_hashing);
  switch (da->algo)
  {
  case MHD_DIGEST_BASE_ALGO_MD5:
#ifdef MHD_SUPPORT_MD5
#  ifdef mhd_MD5_HAS_FINISH
    mhd_MD5_finish (&da->ctx.md5_ctx, digest);
#    ifdef _DEBUG
    da->ready_for_hashing = false;
#    endif /* _DEBUG */
#  else  /* ! mhd_MD5_HAS_FINISH */
    mhd_MD5_finish_reset (&da->ctx.md5_ctx, digest);
#    ifdef _DEBUG
    da->ready_for_hashing = true;
#    endif /* _DEBUG */
#  endif /* ! mhd_MD5_HAS_FINISH */
#else  /* ! MHD_SUPPORT_MD5 */
    mhd_UNREACHABLE ();
#endif /* ! MHD_SUPPORT_MD5 */
    break;

  case MHD_DIGEST_BASE_ALGO_SHA256:
#ifdef MHD_SUPPORT_SHA256
#  ifdef mhd_SHA256_HAS_FINISH
    mhd_SHA256_finish (&da->ctx.sha256_ctx, digest);
#    ifdef _DEBUG
    da->ready_for_hashing = false;
#    endif /* _DEBUG */
#  else  /* ! mhd_SHA256_HAS_FINISH */
    mhd_SHA256_finish_reset (&da->ctx.sha256_ctx, digest);
#    ifdef _DEBUG
    da->ready_for_hashing = true;
#    endif /* _DEBUG */
#  endif /* ! mhd_SHA256_HAS_FINISH */
#else  /* ! MHD_SUPPORT_SHA256 */
    mhd_UNREACHABLE ();
#endif /* ! MHD_SUPPORT_SHA256 */
    break;

  case MHD_DIGEST_BASE_ALGO_SHA512_256:
#ifdef MHD_SUPPORT_SHA512_256
#ifdef mhd_SHA512_256_HAS_FINISH
    mhd_SHA512_256_finish (&da->ctx.sha512_256_ctx, digest);
#ifdef _DEBUG
    da->ready_for_hashing = false;
#endif /* _DEBUG */
#else  /* ! mhd_SHA512_256_HAS_FINISH */
    mhd_SHA512_256_finish_reset (&da->ctx.sha512_256_ctx, digest);
#ifdef _DEBUG
    da->ready_for_hashing = true;
#endif /* _DEBUG */
#endif /* ! mhd_SHA512_256_HAS_FINISH */
#else  /* ! MHD_SUPPORT_SHA512_256 */
    mhd_UNREACHABLE ();
#endif /* ! MHD_SUPPORT_SHA512_256 */
    break;

  case MHD_DIGEST_BASE_ALGO_INVALID:
  default:
    mhd_UNREACHABLE ();
    break;
  }
#ifdef _DEBUG
  da->hashing = false;
#endif /* _DEBUG */
}


/**
 * Reset the digest calculation structure and prepare for new calculation.
 *
 * @param da the structure to reset
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ void
digest_reset (struct DigestAlgorithm *da)
{
  mhd_assert (! da->uninitialised);
  mhd_assert (da->algo_selected);
  mhd_assert (! da->hashing);
  switch (da->algo)
  {
  case MHD_DIGEST_BASE_ALGO_MD5:
#ifdef MHD_SUPPORT_MD5
#  ifdef mhd_MD5_HAS_FINISH
    mhd_assert (! da->ready_for_hashing);
#  else  /* ! mhd_MD5_HAS_FINISH */
    mhd_assert (da->ready_for_hashing);
#  endif /* ! mhd_MD5_HAS_FINISH */
    mhd_MD5_reset (&(da->ctx.md5_ctx));
#  ifdef _DEBUG
    da->ready_for_hashing = true;
#  endif /* _DEBUG */
#else  /* ! MHD_SUPPORT_MD5 */
    mhd_UNREACHABLE ();
#endif /* ! MHD_SUPPORT_MD5 */
    break;

  case MHD_DIGEST_BASE_ALGO_SHA256:
#ifdef MHD_SUPPORT_SHA256
#ifdef mhd_SHA256_HAS_FINISH
    mhd_assert (! da->ready_for_hashing);
#else  /* ! mhd_SHA256_HAS_FINISH */
    mhd_assert (da->ready_for_hashing);
#endif /* ! mhd_SHA256_HAS_FINISH */
    mhd_SHA256_reset (&(da->ctx.sha256_ctx));
#ifdef _DEBUG
    da->ready_for_hashing = true;
#endif /* _DEBUG */
#else  /* ! MHD_SUPPORT_SHA256 */
    mhd_UNREACHABLE ();
#endif /* ! MHD_SUPPORT_SHA256 */
    break;

  case MHD_DIGEST_BASE_ALGO_SHA512_256:
#ifdef MHD_SUPPORT_SHA512_256
#  ifdef mhd_SHA512_256_HAS_FINISH
    mhd_assert (! da->ready_for_hashing);
#  else  /* ! mhd_SHA512_256_HAS_FINISH */
    mhd_assert (da->ready_for_hashing);
#  endif /* ! mhd_SHA512_256_HAS_FINISH */
    mhd_SHA512_256_reset (&(da->ctx.sha512_256_ctx));
#  ifdef _DEBUG
    da->ready_for_hashing = true;
#  endif /* _DEBUG */
#else  /* ! MHD_SUPPORT_SHA512_256 */
    mhd_UNREACHABLE ();
#endif /* ! MHD_SUPPORT_SHA512_256 */
    break;

  case MHD_DIGEST_BASE_ALGO_INVALID:
  default:
    da->ready_for_hashing = false;
    mhd_UNREACHABLE ();
    break;
  }
}


#if defined(mhd_MD5_HAS_EXT_ERROR) \
  || defined(mhd_SHA256_HAS_EXT_ERROR) \
  || defined(mhd_SHA512_256_HAS_EXT_ERROR)
/**
 * Indicates that digest algorithm has external error status
 */
#define mhd_DIGEST_HAS_EXT_ERROR 1
#endif /* mhd_MD5_HAS_EXT_ERROR || mhd_SHA256_HAS_EXT_ERROR
          || mhd_SHA512_256_HAS_EXT_ERROR*/

#ifdef mhd_DIGEST_HAS_EXT_ERROR
/**
 * Get external error state.
 *
 * When external digest calculation used, an error may occur during
 * initialisation or hashing data. This function checks whether external
 * error has been reported for digest calculation.
 * @param da the digest calculation
 * @return 'true' if external error occurs,
 *         'false' otherwise
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ bool
digest_has_error (struct DigestAlgorithm *da)
{
  mhd_assert (! da->uninitialised);
  mhd_assert (da->algo_selected);
  switch (da->algo)
  {
  case MHD_DIGEST_BASE_ALGO_MD5:
#ifdef MHD_SUPPORT_MD5
    return mhd_MD5_has_err (&(da->ctx.md5_ctx));
#else  /* ! MHD_SUPPORT_MD5 */
    mhd_UNREACHABLE ();
#endif /* ! MHD_SUPPORT_MD5 */
    break;

  case MHD_DIGEST_BASE_ALGO_SHA256:
#ifdef MHD_SUPPORT_SHA256
    return mhd_SHA256_has_err (&(da->ctx.sha256_ctx));
#else  /* ! MHD_SUPPORT_SHA256 */
    mhd_UNREACHABLE ();
#endif /* ! MHD_SUPPORT_SHA256 */
    break;

  case MHD_DIGEST_BASE_ALGO_SHA512_256:
#ifdef MHD_SUPPORT_SHA512_256
    return mhd_SHA512_256_has_err (&(da->ctx.sha512_256_ctx));
#else  /* ! MHD_SUPPORT_SHA512_256 */
    mhd_UNREACHABLE ();
#endif /* ! MHD_SUPPORT_SHA512_256 */
    break;

  case MHD_DIGEST_BASE_ALGO_INVALID:
  default:
    break;
  }
  mhd_UNREACHABLE ();
  return true;
}


#else  /* ! mhd_DIGEST_HAS_EXT_ERROR */
#define digest_has_error(da) (((void) (da)), ! ! 0)
#endif /* ! mhd_DIGEST_HAS_EXT_ERROR */


/**
 * Calculate userdigest, return it as binary data.
 *
 * It is equal to H(A1) for non-session algorithms.
 *
 * MHD internal version.
 *
 * @param da the digest algorithm
 * @param username the username to use
 * @param username_len the length of the @a username
 * @param realm the realm to use
 * @param realm_len the length of the @a realm
 * @param password the password, must be zero-terminated
 * @param[out] ha1_bin the output buffer, must have at least
 *                     #digest_get_size(da) bytes available
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (2, 3) MHD_FN_PAR_IN_SIZE_ (4, 5)
MHD_FN_PAR_CSTR_ (6) MHD_FN_PAR_OUT_ (7) void
calc_userdigest (struct DigestAlgorithm *restrict da,
                 const char *restrict username, const size_t username_len,
                 const char *restrict realm, const size_t realm_len,
                 const char *restrict password,
                 uint8_t *ha1_bin)
{
  mhd_assert (! da->uninitialised);
  mhd_assert (da->algo_selected);
  mhd_assert (! da->hashing);
  digest_update (da, username_len, username);
  digest_update_with_colon (da);
  digest_update (da, realm_len, realm);
  digest_update_with_colon (da);
  digest_update_str (da, password);
  digest_calc_hash (da, ha1_bin);
}


MHD_EXTERN_ MHD_FN_PURE_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2) MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_CSTR_ (4)
MHD_FN_PAR_OUT_SIZE_ (6,5) enum MHD_StatusCode
MHD_digest_auth_calc_userdigest (enum MHD_DigestAuthAlgo algo,
                                 const char *MHD_RESTRICT username,
                                 const char *MHD_RESTRICT realm,
                                 const char *MHD_RESTRICT password,
                                 size_t bin_buf_size,
                                 void *MHD_RESTRICT userdigest_bin)
{
  struct DigestAlgorithm da;
  enum MHD_StatusCode ret;
  if (! digest_init_one_time (&da, get_base_digest_algo (algo)))
    return MHD_SC_AUTH_DIGEST_ALGO_NOT_SUPPORTED;

  if (digest_get_size (&da) > bin_buf_size)
    ret = MHD_SC_OUT_BUFF_TOO_SMALL;
  else
  {
    calc_userdigest (&da,
                     username,
                     strlen (username),
                     realm,
                     strlen (realm),
                     password,
                     userdigest_bin);
    ret = digest_has_error (&da) ? MHD_SC_HASH_FAILED : MHD_SC_OK;
  }
  digest_deinit (&da);

  return ret;
}


/**
 * Calculate userhash, return it as binary data.
 *
 * MHD internal version.
 *
 * @param da the digest algorithm
 * @param username_len the length of the @a username
 * @param username the username to use
 * @param realm_len the length of the @a realm
 * @param realm the realm to use
 * @param[out] digest_bin the output buffer, must have at least
 *                        #MHD_digest_get_hash_size(algo) bytes available
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3, 2) MHD_FN_PAR_IN_SIZE_ (5, 4) MHD_FN_PAR_OUT_ (6) void
calc_userhash (struct DigestAlgorithm *da,
               const size_t username_len,
               const char *username,
               const size_t realm_len,
               const char *realm,
               uint8_t *digest_bin)
{
  mhd_assert (! da->uninitialised);
  mhd_assert (da->algo_selected);
  mhd_assert (! da->hashing);
  digest_update (da, username_len, username);
  digest_update_with_colon (da);
  digest_update (da, realm_len, realm);
  digest_calc_hash (da, digest_bin);
}


MHD_EXTERN_ MHD_FN_PURE_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_OUT_SIZE_ (5,4) enum MHD_StatusCode
MHD_digest_auth_calc_userhash (enum MHD_DigestAuthAlgo algo,
                               const char *MHD_RESTRICT username,
                               const char *MHD_RESTRICT realm,
                               size_t bin_buf_size,
                               void *MHD_RESTRICT userhash_bin)
{
  struct DigestAlgorithm da;
  enum MHD_StatusCode ret;

  if (! digest_init_one_time (&da, get_base_digest_algo (algo)))
    return MHD_SC_AUTH_DIGEST_ALGO_NOT_SUPPORTED;
  if (digest_get_size (&da) > bin_buf_size)
    ret = MHD_SC_OUT_BUFF_TOO_SMALL;
  else
  {
    calc_userhash (&da,
                   strlen (username),
                   username,
                   strlen (realm),
                   realm,
                   userhash_bin);

    ret = digest_has_error (&da) ? MHD_SC_HASH_FAILED : MHD_SC_OK;
  }
  digest_deinit (&da);

  return ret;
}


MHD_EXTERN_ MHD_FN_PURE_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_OUT_SIZE_ (5,4) enum MHD_StatusCode
MHD_digest_auth_calc_userhash_hex (
  enum MHD_DigestAuthAlgo algo,
  const char *MHD_RESTRICT username,
  const char *MHD_RESTRICT realm,
  size_t hex_buf_size,
  char userhash_hex[MHD_FN_PAR_DYN_ARR_SIZE_ (hex_buf_size)])
{
  uint8_t userhash_bin[mhd_MAX_DIGEST];
  size_t digest_size;
  enum MHD_StatusCode res;

  digest_size = digest_get_hash_size (algo);
  if (digest_size * 2 + 1 > hex_buf_size)
    return MHD_SC_OUT_BUFF_TOO_SMALL;
  res = MHD_digest_auth_calc_userhash (algo,
                                       username,
                                       realm,
                                       sizeof(userhash_bin),
                                       userhash_bin);
  if (MHD_SC_OK != res)
    return res;

  (void) mhd_bin_to_hex_z (userhash_bin,
                           digest_size,
                           userhash_hex);
  return MHD_SC_OK;
}


/**
 * Extract timestamp from the given nonce.
 * @param nonce the nonce to check in binary form
 * @return 'true' if timestamp was extracted,
 *         'false' if nonce does not have valid timestamp.
 */
MHD_static_inline_ uint_fast32_t
get_nonce_timestamp (const uint8_t nonce[mhd_AUTH_DIGEST_NONCE_BIN_SIZE])
{
  return (uint_fast32_t)
         mhd_GET_32BIT_LE_UNALIGN (nonce + mhd_AUTH_DIGEST_NONCE_RAND_BIN_SIZE);
}


/**
 * The result of nonce-nc map array check.
 */
enum mhd_CheckNonceNC
{
  /**
   * The nonce and NC are OK (valid and NC was not used before).
   */
  mhd_CHECK_NONCENC_OK = MHD_DAUTH_OK,

  /**
   * The 'nonce' is too old, has been overwritten with newer 'nonce' in
   * the same slot or 'nc' value has been used already.
   * The validity of the 'nonce' was not be checked.
   */
  mhd_CHECK_NONCENC_STALE = MHD_DAUTH_NONCE_STALE,

  /**
   * The 'nonce' is wrong, it was not generated before.
   */
  mhd_CHECK_NONCENC_WRONG = MHD_DAUTH_NONCE_WRONG
};


/**
 * Check nonce-nc map array with the new nonce counter.
 *
 * @param daemon the master daemon object
 * @param noncelen the length of @a nonce, in characters
 * @param nonce the pointer that referenced hex nonce, does not need to be
 *              zero-terminated
 * @param nc the nonce counter
 * @param time_now the current timestamp
 * @return #MHD_DAUTH_NONCENC_OK if successful,
 *         #MHD_DAUTH_NONCENC_STALE if nonce is stale (or no nonce-nc array
 *         is available),
 *         #MHD_DAUTH_NONCENC_WRONG if nonce was not recodered in nonce-nc map
 *         array, while it should.
 */
static MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3, 2) enum mhd_CheckNonceNC
check_nonce_nc (struct MHD_Daemon *restrict d,
                size_t noncelen,
                const char *restrict nonce,
                uint_fast32_t nc,
                uint_fast32_t time_now)
{
  uint8_t nonce_bin[mhd_AUTH_DIGEST_NONCE_BIN_SIZE];
  struct mhd_DaemonAuthDigestNonceData *nonce_slot;
  uint_fast32_t valid_time;
  uint_fast32_t slot_valid_time;
  enum mhd_CheckNonceNC ret;

  mhd_assert (! mhd_D_HAS_MASTER (d)); /* only master daemon should be used */
  mhd_assert (0 != noncelen);
  mhd_assert (0 != nc);
  if (mhd_AUTH_DIGEST_NONCE_LEN != noncelen)
    return mhd_CHECK_NONCENC_WRONG;

  if (mhd_AUTH_DIGEST_NONCE_BIN_SIZE !=
      mhd_hex_to_bin (nonce,
                      mhd_AUTH_DIGEST_NONCE_LEN,
                      nonce_bin))
    return mhd_CHECK_NONCENC_WRONG;

  if ((NULL != memchr (nonce, 'A', mhd_AUTH_DIGEST_NONCE_LEN))
      || (NULL != memchr (nonce, 'B', mhd_AUTH_DIGEST_NONCE_LEN))
      || (NULL != memchr (nonce, 'C', mhd_AUTH_DIGEST_NONCE_LEN))
      || (NULL != memchr (nonce, 'D', mhd_AUTH_DIGEST_NONCE_LEN))
      || (NULL != memchr (nonce, 'E', mhd_AUTH_DIGEST_NONCE_LEN))
      || (NULL != memchr (nonce, 'F', mhd_AUTH_DIGEST_NONCE_LEN)))
    return mhd_CHECK_NONCENC_WRONG;   /* Upper case chars are not produced by MHD */

  valid_time = get_nonce_timestamp (nonce_bin);

  nonce_slot = d->auth_dg.nonces
               + nonce_to_index (nonce_bin,
                                 d->auth_dg.cfg.nonces_num);

  mhd_mutex_lock_chk (&(d->auth_dg.nonces_lock));

  slot_valid_time = nonce_slot->valid_time;
  if ((0 == memcmp (nonce_slot->nonce,
                    nonce_bin,
                    sizeof(nonce_slot->nonce)))
      && (slot_valid_time == valid_time))
  {
    /* The nonce matches the stored nonce */
    if (nonce_slot->max_recvd_nc < nc)
    {
      /* 'nc' is larger, shift bitmask and bump limit */
      const uint_fast32_t jump_size =
        (uint_fast32_t) nc - nonce_slot->max_recvd_nc;
      if (64 > jump_size)
      {
        /* small jump, less than mask width */
        nonce_slot->nmask <<= jump_size;
        /* Set bit for the old 'nc' value */
        nonce_slot->nmask |= (UINT64_C (1) << (jump_size - 1));
      }
      else if (64 == jump_size)
        nonce_slot->nmask = (UINT64_C (1) << 63);
      else
        nonce_slot->nmask = 0; /* big jump, unset all bits in the mask */
      nonce_slot->max_recvd_nc = nc;
      ret = mhd_CHECK_NONCENC_OK;
    }
    else if (nonce_slot->max_recvd_nc == nc)
      /* 'nc' was already used */
      ret = mhd_CHECK_NONCENC_STALE;
    else /* (nonce_slot->max_recvd_nc > nc) */
    {
      /* Out-of-order 'nc' value. Check whether was used before */
      if (64 <= nonce_slot->max_recvd_nc - nc)
      {
        if (0 ==
            ((UINT64_C (1) << (nonce_slot->max_recvd_nc - nc - 1))
             & nonce_slot->nmask))
        {
          /* 'nc' has not been used before. Set the bit. */
          nonce_slot->nmask |=
            (UINT64_C (1) << (nonce_slot->max_recvd_nc - nc - 1));
          ret = mhd_CHECK_NONCENC_OK;
        }
        else
          ret = mhd_CHECK_NONCENC_STALE; /* 'nc' has been used before */
      }
      else
        ret = mhd_CHECK_NONCENC_STALE; /* 'nc' is too old (more than 64 value before) */
    }
  }
  else
  {
    /* The nonce does not match the stored nonce */
    if (((valid_time - slot_valid_time) & UINT32_C (0xFFFFFFFF)) <=
        ((slot_valid_time - valid_time) & UINT32_C (0xFFFFFFFF)))
    {
      /* The stored nonce was generated before the checked nonce */
      ret = mhd_CHECK_NONCENC_WRONG;
    }
    else
    {
      /* The stored nonce was generated after the checked nonce */
      const uint_fast32_t nonce_gen_time =
        ((valid_time - d->auth_dg.cfg.nonce_tmout) & UINT32_C (0xFFFFFFFF));
      if (((time_now - nonce_gen_time) & UINT32_C (0xFFFFFFFF)) <
          ((nonce_gen_time - time_now) & UINT32_C (0xFFFFFFFF)))
        ret = mhd_CHECK_NONCENC_WRONG; /* The nonce is generated in "future" */
      else
        /* Probably the nonce has been overwritten with a newer nonce */
        ret = mhd_CHECK_NONCENC_STALE;
    }
  }

  mhd_mutex_unlock_chk (&(d->auth_dg.nonces_lock));

  return ret;
}


struct test_header_param
{
  struct MHD_Request *request;
  size_t num_get_params;
};

/**
 * Test if the given key-value pair is in the headers for the
 * given request.
 *
 * @param cls the test context
 * @param name the name of the key
 * @param value the value of the key
 * @return 'true' if the key-value pair is in the headers,
 *         'false' if not
 */
static MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3) bool
test_header (void *restrict cls,
             const struct MHD_String *restrict name,
             const struct MHD_StringNullable *restrict value)
{
  struct test_header_param *const param = (struct test_header_param *) cls;
  struct MHD_Request *req = param->request;
  struct mhd_RequestField *pos;
  size_t i;

  param->num_get_params++;
  i = 0;
  for (pos = mhd_DLINKEDL_GET_FIRST (req, fields);
       NULL != pos;
       pos = mhd_DLINKEDL_GET_NEXT (pos, fields))
  {
    if (MHD_VK_GET_ARGUMENT != pos->field.kind)
      continue;
    if (++i == param->num_get_params)
    {
      if (name->len != pos->field.nv.name.len)
        return false;
      if (value->len != pos->field.nv.value.len)
        return false;
      if (0 != name->len)
      {
        mhd_assert (NULL != name->cstr);
        mhd_assert (NULL != pos->field.nv.name.cstr);
        if (0 != memcmp (name->cstr,
                         pos->field.nv.name.cstr,
                         name->len))
          return false;
      }
      if (0 != value->len)
      {
        mhd_assert (NULL != value->cstr);
        mhd_assert (NULL != pos->field.nv.value.cstr);
        if (0 != memcmp (value->cstr,
                         pos->field.nv.value.cstr,
                         value->len))
          return false;
      }
      return true;
    }
  }
  return false;
}


/**
 * Check that the arguments given by the client as part
 * of the authentication header match the arguments we
 * got as part of the HTTP request URI.
 *
 * @param req the request with get arguments to compare against
 * @param args the copy of argument URI string (after "?" in URI), will be
 *             modified by this function
 * @return 'true' if the arguments match,
 *         'false' if not
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (3)
MHD_FN_PAR_INOUT_SIZE_ (3, 2) bool
check_argument_match (struct MHD_Request *restrict req,
                      size_t args_len,
                      char *restrict args)
{
  struct mhd_RequestField *pos;
  struct test_header_param param;

  param.request = req;
  param.num_get_params = 0;
  if (! mhd_parse_get_args (args_len,
                            args,
                            &test_header,
                            &param))
    return false;

  /* Check that the number of arguments matches */
  for (pos = mhd_DLINKEDL_GET_FIRST (req, fields);
       NULL != pos;
       pos = mhd_DLINKEDL_GET_NEXT (pos, fields))
  {
    if (MHD_VK_GET_ARGUMENT != pos->field.kind)
      continue;
    param.num_get_params--;
  }

  if (0 != param.num_get_params)
    return false; /* argument count mismatch */

  return true;
}


/**
 * Check that the URI provided by the client as part
 * of the authentication header match the real HTTP request URI.
 *
 * @param req the request to compare URI
 * @param uri the copy of URI in the authentication header, should point to
 *            modifiable buffer at least @a uri_len + 1 characters long,
 *            will be modified by this function, not valid upon return
 * @param uri_len the length of the @a uri string in characters
 * @return boolean true if the URIs match,
 *         boolean false if not
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (3) bool
check_uri_match (struct MHD_Request *restrict req,
                 const size_t uri_len,
                 char *restrict uri)
{
  char *qmark;
  char *args;
  size_t url_len; /* The part before '?' char */
  size_t args_len;

  if (uri_len != req->req_target_len)
    return false;

  uri[uri_len] = 0;
  qmark = memchr (uri,
                  '?',
                  uri_len);
  if (NULL != qmark)
  {
    *qmark = 0;
    url_len = (size_t) (qmark - uri);
  }
  else
    url_len = uri_len;

  /* Need to unescape URI before comparing with req->url */
  url_len = mhd_str_pct_decode_lenient_n (uri,
                                          url_len,
                                          uri,
                                          url_len,
                                          NULL);
  if ((url_len != req->url_len) ||
      (0 != memcmp (uri,
                    req->url,
                    url_len)))
    return false;

  args = (NULL != qmark) ? (qmark + 1) : uri + uri_len;
  args_len = (size_t) (uri + uri_len - args);

  if (! check_argument_match (req,
                              args_len,
                              args))
    return false;

  return true;
}


/**
 * The size of the unquoting buffer in stack
 */
#define mhd_STATIC_UNQ_BUFFER_SIZE 128


/**
 * Get the pointer to buffer with required size
 * @param tmp1 the first buffer with fixed size
 * @param[in,out] ptmp2 the pointer to pointer to malloc'ed buffer
 * @param[in,out] ptmp2_size the pointer to the size of the buffer pointed by @a ptmp2
 * @param required_size the required size in buffer
 * @return the pointer to the buffer or NULL if failed to allocate buffer with
 *         requested size
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (2) MHD_FN_PAR_INOUT_ (3) char *
get_buffer_for_size (char tmp1[mhd_STATIC_UNQ_BUFFER_SIZE],
                     char **restrict ptmp2,
                     size_t *restrict ptmp2_size,
                     size_t required_size)
{
  mhd_assert ((0 == *ptmp2_size) || (NULL != *ptmp2));
  mhd_assert ((NULL != *ptmp2) || (0 == *ptmp2_size));
  mhd_assert ((0 == *ptmp2_size) || \
              (mhd_STATIC_UNQ_BUFFER_SIZE < *ptmp2_size));

  if (required_size <= mhd_STATIC_UNQ_BUFFER_SIZE)
    return tmp1;

  if (required_size <= *ptmp2_size)
    return *ptmp2;

  if (required_size > mhd_AUTH_DIGEST_MAX_PARAM_SIZE)
    return NULL;
  if (NULL != *ptmp2)
    free (*ptmp2);
  *ptmp2 = (char *) malloc (required_size);
  if (NULL == *ptmp2)
    *ptmp2_size = 0;
  else
    *ptmp2_size = required_size;
  return *ptmp2;
}


/**
  * The result of parameter unquoting
  */
enum mhd_GetUnqResult
{
  mhd_UNQ_OK = MHD_DAUTH_OK,               /**< Got unquoted string */
  mhd_UNQ_TOO_LARGE = MHD_DAUTH_TOO_LARGE, /**< The string is too large to unquote */
  mhd_UNQ_OUT_OF_MEM = MHD_DAUTH_ERROR     /**< Out of memory error */
};

/**
 * Get Digest authorisation parameter as unquoted string.
 * @param param the parameter to process
 * @param[in,out] tmp1 the small buffer in stack
 * @param[in,out] ptmp2 the pointer to pointer to malloc'ed buffer
 * @param[in,out] ptmp2_size the pointer to the size of the buffer pointed by @a ptmp2
 * @param[out] unquoted the pointer to store the result, NOT zero terminated
 * @return enum code indicating result of the process
 */
static MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) MHD_FN_PAR_INOUT_ (3) MHD_FN_PAR_INOUT_ (4)
MHD_FN_PAR_OUT_ (5) enum mhd_GetUnqResult
get_unquoted_param (const struct mhd_RqDAuthParam *param,
                    char tmp1[mhd_STATIC_UNQ_BUFFER_SIZE],
                    char **restrict ptmp2,
                    size_t *restrict ptmp2_size,
                    struct mhd_BufferConst *restrict unquoted)
{
  char *str;
  size_t len;
  mhd_assert (NULL != param->value.cstr);
  mhd_assert (0 != param->value.len);

  if (! param->quoted)
  {
    unquoted->data = param->value.cstr;
    unquoted->size = param->value.len;
    return mhd_UNQ_OK;
  }
  /* The value is present and is quoted, needs to be copied and unquoted */
  str = get_buffer_for_size (tmp1,
                             ptmp2,
                             ptmp2_size,
                             param->value.len);
  if (NULL == str)
    return (param->value.len > mhd_AUTH_DIGEST_MAX_PARAM_SIZE) ?
           mhd_UNQ_TOO_LARGE : mhd_UNQ_OUT_OF_MEM;

  len = mhd_str_unquote (param->value.cstr,
                         param->value.len,
                         str);
  unquoted->data = str;
  unquoted->size = len;
  mhd_assert (0 != unquoted->size);
  mhd_assert (unquoted->size < param->value.len);
  return mhd_UNQ_OK;
}


/**
 * Get copy of Digest authorisation parameter as unquoted string.
 * @param param the parameter to process
 * @param[in,out] tmp1 the small buffer in stack
 * @param[in,out] ptmp2 the pointer to pointer to malloc'ed buffer
 * @param[in,out] ptmp2_size the pointer to the size of the buffer pointed by @a ptmp2
 * @param[out] unquoted the pointer to store the result, NOT zero terminated,
 *                      but with enough space to zero-terminate
 * @return enum code indicating result of the process
 */
static MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) MHD_FN_PAR_INOUT_ (3) MHD_FN_PAR_INOUT_ (4)
MHD_FN_PAR_OUT_ (5) enum mhd_GetUnqResult
get_unquoted_param_copy (const struct mhd_RqDAuthParam *param,
                         char tmp1[mhd_STATIC_UNQ_BUFFER_SIZE],
                         char **restrict ptmp2,
                         size_t *restrict ptmp2_size,
                         struct mhd_Buffer *restrict unquoted)
{
  mhd_assert (NULL != param->value.cstr);
  mhd_assert (0 != param->value.len);

  /* The value is present and is quoted, needs to be copied and unquoted */
  /* Allocate buffer with one more additional byte for zero-termination */
  unquoted->data =
    get_buffer_for_size (tmp1,
                         ptmp2,
                         ptmp2_size,
                         param->value.len + 1);

  if (NULL == unquoted->data)
    return (param->value.len + 1 > mhd_AUTH_DIGEST_MAX_PARAM_SIZE) ?
           mhd_UNQ_TOO_LARGE : mhd_UNQ_OUT_OF_MEM;

  if (! param->quoted)
  {
    memcpy (unquoted->data,
            param->value.cstr,
            param->value.len);
    unquoted->size = param->value.len;
    return mhd_UNQ_OK;
  }

  unquoted->size =
    mhd_str_unquote (param->value.cstr,
                     param->value.len,
                     unquoted->data);
  mhd_assert (0 != unquoted->size);
  mhd_assert (unquoted->size < param->value.len);
  return mhd_UNQ_OK;
}


/**
 * Check whether Digest Auth request parameter is equal to given string
 * @param param the parameter to check
 * @param str_len the length of the @a str
 * @param str the string to compare with, does not need to be zero-terminated
 * @return true is parameter is equal to the given string,
 *         false otherwise
 */
MHD_static_inline_ MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3,2) bool
is_param_equal (const struct mhd_RqDAuthParam *restrict param,
                const size_t str_len,
                const char *restrict str)
{
  mhd_assert (NULL != param->value.cstr);
  mhd_assert (0 != param->value.len);
  if (param->quoted)
    return mhd_str_equal_quoted_bin_n (param->value.cstr,
                                       param->value.len,
                                       str,
                                       str_len);
  return (str_len == param->value.len) &&
         (0 == memcmp (str, param->value.cstr, str_len));
}


/**
 * Check whether Digest Auth request parameter is caseless equal to given string
 * @param param the parameter to check
 * @param str_len the length of the @a str
 * @param str the string to compare with, does not need to be zero-terminated
 * @return true is parameter is caseless equal to the given string,
 *         false otherwise
 */
MHD_static_inline_ MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3,2) bool
is_param_equal_caseless (const struct mhd_RqDAuthParam *restrict param,
                         const size_t str_len,
                         const char *restrict str)
{
  mhd_assert (NULL != param->value.cstr);
  mhd_assert (0 != param->value.len);
  if (param->quoted)
    return mhd_str_equal_caseless_quoted_bin_n (param->value.cstr,
                                                param->value.len,
                                                str,
                                                str_len);
  return (str_len == param->value.len) &&
         (mhd_str_equal_caseless_bin_n (str, param->value.cstr, str_len));
}


/**
 * Authenticates the authorization header sent by the client
 *
 * If RFC2069 mode is allowed by setting bit #MHD_DIGEST_AUTH_QOP_NONE in
 * @a mqop and the client uses this mode, then server generated nonces are
 * used as one-time nonces because nonce-count is not supported in this old RFC.
 * Communication in this mode is very inefficient, especially if the client
 * requests several resources one-by-one as for every request new nonce must be
 * generated and client repeat all requests twice (the first time to get a new
 * nonce and the second time to perform an authorised request).
 *
 * @param req the request handle
 * @param realm the realm for authorization of the client
 * @param username the username to be authenticated, must be in clear text
 *                 even if userhash is used by the client
 * @param password the password used in the authentication,
 *                 must be NULL if @a userdigest is not NULL
 * @param userdigest the precalculated binary hash of the string
 *                   "username:realm:password",
 *                   must be NULL if @a password is not NULL
 * @param max_nc the maximum allowed nc (Nonce Count) value, if client's nc
 *               exceeds the specified value then MHD_DAUTH_NONCE_STALE is
 *               returned;
 *               unlike #digest_auth_check_all() zero is treated as "no limit"
 * @param mqop the QOP to use
 * @param malgo digest algorithms allowed to use, fail if algorithm specified
 *               by the client is not allowed by this parameter
 * @param[out] pbuf the pointer to pointer to internally malloc'ed buffer,
 *                  to be freed if not NULL upon return
 * @return #MHD_DAUTH_OK if authenticated,
 *         error code otherwise.
 * @ingroup authentication
 */
static MHD_FN_MUST_CHECK_RESULT_
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (4)  MHD_FN_PAR_CSTR_ (4)
enum MHD_DigestAuthResult
digest_auth_check_all_inner (struct MHD_Request *restrict req,
                             const char *restrict realm,
                             const char *restrict username,
                             const char *restrict password,
                             const uint8_t *restrict userdigest,
                             uint_fast32_t max_nc,
                             enum MHD_DigestAuthMultiQOP mqop,
                             enum MHD_DigestAuthMultiAlgo malgo,
                             char **pbuf,
                             struct DigestAlgorithm *da)
{
  struct MHD_Daemon *const daemon =
    mhd_daemon_get_master_daemon (
      mhd_CNTNR_PTR (req, struct MHD_Connection, rq)->daemon);
  enum MHD_DigestAuthAlgo c_algo; /**< Client's algorithm */
  enum MHD_DigestAuthQOP c_qop; /**< Client's QOP */
  unsigned int digest_size;
  uint8_t hash1_bin[mhd_MAX_DIGEST];
  uint8_t hash2_bin[mhd_MAX_DIGEST];
  uint_fast32_t nc;
  const struct mhd_AuthDigesReqParams *restrict params;
  /**
   * Temporal buffer in stack for unquoting and other needs
   */
  char tmp1[mhd_STATIC_UNQ_BUFFER_SIZE];
  char **const ptmp2 = pbuf;     /**< Temporal malloc'ed buffer for unquoting */
  size_t tmp2_size; /**< The size of @a tmp2 buffer */
  struct mhd_BufferConst unquoted;
  struct mhd_Buffer unq_copy;
  enum mhd_GetUnqResult unq_res;
  size_t username_len;
  size_t realm_len;

  mhd_assert ((NULL == password) != (NULL == userdigest));

  tmp2_size = 0;

  if (1)
  {
    enum MHD_StatusCode res;

    res = get_rq_auth_digest_params (req);
    if (MHD_SC_OK != res)
    {
      if (MHD_SC_AUTH_ABSENT == res)
        return MHD_DAUTH_HEADER_MISSING;
      else if (MHD_SC_CONNECTION_POOL_NO_MEM_AUTH_DATA == res)
        return MHD_DAUTH_ERROR;
      else if (MHD_SC_REQ_AUTH_DATA_BROKEN == res)
        return MHD_DAUTH_HEADER_BROKEN;
      else
        mhd_UNREACHABLE ();
    }
    params = req->auth.digest.rqp;
  }
  mhd_assert (NULL != params);

  /* ** Initial parameters checks and setup ** */
  /* Get client's algorithm */
  c_algo = params->algo;
  /* Check whether client's algorithm is allowed by function parameter */
  if (((unsigned int) c_algo) !=
      (((unsigned int) c_algo) & ((unsigned int) malgo)))
    return MHD_DAUTH_WRONG_ALGO;
  /* Check whether client's algorithm is supported */
  if (0 != (((unsigned int) c_algo) & MHD_DIGEST_AUTH_ALGO_SESSION))
    return MHD_DAUTH_UNSUPPORTED_ALGO;
#ifndef MHD_SUPPORT_MD5
  if (0 != (((unsigned int) c_algo) & MHD_DIGEST_BASE_ALGO_MD5))
    return MHD_DAUTH_UNSUPPORTED_ALGO;
#endif /* ! MHD_SUPPORT_MD5 */
#ifndef MHD_SUPPORT_SHA256
  if (0 != (((unsigned int) c_algo) & MHD_DIGEST_BASE_ALGO_SHA256))
    return MHD_DAUTH_UNSUPPORTED_ALGO;
#endif /* ! MHD_SUPPORT_SHA256 */
#ifndef MHD_SUPPORT_SHA512_256
  if (0 != (((unsigned int) c_algo) & MHD_DIGEST_BASE_ALGO_SHA512_256))
    return MHD_DAUTH_UNSUPPORTED_ALGO;
#endif /* ! MHD_SUPPORT_SHA512_256 */
  if (! digest_init_one_time (da, get_base_digest_algo (c_algo)))
    mhd_UNREACHABLE ();
  /* Check 'mqop' value */
  c_qop = params->qop;
  /* Check whether client's QOP is allowed by function parameter */
  if (((unsigned int) c_qop) !=
      (((unsigned int) c_qop) & ((unsigned int) mqop)))
    return MHD_DAUTH_WRONG_QOP;
  if (0 != (((unsigned int) c_qop) & MHD_DIGEST_AUTH_QOP_AUTH_INT))
    return MHD_DAUTH_UNSUPPORTED_QOP;

  digest_size = digest_get_size (da);

  /* ** A quick check for presence of all required parameters ** */

  if ((NULL == params->username.value.cstr) &&
      (NULL == params->username_ext.value.cstr))
    return MHD_DAUTH_HEADER_BROKEN;
  else if ((NULL != params->username.value.cstr) &&
           (NULL != params->username_ext.value.cstr))
    return MHD_DAUTH_HEADER_BROKEN; /* Parameters cannot be used together */
  else if ((NULL != params->username_ext.value.cstr) &&
           (mhd_DAUTH_EXT_PARAM_MIN_LEN > params->username_ext.value.len))
    return MHD_DAUTH_HEADER_BROKEN;  /* Broken extended notation */
  else if (params->userhash && (NULL == params->username.value.cstr))
    return MHD_DAUTH_HEADER_BROKEN;  /* Userhash cannot be used with extended notation */
  else if (params->userhash && (digest_size * 2 > params->username.value.len))
    return MHD_DAUTH_WRONG_USERNAME;  /* Too few chars for correct userhash */
  else if (params->userhash && (digest_size * 4 < params->username.value.len))
    return MHD_DAUTH_WRONG_USERNAME;  /* Too many chars for correct userhash */

  if (NULL == params->realm.value.cstr)
    return MHD_DAUTH_HEADER_BROKEN;
  else if (((NULL == userdigest) || params->userhash) &&
           (mhd_AUTH_DIGEST_MAX_PARAM_SIZE < params->realm.value.len))
    return MHD_DAUTH_TOO_LARGE; /* Realm is too large and should be used in hash calculations */

  if (MHD_DIGEST_AUTH_QOP_NONE != c_qop)
  {
    if (NULL == params->nc.value.cstr)
      return MHD_DAUTH_HEADER_BROKEN;
    else if (0 == params->nc.value.len)
      return MHD_DAUTH_HEADER_BROKEN;
    else if (4 * 8 < params->nc.value.len) /* Four times more than needed */
      return MHD_DAUTH_HEADER_BROKEN;

    if (NULL == params->cnonce.value.cstr)
      return MHD_DAUTH_HEADER_BROKEN;
    else if (0 == params->cnonce.value.len)
      return MHD_DAUTH_HEADER_BROKEN;
    else if (mhd_AUTH_DIGEST_MAX_PARAM_SIZE < params->cnonce.value.len)
      return MHD_DAUTH_TOO_LARGE;
  }

  /* The QOP parameter was checked already */

  if (NULL == params->uri.value.cstr)
    return MHD_DAUTH_HEADER_BROKEN;
  else if (0 == params->uri.value.len)
    return MHD_DAUTH_HEADER_BROKEN;
  else if (mhd_AUTH_DIGEST_MAX_PARAM_SIZE < params->uri.value.len)
    return MHD_DAUTH_TOO_LARGE;

  if (NULL == params->nonce.value.cstr)
    return MHD_DAUTH_HEADER_BROKEN;
  else if (0 == params->nonce.value.len)
    return MHD_DAUTH_HEADER_BROKEN;
  else if (mhd_AUTH_DIGEST_NONCE_LEN * 2 < params->nonce.value.len)
    return MHD_DAUTH_NONCE_WRONG;

  if (NULL == params->response.value.cstr)
    return MHD_DAUTH_HEADER_BROKEN;
  else if (0 == params->response.value.len)
    return MHD_DAUTH_HEADER_BROKEN;
  else if (digest_size * 4 < params->response.value.len)
    return MHD_DAUTH_RESPONSE_WRONG;

  /* ** Check simple parameters match ** */

  /* Check 'algorithm' */
  /* The 'algorithm' was checked at the start of the function */
  /* 'algorithm' valid */

  /* Check 'qop' */
  /* The 'qop' was checked at the start of the function */
  /* 'qop' valid */

  /* Check 'realm' */
  realm_len = strlen (realm);
  if (! is_param_equal (&params->realm,
                        realm_len,
                        realm))
    return MHD_DAUTH_WRONG_REALM;
  /* 'realm' valid */

  /* Check 'username' */
  username_len = strlen (username);
  if (! params->userhash)
  {
    if (NULL != params->username.value.cstr)
    { /* Username in standard notation */
      if (! is_param_equal (&params->username, username_len, username))
        return MHD_DAUTH_WRONG_USERNAME;
    }
    else
    { /* Username in extended notation */
      char *r_uname;
      size_t buf_size = params->username_ext.value.len;
      ssize_t res;

      mhd_assert (NULL != params->username_ext.value.cstr);
      mhd_assert (mhd_DAUTH_EXT_PARAM_MIN_LEN <= buf_size); /* It was checked already */
      buf_size += 1; /* For zero-termination */
      buf_size -= mhd_DAUTH_EXT_PARAM_MIN_LEN;
      r_uname = get_buffer_for_size (tmp1, ptmp2, &tmp2_size, buf_size);
      if (NULL == r_uname)
        return (mhd_AUTH_DIGEST_MAX_PARAM_SIZE < buf_size) ?
               MHD_DAUTH_TOO_LARGE : MHD_DAUTH_ERROR;
      res = get_rq_extended_uname_copy_z (params->username_ext.value.cstr,
                                          params->username_ext.value.len,
                                          r_uname, buf_size);
      if (0 > res)
        return MHD_DAUTH_HEADER_BROKEN; /* Broken extended notation */
      if ((username_len != (size_t) res) ||
          (0 != memcmp (username, r_uname, username_len)))
        return MHD_DAUTH_WRONG_USERNAME;
    }
  }
  else
  { /* Userhash */
    mhd_assert (NULL != params->username.value.cstr);
    calc_userhash (da,
                   username_len,
                   username,
                   realm_len,
                   realm,
                   hash1_bin);
    if (digest_has_error (da))
      return MHD_DAUTH_ERROR;
    mhd_assert (sizeof (tmp1) >= (2 * digest_size));
    mhd_bin_to_hex (hash1_bin, digest_size, tmp1);
    if (! is_param_equal_caseless (&params->username, 2 * digest_size, tmp1))
      return MHD_DAUTH_WRONG_USERNAME;
    /* To simplify the logic, the digest is reset here instead of resetting
       before the next hash calculation. */
    digest_reset (da);
  }
  /* 'username' valid */

  /* ** Do basic nonce and nonce-counter checks (size, timestamp) ** */

  /* Get 'nc' digital value */
  nc = 0;
  switch (get_rq_nc (params,
                     &nc))
  {
  case mhd_GET_RQ_NC_NONE:
    if (MHD_DIGEST_AUTH_QOP_NONE != c_qop)
      return MHD_DAUTH_HEADER_BROKEN;
    nc = 1; /* Force 'nc' value */
    break;
  case mhd_GET_RQ_NC_VALID:
    if (MHD_DIGEST_AUTH_QOP_NONE == c_qop)
      return MHD_DAUTH_HEADER_BROKEN;
    break;
  case mhd_GET_RQ_NC_TOO_LONG:
  case mhd_GET_RQ_NC_TOO_LARGE:
    return MHD_DAUTH_NONCE_STALE;
    break;
  case mhd_GET_RQ_NC_BROKEN:
    return MHD_DAUTH_HEADER_BROKEN;
    break;
  default:
    mhd_UNREACHABLE ();
    break;
  }
  if (0 == nc)
    return MHD_DAUTH_HEADER_BROKEN;
  if (0 == max_nc)
    max_nc = daemon->auth_dg.cfg.def_max_nc;
  if (max_nc < nc)
    return MHD_DAUTH_NONCE_STALE;    /* Too large 'nc' value */
  /* Got 'nc' digital value */

  /* Get 'nonce' with basic checks */
  unq_res = get_unquoted_param (&params->nonce, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (mhd_UNQ_TOO_LARGE == unq_res)
    return MHD_DAUTH_TOO_LARGE;
  if (mhd_UNQ_OUT_OF_MEM == unq_res)
    return MHD_DAUTH_ERROR;


  switch (check_nonce_nc (daemon,
                          unquoted.size,
                          unquoted.data,
                          nc,
                          (uint_fast32_t)
                          ((mhd_monotonic_msec_counter () / 1000)
                           & UINT32_C (0xFFFFFFFF))))
  {
  case mhd_CHECK_NONCENC_OK:
    break;
  case mhd_CHECK_NONCENC_STALE:
    return MHD_DAUTH_NONCE_STALE;
  case mhd_CHECK_NONCENC_WRONG:
    return MHD_DAUTH_NONCE_WRONG;
  default:
    mhd_UNREACHABLE ();
    break;
  }
  /* The nonce was generated by MHD, is not stale and nonce-nc combination has
     not been used before */

  /* ** Build H(A2) and check URI match in the header and in the request ** */

  /* Get 'uri' */
  mhd_assert (! da->hashing);
  digest_update (da, req->method.len, req->method.cstr);
  digest_update_with_colon (da);
#if 0
  /* TODO: add support for "auth-int" */
  digest_update_str (da, hentity);
  digest_update_with_colon (da);
#endif
  unq_res = get_unquoted_param_copy (&params->uri, tmp1, ptmp2, &tmp2_size,
                                     &unq_copy);
  if (mhd_UNQ_TOO_LARGE == unq_res)
    return MHD_DAUTH_TOO_LARGE;
  if (mhd_UNQ_OUT_OF_MEM == unq_res)
    return MHD_DAUTH_ERROR;

  digest_update_buf (da, &unq_copy);
  /* The next check will modify copied URI string */
  if (! check_uri_match (req, unq_copy.size, unq_copy.data))
    return MHD_DAUTH_WRONG_URI;
  digest_calc_hash (da, hash2_bin);
#ifdef mhd_DIGEST_HAS_EXT_ERROR
  /* Skip digest calculation external error check, the next one checks both */
#endif /* mhd_DIGEST_HAS_EXT_ERROR */
  /* Got H(A2) */

  /* ** Build H(A1) ** */
  if (NULL == userdigest)
  {
    mhd_assert (! da->hashing);
    digest_reset (da);
    calc_userdigest (da,
                     username, username_len,
                     realm, realm_len,
                     password,
                     hash1_bin);
  }
  /* TODO: support '-sess' versions */
#ifdef mhd_DIGEST_HAS_EXT_ERROR
  if (digest_has_error (da))
    return MHD_DAUTH_ERROR;
#endif /* mhd_DIGEST_HAS_EXT_ERROR */
  /* Got H(A1) */

  /* **  Check 'response' ** */

  mhd_assert (! da->hashing);
  digest_reset (da);
  /* Update digest with H(A1) */
  mhd_assert (sizeof (tmp1) >= (digest_size * 2));
  if (NULL == userdigest)
    mhd_bin_to_hex (hash1_bin, digest_size, tmp1);
  else
    mhd_bin_to_hex (userdigest, digest_size, tmp1);
  digest_update (da, digest_size * 2, (const uint8_t *) tmp1);

  /* H(A1) is not needed anymore, reuse the buffer.
   * Use hash1_bin for the client's 'response' decoded to binary form. */
  unq_res = get_unquoted_param (&params->response, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (mhd_UNQ_TOO_LARGE == unq_res)
    return MHD_DAUTH_TOO_LARGE;
  if (mhd_UNQ_OUT_OF_MEM == unq_res)
    return MHD_DAUTH_ERROR;
  if (digest_size != mhd_hex_to_bin (unquoted.data, unquoted.size, hash1_bin))
    return MHD_DAUTH_RESPONSE_WRONG;

  /* Update digest with ':' */
  digest_update_with_colon (da);
  /* Update digest with 'nonce' text value */
  unq_res = get_unquoted_param (&params->nonce, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (mhd_UNQ_TOO_LARGE == unq_res)
    return MHD_DAUTH_TOO_LARGE;
  if (mhd_UNQ_OUT_OF_MEM == unq_res)
    return MHD_DAUTH_ERROR;
  digest_update_cbuf (da, &unquoted);
  /* Update digest with ':' */
  digest_update_with_colon (da);
  if (MHD_DIGEST_AUTH_QOP_NONE != c_qop)
  {
    /* Update digest with 'nc' text value */
    unq_res = get_unquoted_param (&params->nc, tmp1, ptmp2, &tmp2_size,
                                  &unquoted);
    if (mhd_UNQ_TOO_LARGE == unq_res)
      return MHD_DAUTH_TOO_LARGE;
    if (mhd_UNQ_OUT_OF_MEM == unq_res)
      return MHD_DAUTH_ERROR;
    digest_update_cbuf (da, &unquoted);
    /* Update digest with ':' */
    digest_update_with_colon (da);
    /* Update digest with 'cnonce' value */
    unq_res = get_unquoted_param (&params->cnonce, tmp1, ptmp2, &tmp2_size,
                                  &unquoted);
    if (mhd_UNQ_TOO_LARGE == unq_res)
      return MHD_DAUTH_TOO_LARGE;
    if (mhd_UNQ_OUT_OF_MEM == unq_res)
      return MHD_DAUTH_ERROR;
    digest_update_cbuf (da, &unquoted);
    /* Update digest with ':' */
    digest_update_with_colon (da);
    /* Update digest with 'qop' value */
    unq_res = get_unquoted_param (&params->qop_raw, tmp1, ptmp2, &tmp2_size,
                                  &unquoted);
    if (mhd_UNQ_TOO_LARGE == unq_res)
      return MHD_DAUTH_TOO_LARGE;
    if (mhd_UNQ_OUT_OF_MEM == unq_res)
      return MHD_DAUTH_ERROR;
    digest_update_cbuf (da, &unquoted);
    /* Update digest with ':' */
    digest_update_with_colon (da);
  }
  /* Update digest with H(A2) */
  mhd_bin_to_hex (hash2_bin, digest_size, tmp1);
  digest_update (da, digest_size * 2, (const uint8_t *) tmp1);

  /* H(A2) is not needed anymore, reuse the buffer.
   * Use hash2_bin for the calculated response in binary form */
  digest_calc_hash (da, hash2_bin);
#ifdef mhd_DIGEST_HAS_EXT_ERROR
  if (digest_has_error (da))
    return MHD_DAUTH_ERROR;
#endif /* mhd_DIGEST_HAS_EXT_ERROR */

  if (0 != memcmp (hash1_bin, hash2_bin, digest_size))
    return MHD_DAUTH_RESPONSE_WRONG;

  return MHD_DAUTH_OK;
}


/**
 * Authenticates the authorization header sent by the client
 *
 * If RFC2069 mode is allowed by setting bit #MHD_DIGEST_AUTH_QOP_NONE in
 * @a mqop and the client uses this mode, then server generated nonces are
 * used as one-time nonces because nonce-count is not supported in this old RFC.
 * Communication in this mode is very inefficient, especially if the client
 * requests several resources one-by-one as for every request new nonce must be
 * generated and client repeat all requests twice (the first time to get a new
 * nonce and the second time to perform an authorised request).
 *
 * @param req the request handle
 * @param realm the realm for authorization of the client
 * @param username the username to be authenticated, must be in clear text
 *                 even if userhash is used by the client
 * @param password the password used in the authentication,
 *                 must be NULL if @a userdigest is not NULL
 * @param userdigest the precalculated binary hash of the string
 *                   "username:realm:password",
 *                   must be NULL if @a password is not NULL
 * @param max_nc the maximum allowed nc (Nonce Count) value, if client's nc
 *               exceeds the specified value then MHD_DAUTH_NONCE_STALE is
 *               returned;
 *               if set to zero then daemon's default value is used
 * @param mqop the QOP to use
 * @param malgo digest algorithms allowed to use, fail if algorithm specified
 *               by the client is not allowed by this parameter
 * @return #MHD_DAUTH_OK if authenticated,
 *         error code otherwise.
 * @ingroup authentication
 */
static enum MHD_DigestAuthResult
digest_auth_check_all (struct MHD_Request *restrict req,
                       const char *restrict realm,
                       const char *restrict username,
                       const char *restrict password,
                       const uint8_t *restrict userdigest,
                       uint_fast32_t max_nc,
                       enum MHD_DigestAuthMultiQOP mqop,
                       enum MHD_DigestAuthMultiAlgo malgo)
{
  enum MHD_DigestAuthResult res;
  char *buf;
  struct DigestAlgorithm da;

  buf = NULL;
  digest_setup_zero (&da);
  res = digest_auth_check_all_inner (req,
                                     realm,
                                     username,
                                     password,
                                     userdigest,
                                     max_nc,
                                     mqop,
                                     malgo,
                                     &buf,
                                     &da);
  digest_deinit (&da);
  if (NULL != buf)
    free (buf);

  return res;
}


/**
 * Authenticates the authorization header sent by the client.
 *
 * If RFC2069 mode is allowed by setting bit #MHD_DIGEST_AUTH_QOP_NONE in
 * @a mqop and the client uses this mode, then server generated nonces are
 * used as one-time nonces because nonce-count is not supported in this old RFC.
 * Communication in this mode is very inefficient, especially if the client
 * requests several resources one-by-one as for every request a new nonce must
 * be generated and client repeats all requests twice (first time to get a new
 * nonce and second time to perform an authorised request).
 *
 * @param request the request
 * @param realm the realm for authorization of the client
 * @param username the username to be authenticated, must be in clear text
 *                 even if userhash is used by the client
 * @param password the password matching the @a username (and the @a realm)
 * @param nonce_timeout the period of seconds since nonce generation, when
 *                      the nonce is recognised as valid and not stale;
 *                      if zero is specified then daemon default value is used.
 * @param max_nc the maximum allowed nc (Nonce Count) value, if client's nc
 *               exceeds the specified value then MHD_DAUTH_NONCE_STALE is
 *               returned;
 *               if zero is specified then daemon default value is used.
 * @param mqop the QOP to use
 * @param malgo digest algorithms allowed to use, fail if algorithm used
 *               by the client is not allowed by this parameter
 * @return #MHD_DAUTH_OK if authenticated,
 *         the error code otherwise
 * @ingroup authentication
 */
MHD_EXTERN_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2) MHD_FN_PAR_CSTR_ (3) MHD_FN_PAR_CSTR_ (4)
enum MHD_DigestAuthResult
MHD_digest_auth_check (struct MHD_Request *MHD_RESTRICT request,
                       const char *MHD_RESTRICT realm,
                       const char *MHD_RESTRICT username,
                       const char *MHD_RESTRICT password,
                       uint_fast32_t max_nc,
                       enum MHD_DigestAuthMultiQOP mqop,
                       enum MHD_DigestAuthMultiAlgo malgo)
{
  return digest_auth_check_all (request,
                                realm,
                                username,
                                password,
                                NULL,
                                max_nc,
                                mqop,
                                malgo);
}


MHD_EXTERN_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_CSTR_ (3)
MHD_FN_PAR_IN_SIZE_ (5, 4) enum MHD_DigestAuthResult
MHD_digest_auth_check_digest (struct MHD_Request *MHD_RESTRICT request,
                              const char *MHD_RESTRICT realm,
                              const char *MHD_RESTRICT username,
                              size_t userdigest_size,
                              const void *MHD_RESTRICT userdigest,
                              uint_fast32_t max_nc,
                              enum MHD_DigestAuthMultiQOP mqop,
                              enum MHD_DigestAuthMultiAlgo malgo)
{
  if (1 != (((0 != (malgo & MHD_DIGEST_BASE_ALGO_MD5)) ? 1 : 0)
            + ((0 != (malgo & MHD_DIGEST_BASE_ALGO_SHA256)) ? 1 : 0)
            + ((0 != (malgo & MHD_DIGEST_BASE_ALGO_SHA512_256)) ? 1 : 0)))
    return MHD_DAUTH_UNSUPPORTED_ALGO;

#ifndef MHD_SUPPORT_MD5
  if (0 != (((unsigned int) malgo) & MHD_DIGEST_BASE_ALGO_MD5))
    return MHD_DAUTH_UNSUPPORTED_ALGO;
#endif /* ! MHD_SUPPORT_MD5 */
#ifndef MHD_SUPPORT_SHA256
  if (0 != (((unsigned int) malgo) & MHD_DIGEST_BASE_ALGO_SHA256))
    return MHD_DAUTH_UNSUPPORTED_ALGO;
#endif /* ! MHD_SUPPORT_SHA256 */
#ifndef MHD_SUPPORT_SHA512_256
  if (0 != (((unsigned int) malgo) & MHD_DIGEST_BASE_ALGO_SHA512_256))
    return MHD_DAUTH_UNSUPPORTED_ALGO;
#endif /* ! MHD_SUPPORT_SHA512_256 */

  if (digest_get_hash_size ((enum MHD_DigestAuthAlgo) malgo) !=
      userdigest_size)
    return MHD_DAUTH_INVALID_USERDIGEST_SIZE;

  return digest_auth_check_all (request,
                                realm,
                                username,
                                NULL,
                                (const uint8_t *) userdigest,
                                max_nc,
                                mqop,
                                malgo);
}
