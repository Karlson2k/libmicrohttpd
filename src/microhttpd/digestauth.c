/*
     This file is part of libmicrohttpd
     Copyright (C) 2010, 2011, 2012, 2015, 2018 Daniel Pittman and Christian Grothoff
     Copyright (C) 2014-2022 Evgeny Grin (Karlson2k)

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
/**
 * @file digestauth.c
 * @brief Implements HTTP digest authentication
 * @author Amr Ali
 * @author Matthieu Speder
 * @author Christian Grothoff (RFC 7616 support)
 * @author Karlson2k (Evgeny Grin)
 */
#include "digestauth.h"
#include "gen_auth.h"
#include "platform.h"
#include "mhd_limits.h"
#include "internal.h"
#include "md5.h"
#include "sha256.h"
#include "mhd_mono_clock.h"
#include "mhd_str.h"
#include "mhd_compat.h"
#include "mhd_bithelpers.h"
#include "mhd_assert.h"

#if defined(MHD_W32_MUTEX_)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif /* !WIN32_LEAN_AND_MEAN */
#include <windows.h>
#endif /* MHD_W32_MUTEX_ */


/**
 * Allow re-use of the nonce-nc map array slot after #REUSE_TIMEOUT seconds,
 * if this slot is needed for the new nonce, while the old nonce was not used
 * even one time by the client.
 * Typically clients immediately use generated nonce for new request.
 */
#define REUSE_TIMEOUT 30

/**
 * The maximum value of artificial timestamp difference to avoid clashes.
 * The value must be suitable for bitwise AND operation.
 */
#define DAUTH_JUMPBACK_MAX (0x7F)


/**
 * 48 bit value in bytes
 */
#define TIMESTAMP_BIN_SIZE (48 / 8)


/**
 * Trim value to the TIMESTAMP_BIN_SIZE size
 */
#define TRIM_TO_TIMESTAMP(value) \
  ((value) & ((UINT64_C(1) << (TIMESTAMP_BIN_SIZE * 8)) - 1))


/**
 * The printed timestamp size in chars
 */
#define TIMESTAMP_CHARS_LEN (TIMESTAMP_BIN_SIZE * 2)


/**
 * Standard server nonce length, not including terminating null,
 *
 * @param digest_size digest size
 */
#define NONCE_STD_LEN(digest_size) \
  ((digest_size) * 2 + TIMESTAMP_CHARS_LEN)


/**
 * Maximum size of any digest hash supported by MHD.
 * (SHA-256 > MD5).
 */
#define MAX_DIGEST SHA256_DIGEST_SIZE

/**
 * Macro to avoid using VLAs if the compiler does not support them.
 */
#ifndef HAVE_C_VARARRAYS
/**
 * Return #MAX_DIGEST.
 *
 * @param n length of the digest to be used for a VLA
 */
#define VLA_ARRAY_LEN_DIGEST(n) (MAX_DIGEST)

#else
/**
 * Return @a n.
 *
 * @param n length of the digest to be used for a VLA
 */
#define VLA_ARRAY_LEN_DIGEST(n) (n)
#endif

/**
 * Check that @a n is below #MAX_DIGEST
 */
#define VLA_CHECK_LEN_DIGEST(n) \
  do { if ((n) > MAX_DIGEST) MHD_PANIC (_ ("VLA too big.\n")); } while (0)

/**
 * Maximum length of a username for digest authentication.
 */
#define MAX_USERNAME_LENGTH 128

/**
 * Maximum length of a realm for digest authentication.
 */
#define MAX_REALM_LENGTH 256

/**
 * Maximum length of the response in digest authentication.
 */
#define MAX_AUTH_RESPONSE_LENGTH (MAX_DIGEST * 2)

/**
 * The token for MD5 algorithm.
 */
#define _MHD_MD5_TOKEN "MD5"

/**
 * The token for SHA-256 algorithm.
 */
#define _MHD_SHA256_TOKEN "SHA-256"

/**
 * The token for SHA-512/256 algorithm.
 * Unsupported currently by MHD for authentication.
 */
#define _MHD_SHA512_256_TOKEN "SHA-512-256"

/**
 * The postfix token for "session" algorithms.
 */
#define _MHD_SESS_TOKEN "-sess"

/**
 * The required prefix of parameter with the extended notation
 */
#define MHD_DAUTH_EXT_PARAM_PREFIX "UTF-8'"

/**
 * The minimal size of the prefix for parameter with the extended notation
 */
#define MHD_DAUTH_EXT_PARAM_MIN_LEN \
  MHD_STATICSTR_LEN_(MHD_DAUTH_EXT_PARAM_PREFIX "'")

/**
 * The result of nonce-nc map array check.
 */
enum MHD_CheckNonceNC_
{
  /**
   * The nonce and NC are OK (valid and NC was not used before).
   */
  MHD_CHECK_NONCENC_OK = MHD_DAUTH_OK,

  /**
   * The 'nonce' was overwritten with newer 'nonce' in the same slot or
   * NC was already used.
   * The validity of the 'nonce' was not be checked.
   */
  MHD_CHECK_NONCENC_STALE = MHD_DAUTH_NONCE_STALE,

  /**
   * The 'nonce' is wrong, it was not generated before.
   */
  MHD_CHECK_NONCENC_WRONG = MHD_DAUTH_NONCE_WRONG,
};


/**
 * Digest context data
 */
union DigestCtx
{
  struct MD5Context md5_ctx;
  struct Sha256Ctx sha256_ctx;
};

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
#if _DEBUG
  bool setup; /**< The structure was set-up */
  bool inited; /**< The calculation was initialised */
  bool digest_calculated; /**< The digest was calculated */
#endif /* _DEBUG */
};


/**
 * Return name of the algorithm as a string.
 * @param da the digest calculation structure to identify
 * @return the name of the @a algo as a string.
 */
_MHD_static_inline const char *
digest_get_algo_name (struct DigestAlgorithm *da)
{
  mhd_assert (da->setup);
  if (MHD_DIGEST_BASE_ALGO_MD5 == da->algo)
    return _MHD_MD5_TOKEN;
  if (MHD_DIGEST_BASE_ALGO_SHA256 == da->algo)
    return _MHD_SHA256_TOKEN;
  mhd_assert (0); /* May not happen */
  return "";
}


/**
 * Return the size of the digest.
 * @param da the digest calculation structure to identify
 * @return the size of the digest.
 */
_MHD_static_inline unsigned int
digest_get_size (struct DigestAlgorithm *da)
{
  mhd_assert (da->setup);
  if (MHD_DIGEST_BASE_ALGO_MD5 == da->algo)
    return MD5_DIGEST_SIZE;
  if (MHD_DIGEST_BASE_ALGO_SHA256 == da->algo)
    return SHA256_DIGEST_SIZE;
  mhd_assert (0); /* May not happen */
  return 0;
}


/**
 * Set-up the digest calculation structure.
 * @param da the structure to set-up
 * @param algo the algorithm to use for digest calculation
 * @return boolean 'true' if successfully set-up,
 *         false otherwise.
 */
_MHD_static_inline bool
digest_setup (struct DigestAlgorithm *da,
              enum MHD_DigestBaseAlgo algo)
{
#ifdef _DEBUG
  da->setup = false;
  da->inited = false;
  da->digest_calculated = false;
#endif /* _DEBUG */
  if ((MHD_DIGEST_BASE_ALGO_MD5 == algo) ||
      (MHD_DIGEST_BASE_ALGO_SHA256 == algo))
  {
    da->algo = algo;
#ifdef _DEBUG
    da->setup = true;
#endif /* _DEBUG */
    return true;
  }
  mhd_assert (0); /* Bad parameter */
  return false;
}


/**
 * Initialise/reset the digest calculation structure.
 * @param da the structure to initialise/reset
 */
_MHD_static_inline void
digest_init (struct DigestAlgorithm *da)
{
  mhd_assert (da->setup);
#ifdef _DEBUG
  da->digest_calculated = false;
#endif
  if (MHD_DIGEST_BASE_ALGO_MD5 == da->algo)
  {
    MHD_MD5Init (&da->ctx.md5_ctx);
#ifdef _DEBUG
    da->inited = true;
#endif
  }
  else if (MHD_DIGEST_BASE_ALGO_SHA256 == da->algo)
  {
    MHD_SHA256_init (&da->ctx.sha256_ctx);
#ifdef _DEBUG
    da->inited = true;
#endif
  }
  else
  {
#ifdef _DEBUG
    da->inited = false;
#endif
    mhd_assert (0); /* Bad algorithm */
  }
}


/**
 * Feed digest calculation with more data.
 * @param da the digest calculation
 * @param data the data to process
 * @param length the size of the @a data in bytes
 */
_MHD_static_inline void
digest_update (struct DigestAlgorithm *da,
               const void *data,
               size_t length)
{
  mhd_assert (da->inited);
  mhd_assert (! da->digest_calculated);
  if (MHD_DIGEST_BASE_ALGO_MD5 == da->algo)
    MHD_MD5Update (&da->ctx.md5_ctx, (const uint8_t *) data, length);
  else if (MHD_DIGEST_BASE_ALGO_SHA256 == da->algo)
    MHD_SHA256_update (&da->ctx.sha256_ctx, (const uint8_t *) data, length);
  else
    mhd_assert (0); /* May not happen */
}


/**
 * Feed digest calculation with more data from string.
 * @param da the digest calculation
 * @param str the zero-terminated string to process
 */
_MHD_static_inline void
digest_update_str (struct DigestAlgorithm *da,
                   const char *str)
{
  const size_t str_len = strlen (str);
  digest_update (da, (const uint8_t *) str, str_len);
}


/**
 * Feed digest calculation with single colon ':' character.
 * @param da the digest calculation
 * @param str the zero-terminated string to process
 */
_MHD_static_inline void
digest_update_with_colon (struct DigestAlgorithm *da)
{
  static const uint8_t colon = (uint8_t) ':';
  digest_update (da, &colon, 1);
}


/**
 * Finally calculate hash (the digest).
 * @param da the digest calculation
 * @param[out] digest the pointer to the buffer to put calculated digest,
 *                    must be at least digest_get_size(da) bytes large
 */
_MHD_static_inline void
digest_calc_hash (struct DigestAlgorithm *da, uint8_t *digest)
{
  mhd_assert (da->inited);
  mhd_assert (! da->digest_calculated);
  if (MHD_DIGEST_BASE_ALGO_MD5 == da->algo)
    MHD_MD5Final (&da->ctx.md5_ctx, digest);
  else if (MHD_DIGEST_BASE_ALGO_SHA256 == da->algo)
    MHD_SHA256_finish (&da->ctx.sha256_ctx, digest);
  else
    mhd_assert (0); /* May not happen */
#ifdef _DEBUG
  da->digest_calculated = true;
#endif
}


static const struct MHD_RqDAuth *
get_rq_dauth_params (struct MHD_Connection *connection)
{
  const struct MHD_AuthRqHeader *rq_params;

  rq_params = MHD_get_auth_rq_params_ (connection);
  if ( (NULL == rq_params) ||
       (MHD_AUTHTYPE_DIGEST != rq_params->auth_type) )
    return NULL;

  return rq_params->params.dauth;
}


/**
 * Extract timestamp from the given nonce.
 * @param nonce the nonce to check
 * @param noncelen the length of the nonce, zero for autodetect
 * @param[out] ptimestamp the pointer to store extracted timestamp
 * @return true if timestamp was extracted,
 *         false if nonce does not have valid timestamp.
 */
static bool
get_nonce_timestamp (const char *const nonce,
                     size_t noncelen,
                     uint64_t *const ptimestamp)
{
  if (0 == noncelen)
    noncelen = strlen (nonce);

  if ( (NONCE_STD_LEN (SHA256_DIGEST_SIZE) != noncelen) &&
       (NONCE_STD_LEN (MD5_DIGEST_SIZE) != noncelen) )
    return false;

  if (TIMESTAMP_CHARS_LEN !=
      MHD_strx_to_uint64_n_ (nonce + noncelen - TIMESTAMP_CHARS_LEN,
                             TIMESTAMP_CHARS_LEN,
                             ptimestamp))
    return false;
  return true;
}


/**
 * Super-fast xor-based "hash" function
 *
 * @param data the data to calculate hash for
 * @param data_size the size of the data in bytes
 * @return the "hash"
 */
static uint32_t
fast_simple_hash (const uint8_t *data,
                  size_t data_size)
{
  uint32_t hash;

  if (0 != data_size)
  {
    size_t i;
    hash = data[0];
    for (i = 1; i < data_size; i++)
      hash = _MHD_ROTL32 (hash, 7) ^ data[i];
  }
  else
    hash = 0;

  return hash;
}


/**
 * Get index of the nonce in the nonce-nc map array.
 *
 * @param arr_size the size of nonce_nc array
 * @param nonce the pointer that referenced a zero-terminated array of nonce
 * @param noncelen the length of @a nonce, in characters
 * @return #MHD_YES if successful, #MHD_NO if invalid (or we have no NC array)
 */
static size_t
get_nonce_nc_idx (size_t arr_size,
                  const char *nonce,
                  size_t noncelen)
{
  mhd_assert (0 != arr_size);
  mhd_assert (0 != noncelen);
  return fast_simple_hash ((const uint8_t *) nonce, noncelen) % arr_size;
}


/**
 * Check nonce-nc map array with the new nonce counter.
 *
 * @param connection The MHD connection structure
 * @param nonce the pointer that referenced hex nonce, does not need to be
 *              zero-terminated
 * @param noncelen the length of @a nonce, in characters
 * @param nc The nonce counter
 * @return #MHD_DAUTH_NONCENC_OK if successful,
 *         #MHD_DAUTH_NONCENC_STALE if nonce is stale (or no nonce-nc array
 *         is available),
 *         #MHD_DAUTH_NONCENC_WRONG if nonce was not recodered in nonce-nc map
 *         array, while it should.
 */
static enum MHD_CheckNonceNC_
check_nonce_nc (struct MHD_Connection *connection,
                const char *nonce,
                size_t noncelen,
                uint64_t nonce_time,
                uint64_t nc)
{
  struct MHD_Daemon *daemon = MHD_get_master (connection->daemon);
  struct MHD_NonceNc *nn;
  uint32_t mod;
  enum MHD_CheckNonceNC_ ret;

  mhd_assert (0 != noncelen);
  mhd_assert (0 != nc);
  if (MAX_DIGEST_NONCE_LENGTH < noncelen)
    return MHD_CHECK_NONCENC_WRONG; /* This should be impossible, but static analysis
                      tools have a hard time with it *and* this also
                      protects against unsafe modifications that may
                      happen in the future... */
  mod = daemon->nonce_nc_size;
  if (0 == mod)
    return MHD_CHECK_NONCENC_STALE;  /* no array! */
  if (nc >= UINT64_MAX - 64)
    return MHD_CHECK_NONCENC_STALE;  /* Overflow, unrealistically high value */

  nn = &daemon->nnc[get_nonce_nc_idx (mod, nonce, noncelen)];

  MHD_mutex_lock_chk_ (&daemon->nnc_lock);

  mhd_assert (0 == nn->nonce[noncelen]); /* The old value must be valid */

  if ( (0 != memcmp (nn->nonce, nonce, noncelen)) ||
       (0 != nn->nonce[noncelen]) )
  { /* The nonce in the slot does not match nonce from the client */
    if (0 == nn->nonce[0])
    { /* The slot was never used, while the client's nonce value should be
       * recorded when it was generated by MHD */
      ret = MHD_CHECK_NONCENC_WRONG;
    }
    else if (0 != nn->nonce[noncelen])
    { /* The value is the slot is wrong */
      ret =  MHD_CHECK_NONCENC_STALE;
    }
    else
    {
      uint64_t slot_ts; /**< The timestamp in the slot */
      if (! get_nonce_timestamp (nn->nonce, noncelen, &slot_ts))
      {
        mhd_assert (0); /* The value is the slot is wrong */
        ret = MHD_CHECK_NONCENC_STALE;
      }
      else
      {
        /* Unsigned value, will be large if nonce_time is less than slot_ts */
        const uint64_t ts_diff = TRIM_TO_TIMESTAMP (nonce_time - slot_ts);
        if ((REUSE_TIMEOUT * 1000) >= ts_diff)
        {
          /* The nonce from the client may not have been placed in the slot
           * because another nonce in that slot has not yet expired. */
          ret = MHD_CHECK_NONCENC_STALE;
        }
        else if (TRIM_TO_TIMESTAMP (UINT64_MAX) / 2 >= ts_diff)
        {
          /* Too large value means that nonce_time is less than slot_ts.
           * The nonce from the client may have been overwritten by the newer
           * nonce. */
          ret = MHD_CHECK_NONCENC_STALE;
        }
        else
        {
          /* The nonce from the client should be generated after the nonce
           * in the slot has been expired, the nonce must be recorded, but
           * it's not. */
          ret = MHD_CHECK_NONCENC_WRONG;
        }
      }
    }
  }
  else if (nc > nn->nc)
  {
    /* 'nc' is larger, shift bitmask and bump limit */
    const uint64_t jump_size = nc - nn->nc;
    if (64 > jump_size)
    {
      /* small jump, less than mask width */
      nn->nmask <<= jump_size;
      /* Set bit for the old 'nc' value */
      nn->nmask |= (UINT64_C (1) << (jump_size - 1));
    }
    else if (64 == jump_size)
      nn->nmask = (UINT64_C (1) << 63);
    else
      nn->nmask = 0;                /* big jump, unset all bits in the mask */
    nn->nc = nc;
    ret = MHD_CHECK_NONCENC_OK;
  }
  else if (nc < nn->nc)
  {
    /* Note that we use 64 here, as we do not store the
       bit for 'nn->nc' itself in 'nn->nmask' */
    if ( (nc + 64 >= nn->nc) &&
         (0 == ((UINT64_C (1) << (nn->nc - nc - 1)) & nn->nmask)) )
    {
      /* Out-of-order nonce, but within 64-bit bitmask, set bit */
      nn->nmask |= (UINT64_C (1) << (nn->nc - nc - 1));
      ret = MHD_CHECK_NONCENC_OK;
    }
    else
      /* 'nc' was already used or too old (more then 64 values ago) */
      ret = MHD_CHECK_NONCENC_STALE;
  }
  else /* if (nc == nn->nc) */
    /* 'nc' was already used */
    ret = MHD_CHECK_NONCENC_STALE;

  MHD_mutex_unlock_chk_ (&daemon->nnc_lock);

  return ret;
}


/**
 * Get username type used by the client.
 * This function does not check whether userhash can be decoded or
 * extended notation (if used) is valid.
 * @param params the Digest Authorization parameters
 * @return the type of username
 */
_MHD_static_inline enum MHD_DigestAuthUsernameType
get_rq_uname_type (const struct MHD_RqDAuth *params)
{
  if (NULL != params->username.value.str)
  {
    if (NULL == params->username_ext.value.str)
      return params->userhash ?
             MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH :
             MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD;
    else  /* Both 'username' and 'username*' are used */
      return MHD_DIGEST_AUTH_UNAME_TYPE_INVALID;
  }
  else if (NULL != params->username_ext.value.str)
  {
    if (! params->username_ext.quoted && ! params->userhash &&
        (MHD_DAUTH_EXT_PARAM_MIN_LEN <= params->username_ext.value.len) )
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
_MHD_static_inline size_t
get_rq_unames_size (const struct MHD_RqDAuth *params,
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
    s += params->username_ext.value.len + 1; /* Add one byte for zero-termination */
  return s;
}


/**
 * Get client's Digest Authorization algorithm type.
 * If no algorithm is specified by client, MD5 is assumed.
 * @param params the Digest Authorization parameters
 * @return the algorithm type
 */
static enum MHD_DigestAuthAlgo3
get_rq_algo (const struct MHD_RqDAuth *params)
{
  const struct MHD_RqDAuthParam *const algo_param =
    &params->algorithm;
  if (NULL == algo_param->value.str)
    return MHD_DIGEST_AUTH_ALGO3_MD5; /* Assume MD5 by default */

  if (algo_param->quoted)
  {
    if (MHD_str_equal_caseless_quoted_s_bin_n (algo_param->value.str, \
                                               algo_param->value.len, \
                                               _MHD_MD5_TOKEN))
      return MHD_DIGEST_AUTH_ALGO3_MD5;
    if (MHD_str_equal_caseless_quoted_s_bin_n (algo_param->value.str, \
                                               algo_param->value.len, \
                                               _MHD_SHA256_TOKEN))
      return MHD_DIGEST_AUTH_ALGO3_SHA256;
    if (MHD_str_equal_caseless_quoted_s_bin_n (algo_param->value.str, \
                                               algo_param->value.len, \
                                               _MHD_MD5_TOKEN _MHD_SESS_TOKEN))
      return MHD_DIGEST_AUTH_ALGO3_MD5_SESSION;
    if (MHD_str_equal_caseless_quoted_s_bin_n (algo_param->value.str, \
                                               algo_param->value.len, \
                                               _MHD_SHA256_TOKEN \
                                               _MHD_SESS_TOKEN))
      return MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION;

    /* Algorithms below are not supported by MHD for authentication */

    if (MHD_str_equal_caseless_quoted_s_bin_n (algo_param->value.str, \
                                               algo_param->value.len, \
                                               _MHD_SHA512_256_TOKEN))
      return MHD_DIGEST_AUTH_ALGO3_SHA512_256;
    if (MHD_str_equal_caseless_quoted_s_bin_n (algo_param->value.str, \
                                               algo_param->value.len, \
                                               _MHD_SHA512_256_TOKEN \
                                               _MHD_SESS_TOKEN))
      return MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION;

    /* No known algorithm has been detected */
    return MHD_DIGEST_AUTH_ALGO3_INVALID;
  }
  /* The algorithm value is not quoted */
  if (MHD_str_equal_caseless_s_bin_n_ (_MHD_MD5_TOKEN, \
                                       algo_param->value.str, \
                                       algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO3_MD5;
  if (MHD_str_equal_caseless_s_bin_n_ (_MHD_SHA256_TOKEN, \
                                       algo_param->value.str, \
                                       algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO3_MD5;
  if (MHD_str_equal_caseless_s_bin_n_ (_MHD_MD5_TOKEN _MHD_SESS_TOKEN, \
                                       algo_param->value.str, \
                                       algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO3_MD5;
  if (MHD_str_equal_caseless_s_bin_n_ (_MHD_SHA256_TOKEN _MHD_SESS_TOKEN, \
                                       algo_param->value.str, \
                                       algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO3_MD5;

  /* Algorithms below are not supported by MHD for authentication */

  if (MHD_str_equal_caseless_s_bin_n_ (_MHD_SHA512_256_TOKEN, \
                                       algo_param->value.str, \
                                       algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO3_MD5;
  if (MHD_str_equal_caseless_s_bin_n_ (_MHD_SHA512_256_TOKEN _MHD_SESS_TOKEN, \
                                       algo_param->value.str, \
                                       algo_param->value.len))
    return MHD_DIGEST_AUTH_ALGO3_MD5;

  /* No known algorithm has been detected */
  return MHD_DIGEST_AUTH_ALGO3_INVALID;
}


/**
 * Get unquoted version of Digest Authorization parameter.
 * This function automatically zero-teminate the result.
 * @param param the parameter to extract
 * @param[out] buf the output buffer, must be enough size to hold the result,
 *                 the recommended size is 'param->value.len + 1'
 * @return the size of the result, not including the terminating zero
 */
static size_t
get_rq_param_unquoted_copy_z (const struct MHD_RqDAuthParam *param, char *buf)
{
  size_t len;
  mhd_assert (NULL != param->value.str);
  if (! param->quoted)
  {
    memcpy (buf, param->value.str, param->value.len);
    buf [param->value.len] = 0;
    return param->value.len;
  }

  len = MHD_str_unquote (param->value.str, param->value.len, buf);
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
static ssize_t
get_rq_extended_uname_copy_z (const char *uname_ext, size_t uname_ext_len,
                              char *buf, size_t buf_size)
{
  size_t r;
  size_t w;
  if ((size_t) SSIZE_MAX < uname_ext_len)
    return -1; /* Too long input string */

  if (MHD_DAUTH_EXT_PARAM_MIN_LEN > uname_ext_len)
    return -1; /* Required prefix is missing */

  if (! MHD_str_equal_caseless_bin_n_ (uname_ext, MHD_DAUTH_EXT_PARAM_PREFIX,
                                       MHD_STATICSTR_LEN_ ( \
                                         MHD_DAUTH_EXT_PARAM_PREFIX)))
    return -1; /* Only UTF-8 is supported, as it is implied by RFC 7616 */

  r = MHD_STATICSTR_LEN_ (MHD_DAUTH_EXT_PARAM_PREFIX);
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

  w = MHD_str_pct_decode_strict_n_ (uname_ext + r, uname_ext_len - r,
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
 * @param[out] unames the pointer to the structure to be filled
 * @param buf the buffer to be used for usernames
 * @param buf_size the size of the @a buf
 * @return the size of the @a buf used by pointers in @a unames structure
 */
static size_t
get_rq_uname (const struct MHD_RqDAuth *params,
              enum MHD_DigestAuthUsernameType uname_type,
              struct MHD_DigestAuthUsernameInfo *uname_info,
              uint8_t *buf,
              size_t buf_size)
{
  size_t buf_used;

  buf_used = 0;
  mhd_assert (get_rq_uname_type (params) == uname_type);
  mhd_assert (MHD_DIGEST_AUTH_UNAME_TYPE_INVALID != uname_type);
  mhd_assert (MHD_DIGEST_AUTH_UNAME_TYPE_MISSING != uname_type);

  if ( (MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD == uname_type) ||
       (MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH == uname_type) )
  {
    uname_info->username = (char *) (buf + buf_used);
    uname_info->username_len =
      get_rq_param_unquoted_copy_z (&params->username,
                                    uname_info->username);
    buf_used += uname_info->username_len + 1;
    if (MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH == uname_type)
    {
      uname_info->userhash_bin_size = MHD_hex_to_bin (uname_info->username,
                                                      uname_info->username_len,
                                                      buf + buf_used);
      if ( (0 == uname_info->userhash_bin_size) &&
           (0 != uname_info->username_len) )
      {
        uname_info->userhash_bin = NULL;
        uname_info->uname_type = MHD_DIGEST_AUTH_UNAME_TYPE_INVALID;
      }
      else
      {
        uname_info->userhash_bin = (uint8_t *) (buf + buf_used);
        buf_used += uname_info->userhash_bin_size;
      }
    }
  }
  else if (MHD_DIGEST_AUTH_UNAME_TYPE_EXTENDED == uname_type)
  {
    ssize_t res;
    res = get_rq_extended_uname_copy_z (params->username_ext.value.str,
                                        params->username_ext.value.len,
                                        (char *) (buf + buf_used),
                                        buf_size - buf_used);
    if (0 > res)
      uname_info->uname_type = MHD_DIGEST_AUTH_UNAME_TYPE_INVALID;
    else
    {
      uname_info->username = (char *) (buf + buf_used);
      uname_info->username_len = (size_t) res;
      buf_used += uname_info->username_len + 1;
    }
  }
  mhd_assert (buf_size >= buf_used);
  return buf_used;
}


/**
 * Get QOP ('quality of protection') type.
 * @param params the Digest Authorization parameters
 * @return detected QOP ('quality of protection') type.
 */
static enum MHD_DigestAuthQOP
get_rq_qop (const struct MHD_RqDAuth *params)
{
  const struct MHD_RqDAuthParam *const qop_param =
    &params->qop;
  if (NULL == qop_param->value.str)
    return MHD_DIGEST_AUTH_QOP_NONE;
  if (qop_param->quoted)
  {
    if (MHD_str_equal_caseless_quoted_s_bin_n (qop_param->value.str, \
                                               qop_param->value.len, \
                                               "auth"))
      return MHD_DIGEST_AUTH_QOP_AUTH;
    if (MHD_str_equal_caseless_quoted_s_bin_n (qop_param->value.str, \
                                               qop_param->value.len, \
                                               "auth-int"))
      return MHD_DIGEST_AUTH_QOP_AUTH_INT;
  }
  else
  {
    if (MHD_str_equal_caseless_s_bin_n_ ("auth", \
                                         qop_param->value.str, \
                                         qop_param->value.len))
      return MHD_DIGEST_AUTH_QOP_AUTH;
    if (MHD_str_equal_caseless_s_bin_n_ ("auth-int", \
                                         qop_param->value.str, \
                                         qop_param->value.len))
      return MHD_DIGEST_AUTH_QOP_AUTH_INT;
  }
  /* No know QOP has been detected */
  return MHD_DIGEST_AUTH_QOP_INVALID;
}


/**
 * Result of request's Digest Authorization 'nc' value extraction
 */
enum MHD_GetRqNCResult
{
  MHD_GET_RQ_NC_NONE = -1,    /**< No 'nc' value */
  MHD_GET_RQ_NC_VALID = 0,    /**< Readable 'nc' value */
  MHD_GET_RQ_NC_TOO_LONG = 1, /**< The 'nc' value is too long */
  MHD_GET_RQ_NC_TOO_LARGE = 2,/**< The 'nc' value is too big to fit uint32_t */
  MHD_GET_RQ_NC_BROKEN = 3    /**< The 'nc' value is not a number */
};


/**
 * Get 'nc' value from request's Authorization header
 * @param params the request digest authentication
 * @param[out] nc the pointer to put nc value to
 * @return enum value indicating the result
 */
static enum MHD_GetRqNCResult
get_rq_nc (const struct MHD_RqDAuth *params,
           uint32_t *nc)
{
  const struct MHD_RqDAuthParam *const nc_param =
    &params->nc;
  char unq[16];
  const char *val;
  size_t val_len;
  size_t res;
  uint64_t nc_val;

  if (NULL == nc_param->value.str)
    return MHD_GET_RQ_NC_NONE;

  if (0 == nc_param->value.len)
    return MHD_GET_RQ_NC_BROKEN;

  if (! nc_param->quoted)
  {
    val = nc_param->value.str;
    val_len = nc_param->value.len;
  }
  else
  {
    /* Actually no backslashes must be used in 'nc' */
    if (sizeof(unq) < params->nc.value.len)
      return MHD_GET_RQ_NC_TOO_LONG;
    val_len = MHD_str_unquote (nc_param->value.str, nc_param->value.len, unq);
    if (0 == val_len)
      return MHD_GET_RQ_NC_BROKEN;
    val = unq;
  }

  res = MHD_strx_to_uint64_n_ (val, val_len, &nc_val);
  if (0 == res)
  {
    const char f = val[0];
    if ( (('9' >= f) && ('0' <= f)) ||
         (('F' >= f) && ('A' <= f)) ||
         (('a' <= f) && ('f' >= f)) )
      return MHD_GET_RQ_NC_TOO_LARGE;
    else
      return MHD_GET_RQ_NC_BROKEN;
  }
  if (val_len != res)
    return MHD_GET_RQ_NC_BROKEN;
  if (UINT32_MAX < nc_val)
    return MHD_GET_RQ_NC_TOO_LARGE;
  *nc = (uint32_t) nc_val;
  return MHD_GET_RQ_NC_VALID;
}


/**
 * Get information about Digest Authorization client's header.
 *
 * @param connection The MHD connection structure
 * @return NULL no valid Digest Authorization header is used in the request;
 *         a pointer structure with information if the valid request header
 *         found, free using #MHD_free().
 * @note Available since #MHD_VERSION 0x00097519
 * @ingroup authentication
 */
_MHD_EXTERN struct MHD_DigestAuthInfo *
MHD_digest_auth_get_request_info3 (struct MHD_Connection *connection)
{
  const struct MHD_RqDAuth *params;
  struct MHD_DigestAuthInfo *info;
  enum MHD_DigestAuthUsernameType uname_type;
  size_t unif_buf_size;
  uint8_t *unif_buf_ptr;
  size_t unif_buf_used;
  enum MHD_GetRqNCResult nc_res;

  params = get_rq_dauth_params (connection);
  if (NULL == params)
    return NULL;

  unif_buf_size = 0;

  uname_type = get_rq_uname_type (params);

  unif_buf_size += get_rq_unames_size (params, uname_type);

  if (NULL != params->opaque.value.str)
    unif_buf_size += params->opaque.value.len + 1;  /* Add one for zero-termination */
  if (NULL != params->realm.value.str)
    unif_buf_size += params->realm.value.len + 1;   /* Add one for zero-termination */
  info = (struct MHD_DigestAuthInfo *)
         MHD_calloc_ (1, (sizeof(struct MHD_DigestAuthInfo)) + unif_buf_size);
  unif_buf_ptr = (uint8_t *) (info + 1);
  unif_buf_used = 0;

  info->algo = get_rq_algo (params);

  if ( (MHD_DIGEST_AUTH_UNAME_TYPE_MISSING != uname_type) &&
       (MHD_DIGEST_AUTH_UNAME_TYPE_INVALID != uname_type) )
  {
    struct MHD_DigestAuthUsernameInfo uname_strct;
    memset (&uname_strct, 0, sizeof(uname_strct));
    unif_buf_used += get_rq_uname (params, uname_type, &uname_strct,
                                   unif_buf_ptr + unif_buf_used,
                                   unif_buf_size - unif_buf_used);
    info->uname_type = uname_strct.uname_type;
    info->username = uname_strct.username;
    info->username_len = uname_strct.username_len;
    info->userhash_bin = uname_strct.userhash_bin;
    info->userhash_bin_size = uname_strct.userhash_bin_size;
  }
  else
    info->uname_type = uname_type;

  if (NULL != params->opaque.value.str)
  {
    info->opaque = (char *) (unif_buf_ptr + unif_buf_used);
    info->opaque_len = get_rq_param_unquoted_copy_z (&params->opaque,
                                                     info->opaque);
    unif_buf_used += info->opaque_len + 1;
  }
  if (NULL != params->realm.value.str)
  {
    info->realm = (char *) (unif_buf_ptr + unif_buf_used);
    info->realm_len = get_rq_param_unquoted_copy_z (&params->realm,
                                                    info->realm);
    unif_buf_used += info->realm_len + 1;
  }

  mhd_assert (unif_buf_size >= unif_buf_used);

  info->qop = get_rq_qop (params);

  if (NULL != params->cnonce.value.str)
    info->cnonce_len = params->cnonce.value.len;
  else
    info->cnonce_len = 0;

  nc_res = get_rq_nc (params, &info->nc);
  if (MHD_GET_RQ_NC_VALID != nc_res)
    info->nc = MHD_DIGEST_AUTH_INVALID_NC_VALUE;

  return info;
}


/**
 * Get the username from Digest Authorization client's header.
 *
 * @param connection The MHD connection structure
 * @return NULL if no valid Digest Authorization header is used in the request,
 *         or no username parameter is present in the header, or username is
 *         provided incorrectly by client (see description for
 *         #MHD_DIGEST_AUTH_UNAME_TYPE_INVALID);
 *         a pointer structure with information if the valid request header
 *         found, free using #MHD_free().
 * @sa MHD_digest_auth_get_request_info3() provides more complete information
 * @note Available since #MHD_VERSION 0x00097519
 * @ingroup authentication
 */
_MHD_EXTERN struct MHD_DigestAuthUsernameInfo *
MHD_digest_auth_get_username3 (struct MHD_Connection *connection)
{
  const struct MHD_RqDAuth *params;
  struct MHD_DigestAuthUsernameInfo *uname_info;
  enum MHD_DigestAuthUsernameType uname_type;
  size_t unif_buf_size;
  uint8_t *unif_buf_ptr;
  size_t unif_buf_used;

  params = get_rq_dauth_params (connection);
  if (NULL == params)
    return NULL;

  uname_type = get_rq_uname_type (params);
  if ( (MHD_DIGEST_AUTH_UNAME_TYPE_MISSING == uname_type) ||
       (MHD_DIGEST_AUTH_UNAME_TYPE_INVALID == uname_type) )
    return NULL;

  unif_buf_size = get_rq_unames_size (params, uname_type);

  uname_info = (struct MHD_DigestAuthUsernameInfo *)
               MHD_calloc_ (1, (sizeof(struct MHD_DigestAuthUsernameInfo))
                            + unif_buf_size);
  unif_buf_ptr = (uint8_t *) (uname_info + 1);
  unif_buf_used = get_rq_uname (params, uname_type, uname_info, unif_buf_ptr,
                                unif_buf_size);
  mhd_assert (unif_buf_size >= unif_buf_used);
  (void) unif_buf_used; /* Mute compiler warning on non-debug builds */
  mhd_assert (MHD_DIGEST_AUTH_UNAME_TYPE_MISSING != uname_info->uname_type);

  if (MHD_DIGEST_AUTH_UNAME_TYPE_INVALID == uname_info->uname_type)
  {
    free (uname_info);
    return NULL;
  }
  mhd_assert (uname_type == uname_info->uname_type);

  return uname_info;
}


/**
 * Get the username from the authorization header sent by the client
 *
 * @param connection The MHD connection structure
 * @return NULL if no username could be found, a pointer
 *      to the username if found
 * @warning Returned value must be freed by #MHD_free().
 * @ingroup authentication
 */
_MHD_EXTERN char *
MHD_digest_auth_get_username (struct MHD_Connection *connection)
{
  const struct MHD_RqDAuth *params;
  char *username;
  size_t username_len;

  params = get_rq_dauth_params (connection);
  if (NULL == params)
    return NULL;

  if (NULL == params->username.value.str)
    return NULL;

  username_len = params->username.value.len;
  username = malloc (username_len + 1);
  if (NULL == username)
    return NULL;

  if (! params->username.quoted)
  {
    /* The username is not quoted, no need to unquote */
    if (0 != username_len)
      memcpy (username, params->username.value.str, username_len);
    username[username_len] = 0; /* Zero-terminate */
  }
  else
  {
    /* Need to properly unquote the username */
    mhd_assert (0 != username_len); /* Quoted string may not be zero-legth */
    username_len = MHD_str_unquote (params->username.value.str, username_len,
                                    username);
    mhd_assert (0 != username_len); /* The unquoted string cannot be empty */
    username[username_len] = 0; /* Zero-terminate */
  }

  return username;
}


/**
 * Calculate the server nonce so that it mitigates replay attacks
 * The current format of the nonce is ...
 * H(timestamp ":" method ":" random ":" uri ":" realm) + Hex(timestamp)
 *
 * @param nonce_time The amount of time in seconds for a nonce to be invalid
 * @param method HTTP method
 * @param rnd A pointer to a character array for the random seed
 * @param rnd_size The size of the random seed array @a rnd
 * @param uri HTTP URI (in MHD, without the arguments ("?k=v")
 * @param realm A string of characters that describes the realm of auth.
 * @param realm_len the length of the @a realm.
 * @param da digest algorithm to use
 * @param[out] nonce A pointer to a character array for the nonce to put in,
 *        must provide NONCE_STD_LEN(da->digest_size)+1 bytes
 */
static void
calculate_nonce (uint64_t nonce_time,
                 const char *method,
                 const char *rnd,
                 size_t rnd_size,
                 const char *uri,
                 size_t uri_len,
                 struct MHD_HTTP_Req_Header *first_header,
                 const char *realm,
                 size_t realm_len,
                 struct DigestAlgorithm *da,
                 char *nonce)
{
  uint8_t timestamp[TIMESTAMP_BIN_SIZE];
  struct MHD_HTTP_Req_Header *h;

  digest_init (da);
  /* If the nonce_time is milliseconds, then the same 48 bit value will repeat
   * every 8 925 years, which is more than enough to mitigate a replay attack */
#if TIMESTAMP_BIN_SIZE != 6
#error The code needs to be updated here
#endif
  timestamp[0] = (uint8_t) (nonce_time >> (8 * (TIMESTAMP_BIN_SIZE - 1 - 0)));
  timestamp[1] = (uint8_t) (nonce_time >> (8 * (TIMESTAMP_BIN_SIZE - 1 - 1)));
  timestamp[2] = (uint8_t) (nonce_time >> (8 * (TIMESTAMP_BIN_SIZE - 1 - 2)));
  timestamp[3] = (uint8_t) (nonce_time >> (8 * (TIMESTAMP_BIN_SIZE - 1 - 3)));
  timestamp[4] = (uint8_t) (nonce_time >> (8 * (TIMESTAMP_BIN_SIZE - 1 - 4)));
  timestamp[5] = (uint8_t) (nonce_time >> (8 * (TIMESTAMP_BIN_SIZE - 1 - 5)));
  digest_update (da,
                 timestamp,
                 sizeof (timestamp));
  digest_update_with_colon (da);
  digest_update_str (da, method);
  digest_update_with_colon (da);
  if (rnd_size > 0)
    digest_update (da,
                   rnd,
                   rnd_size);
  digest_update_with_colon (da);
  digest_update (da,
                 uri,
                 uri_len);
  for (h = first_header; NULL != h; h = h->next)
  {
    if (MHD_GET_ARGUMENT_KIND != h->kind)
      continue;
    digest_update (da, "\0", 2);
    if (0 != h->header_size)
      digest_update (da, h->header, h->header_size);
    digest_update (da, "", 1);
    if (0 != h->value_size)
      digest_update (da, h->value, h->value_size);
  }
  digest_update_with_colon (da);
  digest_update (da,
                 realm,
                 realm_len);
  if (1)
  {
    const unsigned int digest_size = digest_get_size (da);
    uint8_t hash[VLA_ARRAY_LEN_DIGEST (digest_size)];
    digest_calc_hash (da, hash);
    MHD_bin_to_hex (hash,
                    digest_size,
                    nonce);
  }
  MHD_bin_to_hex (timestamp,
                  sizeof (timestamp),
                  nonce + digest_get_size (da) * 2);
}


/**
 * Check whether it is possible to use slot in nonce-nc map array.
 *
 * Should be called with mutex held to avoid external modification of
 * the slot data.
 *
 * @param nn the pointer to the nonce-nc slot
 * @param now the current time
 * @param new_nonce the new nonce supposed to be stored in this slot,
 *                  zero-terminated
 * @param new_nonce_len the length of the @a new_nonce in chars, not including
 *                      the terminating zero.
 * @return true if the slot can be used to store the new nonce,
 *         false otherwise.
 */
static bool
is_slot_available (const struct MHD_NonceNc *const nn,
                   const uint64_t now,
                   const char *const new_nonce,
                   size_t new_nonce_len)
{
  uint64_t timestamp;
  bool timestamp_valid;
  mhd_assert (new_nonce_len <= NONCE_STD_LEN (MAX_DIGEST));
  mhd_assert (NONCE_STD_LEN (MAX_DIGEST) <= MAX_DIGEST_NONCE_LENGTH);
  if (0 == nn->nonce[0])
    return true; /* The slot is empty */

  if ((0 == memcmp (nn->nonce, new_nonce, new_nonce_len)) &&
      (0 == nn->nonce[new_nonce_len]))
  {
    /* The slot has the same nonce already, the same nonce was already generated
     * and used, this slot cannot be used with the same nonce as it would
     * just reset received 'nc' values. */
    return false;
  }

  if (0 != nn->nc)
    return true; /* Client already used the nonce in this slot at least
                    one time, re-use the slot */

  /* The nonce must be zero-terminated */
  mhd_assert (0 == nn->nonce[sizeof(nn->nonce) - 1]);
  if (0 != nn->nonce[sizeof(nn->nonce) - 1])
    return true; /* Wrong nonce format in the slot */

  timestamp_valid = get_nonce_timestamp (nn->nonce, 0, &timestamp);
  mhd_assert (timestamp_valid);
  if (! timestamp_valid)
    return true; /* Invalid timestamp in nonce-nc, should not be possible */

  if ((REUSE_TIMEOUT * 1000) < TRIM_TO_TIMESTAMP (now - timestamp))
    return true;

  return false;
}


/**
 * Calculate the server nonce so that it mitigates replay attacks and add
 * the new nonce to the nonce-nc map array.
 *
 * @param connection the MHD connection structure
 * @param timestamp the current timestamp
 * @param realm the string of characters that describes the realm of auth
 * @param realm_len the length of the @a realm
 * @param da the digest algorithm to use
 * @param[out] nonce the pointer to a character array for the nonce to put in,
 *        must provide NONCE_STD_LEN(da->digest_size)+1 bytes
 * @return true if the new nonce has been added to the nonce-nc map array,
 *         false otherwise.
 */
static bool
calculate_add_nonce (struct MHD_Connection *const connection,
                     uint64_t timestamp,
                     const char *realm,
                     size_t realm_len,
                     struct DigestAlgorithm *da,
                     char *nonce)
{
  struct MHD_Daemon *const daemon = MHD_get_master (connection->daemon);
  struct MHD_NonceNc *nn;
  const size_t nonce_size = NONCE_STD_LEN (digest_get_size (da));
  bool ret;

  mhd_assert (MAX_DIGEST_NONCE_LENGTH >= nonce_size);
  mhd_assert (0 != nonce_size);

  calculate_nonce (timestamp,
                   connection->method,
                   daemon->digest_auth_random,
                   daemon->digest_auth_rand_size,
                   connection->url,
                   connection->url_len,
                   connection->headers_received,
                   realm,
                   realm_len,
                   da,
                   nonce);

  if (0 == daemon->nonce_nc_size)
    return false;

  /* Sanity check for values */
  mhd_assert (MAX_DIGEST_NONCE_LENGTH == NONCE_STD_LEN (MAX_DIGEST));

  nn = daemon->nnc + get_nonce_nc_idx (daemon->nonce_nc_size,
                                       nonce,
                                       nonce_size);

  MHD_mutex_lock_chk_ (&daemon->nnc_lock);
  if (is_slot_available (nn, timestamp, nonce, nonce_size))
  {
    memcpy (nn->nonce,
            nonce,
            nonce_size);
    nn->nonce[nonce_size] = 0;  /* With terminating zero */
    nn->nc = 0;
    nn->nmask = 0;
    ret = true;
  }
  else
    ret = false;
  MHD_mutex_unlock_chk_ (&daemon->nnc_lock);

  return ret;
}


/**
 * Calculate the server nonce so that it mitigates replay attacks and add
 * the new nonce to the nonce-nc map array.
 *
 * @param connection the MHD connection structure
 * @param realm A string of characters that describes the realm of auth.
 * @param da digest algorithm to use
 * @param[out] nonce A pointer to a character array for the nonce to put in,
 *        must provide NONCE_STD_LEN(da->digest_size)+1 bytes
 */
static bool
calculate_add_nonce_with_retry (struct MHD_Connection *const connection,
                                const char *realm,
                                struct DigestAlgorithm *da,
                                char *nonce)
{
  const uint64_t timestamp1 = MHD_monotonic_msec_counter ();
  const size_t realm_len = strlen (realm);

  if (! calculate_add_nonce (connection, timestamp1, realm, realm_len, da,
                             nonce))
  {
    /* Either:
     * 1. The same nonce was already generated. If it will be used then one
     * of the clients will fail (as no initial 'nc' value could be given to
     * the client, the second client which will use 'nc=00000001' will fail).
     * 2. Another nonce uses the same slot, and this nonce never has been
     * used by the client and this nonce is still fresh enough.
     */
    const size_t digest_size = digest_get_size (da);
    char nonce2[NONCE_STD_LEN (VLA_ARRAY_LEN_DIGEST (digest_size)) + 1];
    uint64_t timestamp2;
    if (0 == MHD_get_master (connection->daemon)->nonce_nc_size)
      return false; /* No need to re-try */

    timestamp2 = MHD_monotonic_msec_counter ();
    if (timestamp1 == timestamp2)
    {
      /* The timestamps are equal, need to generate some arbitrary
       * difference for nonce. */
      uint64_t base1;
      uint32_t base2;
      uint16_t base3;
      uint8_t base4;
      base1 = (uint64_t) (uintptr_t) nonce2;
      base2 = ((uint32_t) (base1 >> 32)) ^ ((uint32_t) base1);
      base2 = _MHD_ROTL32 (base2, 4);
      base3 = ((uint16_t) (base2 >> 16)) ^ ((uint16_t) base2);
      base4 = ((uint8_t) (base3 >> 8)) ^ ((uint8_t) base3);
      base1 = (uint64_t) (uintptr_t) connection;
      base2 = ((uint32_t) (base1 >> 32)) ^ ((uint32_t) base1);
      base2 = _MHD_ROTL32 (base2, (((base4 >> 4) ^ base4) % 32));
      base3 = ((uint16_t) (base2 >> 16)) ^ ((uint16_t) base2);
      base4 = ((uint8_t) (base3 >> 8)) ^ ((uint8_t) base3);
      /* Use up to 127 ms difference */
      timestamp2 -= (base4 & DAUTH_JUMPBACK_MAX);
      if (timestamp1 == timestamp2)
        timestamp2 -= 2; /* Fallback value */
    }
    if (! calculate_add_nonce (connection, timestamp2, realm, realm_len, da,
                               nonce2))
    {
      /* No free slot has been found. Re-tries are expensive, just use
       * the generated nonce. As it is not stored in nonce-nc map array,
       * the next request of the client will be recognized as valid, but 'stale'
       * so client should re-try automatically. */
      return false;
    }
    memcpy (nonce, nonce2, NONCE_STD_LEN (digest_size));
    mhd_assert (0 == nonce[NONCE_STD_LEN (digest_size)]);
  }
  return true;
}


struct test_header_param
{
  struct MHD_Connection *connection;
  size_t num_headers;
};

/**
 * Test if the given key-value pair is in the headers for the
 * given connection.
 *
 * @param cls the test context
 * @param key the key
 * @param key_size number of bytes in @a key
 * @param value the value, can be NULL
 * @param value_size number of bytes in @a value
 * @param kind type of the header
 * @return #MHD_YES if the key-value pair is in the headers,
 *         #MHD_NO if not
 */
static enum MHD_Result
test_header (void *cls,
             const char *key,
             size_t key_size,
             const char *value,
             size_t value_size,
             enum MHD_ValueKind kind)
{
  struct test_header_param *const param = (struct test_header_param *) cls;
  struct MHD_Connection *connection = param->connection;
  struct MHD_HTTP_Req_Header *pos;
  size_t i;

  param->num_headers++;
  i = 0;
  for (pos = connection->headers_received; NULL != pos; pos = pos->next)
  {
    if (kind != pos->kind)
      continue;
    if (++i == param->num_headers)
    {
      if (key_size != pos->header_size)
        return MHD_NO;
      if (value_size != pos->value_size)
        return MHD_NO;
      if (0 != key_size)
      {
        mhd_assert (NULL != key);
        mhd_assert (NULL != pos->header);
        if (0 != memcmp (key,
                         pos->header,
                         key_size))
          return MHD_NO;
      }
      if (0 != value_size)
      {
        mhd_assert (NULL != value);
        mhd_assert (NULL != pos->value);
        if (0 != memcmp (value,
                         pos->value,
                         value_size))
          return MHD_NO;
      }
      return MHD_YES;
    }
  }
  return MHD_NO;
}


/**
 * Check that the arguments given by the client as part
 * of the authentication header match the arguments we
 * got as part of the HTTP request URI.
 *
 * @param connection connections with headers to compare against
 * @param args the copy of argument URI string (after "?" in URI), will be
 *             modified by this function
 * @return boolean true if the arguments match,
 *         boolean false if not
 */
static bool
check_argument_match (struct MHD_Connection *connection,
                      char *args)
{
  struct MHD_HTTP_Req_Header *pos;
  enum MHD_Result ret;
  struct test_header_param param;

  param.connection = connection;
  param.num_headers = 0;
  ret = MHD_parse_arguments_ (connection,
                              MHD_GET_ARGUMENT_KIND,
                              args,
                              &test_header,
                              &param);
  if (MHD_NO == ret)
  {
    return false;
  }
  /* also check that the number of headers matches */
  for (pos = connection->headers_received; NULL != pos; pos = pos->next)
  {
    if (MHD_GET_ARGUMENT_KIND != pos->kind)
      continue;
    param.num_headers--;
  }
  if (0 != param.num_headers)
  {
    /* argument count mismatch */
    return false;
  }
  return true;
}


/**
 * Check that the URI provided by the client as part
 * of the authentication header match the real HTTP request URI.
 *
 * @param connection connections with headers to compare against
 * @param uri the copy of URI in the authentication header, should point to
 *            modifiable buffer at least @a uri_len + 1 characters long,
 *            will be modified by this function, not valid upon return
 * @param uri_len the length of the @a uri string in characters
 * @return boolean true if the URIs match,
 *         boolean false if not
 */
static bool
check_uri_match (struct MHD_Connection *connection, char *uri, size_t uri_len)
{
  char *qmark;
  char *args;
  struct MHD_Daemon *const daemon = connection->daemon;

  uri[uri_len] = 0;
  qmark = memchr (uri,
                  '?',
                  uri_len);
  if (NULL != qmark)
    *qmark = '\0';

  /* Need to unescape URI before comparing with connection->url */
  uri_len = daemon->unescape_callback (daemon->unescape_callback_cls,
                                       connection,
                                       uri);
  if ((uri_len != connection->url_len) ||
      (0 != memcmp (uri, connection->url, uri_len)))
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (daemon,
              _ ("Authentication failed, URI does not match.\n"));
#endif
    return false;
  }

  args = (NULL != qmark) ? (qmark + 1) : uri + uri_len;

  if (! check_argument_match (connection,
                              args) )
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (daemon,
              _ ("Authentication failed, arguments do not match.\n"));
#endif
    return false;
  }
  return true;
}


/**
 * The size of the unquoting buffer in stack
 */
#define _MHD_STATIC_UNQ_BUFFER_SIZE 128


/**
 * Get the pointer to buffer with required size
 * @param tmp1 the first buffer with fixed size
 * @param ptmp2 the pointer to pointer to malloc'ed buffer
 * @param ptmp2_size the pointer to the size of the buffer pointed by @a ptmp2
 * @param required_size the required size in buffer
 * @return the pointer to the buffer or NULL if failed to allocate buffer with
 *         requested size
 */
static char *
get_buffer_for_size (char tmp1[_MHD_STATIC_UNQ_BUFFER_SIZE],
                     char **ptmp2,
                     size_t *ptmp2_size,
                     size_t required_size)
{
  mhd_assert ((0 == *ptmp2_size) || (NULL != *ptmp2));
  mhd_assert ((NULL != *ptmp2) || (0 == *ptmp2_size));
  mhd_assert ((0 == *ptmp2_size) || \
              (_MHD_STATIC_UNQ_BUFFER_SIZE < *ptmp2_size));

  if (required_size <= _MHD_STATIC_UNQ_BUFFER_SIZE)
    return tmp1;

  if (required_size <= *ptmp2_size)
    return *ptmp2;

  if (required_size > _MHD_AUTH_DIGEST_MAX_PARAM_SIZE)
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
enum _MHD_GetUnqResult
{
  _MHD_UNQ_OK = 0,         /**< Got unquoted string */
  _MHD_UNQ_TOO_LARGE = -7, /**< The string is too large to unquote */
  _MHD_UNQ_OUT_OF_MEM = 3  /**< Out of memory error */
};

/**
 * Get Digest authorisation parameter as unquoted string.
 * @param param the parameter to process
 * @param tmp1 the small buffer in stack
 * @param ptmp2 the pointer to pointer to malloc'ed buffer
 * @param ptmp2_size the pointer to the size of the buffer pointed by @a ptmp2
 * @param[out] unquoted the pointer to store the result, NOT zero terminated
 * @return enum code indicating result of the process
 */
static enum _MHD_GetUnqResult
get_unquoted_param (const struct MHD_RqDAuthParam *param,
                    char tmp1[_MHD_STATIC_UNQ_BUFFER_SIZE],
                    char **ptmp2,
                    size_t *ptmp2_size,
                    struct _MHD_str_w_len *unquoted)
{
  char *str;
  size_t len;
  mhd_assert (NULL != param->value.str);
  mhd_assert (0 != param->value.len);

  if (! param->quoted)
  {
    unquoted->str = param->value.str;
    unquoted->len = param->value.len;
    return _MHD_UNQ_OK;
  }
  /* The value is present and is quoted, needs to be copied and unquoted */
  str = get_buffer_for_size (tmp1, ptmp2, ptmp2_size, param->value.len);
  if (NULL == str)
    return (param->value.len > _MHD_AUTH_DIGEST_MAX_PARAM_SIZE) ?
           _MHD_UNQ_TOO_LARGE : _MHD_UNQ_OUT_OF_MEM;

  len = MHD_str_unquote (param->value.str, param->value.len, str);
  unquoted->str = str;
  unquoted->len = len;
  mhd_assert (0 != unquoted->len);
  mhd_assert (unquoted->len < param->value.len);
  return _MHD_UNQ_OK;
}


/**
 * Get copy of Digest authorisation parameter as unquoted string.
 * @param param the parameter to process
 * @param tmp1 the small buffer in stack
 * @param ptmp2 the pointer to pointer to malloc'ed buffer
 * @param ptmp2_size the pointer to the size of the buffer pointed by @a ptmp2
 * @param[out] unquoted the pointer to store the result, NOT zero terminated,
 *                      but with enough space to zero-terminate
 * @return enum code indicating result of the process
 */
static enum _MHD_GetUnqResult
get_unquoted_param_copy (const struct MHD_RqDAuthParam *param,
                         char tmp1[_MHD_STATIC_UNQ_BUFFER_SIZE],
                         char **ptmp2,
                         size_t *ptmp2_size,
                         struct _MHD_mstr_w_len *unquoted)
{
  mhd_assert (NULL != param->value.str);
  mhd_assert (0 != param->value.len);

  /* The value is present and is quoted, needs to be copied and unquoted */
  /* Allocate buffer with one more additional byte for zero-termination */
  unquoted->str =
    get_buffer_for_size (tmp1, ptmp2, ptmp2_size, param->value.len + 1);

  if (NULL == unquoted->str)
    return (param->value.len + 1 > _MHD_AUTH_DIGEST_MAX_PARAM_SIZE) ?
           _MHD_UNQ_TOO_LARGE : _MHD_UNQ_OUT_OF_MEM;

  if (! param->quoted)
  {
    memcpy (unquoted->str, param->value.str, param->value.len);
    unquoted->len = param->value.len;
    return _MHD_UNQ_OK;
  }

  unquoted->len =
    MHD_str_unquote (param->value.str, param->value.len, unquoted->str);
  mhd_assert (0 != unquoted->len);
  mhd_assert (unquoted->len < param->value.len);
  return _MHD_UNQ_OK;
}


/**
 * Check whether Digest Auth request parameter is equal to given string
 * @param param the parameter to check
 * @param str the string to compare with, does not need to be zero-terminated
 * @param str_len the length of the @a str
 * @return true is parameter is equal to the given string,
 *         false otherwise
 */
_MHD_static_inline bool
is_param_equal (const struct MHD_RqDAuthParam *param,
                const char *const str,
                const size_t str_len)
{
  mhd_assert (NULL != param->value.str);
  mhd_assert (0 != param->value.len);
  if (param->quoted)
    return MHD_str_equal_quoted_bin_n (param->value.str, param->value.len,
                                       str, str_len);
  return (str_len == param->value.len) &&
         (0 == memcmp (str, param->value.str, str_len));

}


/**
 * Check whether Digest Auth request parameter is caseless equal to given string
 * @param param the parameter to check
 * @param str the string to compare with, does not need to be zero-terminated
 * @param str_len the length of the @a str
 * @return true is parameter is caseless equal to the given string,
 *         false otherwise
 */
_MHD_static_inline bool
is_param_equal_caseless (const struct MHD_RqDAuthParam *param,
                         const char *const str,
                         const size_t str_len)
{
  mhd_assert (NULL != param->value.str);
  mhd_assert (0 != param->value.len);
  if (param->quoted)
    return MHD_str_equal_quoted_bin_n (param->value.str, param->value.len,
                                       str, str_len);
  return (str_len == param->value.len) &&
         (0 == memcmp (str, param->value.str, str_len));

}


/**
 * Authenticates the authorization header sent by the client
 *
 * @param connection The MHD connection structure
 * @param[in,out] da digest algorithm to use for checking (written to as
 *         part of the calculations, but the values left in the struct
 *         are not actually expected to be useful for the caller)
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param password The password used in the authentication
 * @param digest An optional binary hash
 *     of the precalculated hash value "username:realm:password"
 *     (must contain "da->digest_size" bytes or be NULL)
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @param[out] pbuf the pointer to pointer to internally malloc'ed buffer,
 *                  to be free if not NULL upon return
 * @return #MHD_DAUTH_OK if authenticated,
 *         error code otherwise.
 * @ingroup authentication
 */
static enum MHD_DigestAuthResult
digest_auth_check_all_inner (struct MHD_Connection *connection,
                             struct DigestAlgorithm *da,
                             const char *realm,
                             const char *username,
                             const char *password,
                             const uint8_t *digest,
                             unsigned int nonce_timeout,
                             char **pbuf)
{
  struct MHD_Daemon *daemon = MHD_get_master (connection->daemon);
  const unsigned int digest_size = digest_get_size (da);
  uint8_t hash1_bin[VLA_ARRAY_LEN_DIGEST (digest_size)];
  uint8_t hash2_bin[VLA_ARRAY_LEN_DIGEST (digest_size)];
#if 0
  const char *hentity = NULL; /* "auth-int" is not supported */
#endif
  uint64_t nonce_time;
  uint64_t t;
  uint64_t nci;
  const struct MHD_RqDAuth *params;
  /**
   * Temporal buffer in stack for unquoting and other needs
   */
  char tmp1[_MHD_STATIC_UNQ_BUFFER_SIZE];
  char **const ptmp2 = pbuf;     /**< Temporal malloc'ed buffer for unquoting */
  size_t tmp2_size; /**< The size of @a tmp2 buffer */
  struct _MHD_str_w_len unquoted;
  struct _MHD_mstr_w_len unq_copy;
  enum _MHD_GetUnqResult unq_res;
  size_t username_len;
  size_t realm_len;

  tmp2_size = 0;

  params = get_rq_dauth_params (connection);
  if (NULL == params)
    return MHD_DAUTH_WRONG_HEADER;

  /* ** A quick check for presence of all required parameters ** */
  if (NULL == params->username.value.str)
    return MHD_DAUTH_WRONG_HEADER;

  if (NULL == params->realm.value.str)
    return MHD_DAUTH_WRONG_HEADER;

  if (NULL == params->nonce.value.str)
    return MHD_DAUTH_WRONG_HEADER;
  else if (0 == params->nonce.value.len)
    return MHD_DAUTH_NONCE_WRONG;
  else if (NONCE_STD_LEN (digest_size) * 2 < params->nonce.value.len)
    return MHD_DAUTH_NONCE_WRONG;

  if (NULL == params->nc.value.str)
    return MHD_DAUTH_WRONG_HEADER;
  else if (0 == params->nc.value.len)
    return MHD_DAUTH_WRONG_HEADER;
  else if (4 * 8 < params->nc.value.len) /* Four times more than needed */
    return MHD_DAUTH_WRONG_HEADER;

  if (NULL == params->cnonce.value.str)
    return MHD_DAUTH_WRONG_HEADER;
  else if (0 == params->cnonce.value.len)
    return MHD_DAUTH_WRONG_HEADER;
  else if (_MHD_AUTH_DIGEST_MAX_PARAM_SIZE < params->cnonce.value.len)
    return MHD_DAUTH_TOO_LARGE;

  if (NULL == params->qop.value.str)
    return MHD_DAUTH_WRONG_HEADER;
  else if (0 == params->qop.value.len)
    return MHD_DAUTH_WRONG_QOP;
  else if (MHD_STATICSTR_LEN_ ("auth-int") * 2 < params->qop.value.len)
    return MHD_DAUTH_WRONG_QOP;

  if (NULL == params->response.value.str)
    return MHD_DAUTH_WRONG_HEADER;
  else if (0 == params->response.value.len)
    return MHD_DAUTH_RESPONSE_WRONG;
  else if (digest_size * 4 < params->response.value.len)
    return MHD_DAUTH_RESPONSE_WRONG;

  if (NULL == params->uri.value.str)
    return MHD_DAUTH_WRONG_HEADER;
  else if (0 == params->uri.value.len)
    return MHD_DAUTH_WRONG_URI;
  else if (_MHD_AUTH_DIGEST_MAX_PARAM_SIZE < params->uri.value.len)
    return MHD_DAUTH_TOO_LARGE;

  /* ** Check simple parameters match ** */

  /* Check 'username' */
  username_len = strlen (username);
  if (! is_param_equal (&params->username, username, username_len))
    return MHD_DAUTH_WRONG_USERNAME;
  /* 'username' valid */

  /* Check 'realm' */
  realm_len = strlen (realm);
  if (! is_param_equal (&params->realm, realm, realm_len))
    return MHD_DAUTH_WRONG_REALM;
  /* 'realm' valid */

  /* Check 'qop' */
  /* TODO: support MHD_DIGEST_AUTH_QOP_NONE and MHD_DIGEST_AUTH_QOP_AUTH_INT */
  if (MHD_DIGEST_AUTH_QOP_AUTH != get_rq_qop (params))
    return MHD_DAUTH_WRONG_QOP;
  /* 'qop' valid */

  /* Check 'algorithm' */
  if (1)
  {
    const enum MHD_DigestAuthAlgo3 r_algo = get_rq_algo (params);
    const enum MHD_DigestBaseAlgo p_algo = da->algo;
    if ( (! ((MHD_DIGEST_AUTH_ALGO3_MD5 == r_algo) &&
             (MHD_DIGEST_BASE_ALGO_MD5 == p_algo))) &&
         (! ((MHD_DIGEST_AUTH_ALGO3_SHA256 == r_algo) &&
             (MHD_DIGEST_BASE_ALGO_SHA256 == p_algo))) )
      return MHD_DAUTH_WRONG_ALGO;
  }
  /* 'algorithm' valid */

  /* ** Do basic nonce and nonce-counter checks (size, timestamp) ** */
  /* Get 'nc' digital value */
  unq_res = get_unquoted_param (&params->nc, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (_MHD_UNQ_OK != unq_res)
    return MHD_DAUTH_ERROR;

  if (unquoted.len != MHD_strx_to_uint64_n_ (unquoted.str,
                                             unquoted.len,
                                             &nci))
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (daemon,
              _ ("Authentication failed, invalid nc format.\n"));
#endif
    return MHD_DAUTH_WRONG_HEADER;   /* invalid nonce format */
  }
  if (0 == nci)
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (daemon,
              _ ("Authentication failed, invalid 'nc' value.\n"));
#endif
    return MHD_DAUTH_WRONG_HEADER;   /* invalid nc value */
  }
  /* Got 'nc' digital value */
  /* Get 'nonce' with basic checks */
  unq_res = get_unquoted_param (&params->nonce, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (_MHD_UNQ_OK != unq_res)
    return MHD_DAUTH_ERROR;

  if ((NONCE_STD_LEN (digest_size) != unquoted.len) ||
      (! get_nonce_timestamp (unquoted.str, unquoted.len, &nonce_time)))
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (daemon,
              _ ("Authentication failed, invalid nonce format.\n"));
#endif
    return MHD_DAUTH_NONCE_WRONG;
  }
  t = MHD_monotonic_msec_counter ();
  /*
   * First level vetting for the nonce validity: if the timestamp
   * attached to the nonce exceeds `nonce_timeout', then the nonce is
   * invalid.
   */
  if (TRIM_TO_TIMESTAMP (t - nonce_time) > (nonce_timeout * 1000))
    return MHD_DAUTH_NONCE_STALE; /* too old */
  if (1)
  {
    enum MHD_CheckNonceNC_ nonce_nc_check;
    /*
     * Checking if that combination of nonce and nc is sound
     * and not a replay attack attempt. Refuse if nonce was not
     * generated previously.
     */
    nonce_nc_check = check_nonce_nc (connection,
                                     unquoted.str,
                                     NONCE_STD_LEN (digest_size),
                                     nonce_time,
                                     nci);
    if (MHD_CHECK_NONCENC_STALE == nonce_nc_check)
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _ ("Stale nonce received. If this happens a lot, you should "
                   "probably increase the size of the nonce array.\n"));
#endif
      return MHD_DAUTH_NONCE_STALE;
    }
    else if (MHD_CHECK_NONCENC_WRONG == nonce_nc_check)
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _ ("Received nonce that technically valid, but was not "
                   "generated by MHD. This may indicate an attack attempt.\n"));
#endif
      return MHD_DAUTH_NONCE_WRONG;
    }
    mhd_assert (MHD_CHECK_NONCENC_OK == nonce_nc_check);
  }
  /* The nonce was generated by MHD, is not stale and nonce-nc combination was
     not used before */

  /* ** Build H(A2) and check URI match in the header and in the request ** */
  /* Get 'uri' */
  digest_init (da);
  digest_update_str (da, connection->method);
  digest_update_with_colon (da);
#if 0
  /* TODO: add support for "auth-int" */
  digest_update_str (da, hentity);
  digest_update_with_colon (da);
#endif
  unq_res = get_unquoted_param_copy (&params->uri, tmp1, ptmp2, &tmp2_size,
                                     &unq_copy);
  if (_MHD_UNQ_OK != unq_res)
    return MHD_DAUTH_ERROR;

  digest_update (da, unq_copy.str, unq_copy.len);
  /* The next check will modify copied URI string */
  if (! check_uri_match (connection, unq_copy.str, unq_copy.len))
    return MHD_DAUTH_WRONG_URI;
  digest_calc_hash (da, hash2_bin);
  /* Got H(A2) */

  /* ** Build H(A1) ** */
  if (NULL == digest)
  {
    digest_init (da);
    digest_update (da, (const uint8_t *) username, username_len);
    digest_update_with_colon (da);
    digest_update (da, (const uint8_t *) realm, realm_len);
    digest_update_with_colon (da);
    digest_update_str (da, password);
    digest_calc_hash (da, hash1_bin);
  }
  /* TODO: support '-sess' versions */
  /* Got H(A1) */

  /* **  Check 'response' ** */
  digest_init (da);
  /* Update digest with H(A1) */
  mhd_assert (sizeof (tmp1) >= (digest_size * 2 + 1));
  if (NULL == digest)
    MHD_bin_to_hex (hash1_bin, digest_size, tmp1);
  else
    MHD_bin_to_hex (digest, digest_size, tmp1);
  digest_update (da, (const uint8_t *) tmp1, digest_size * 2);

  /* H(A1) is not needed anymore, reuse the buffer.
   * Use hash1_bin for the client's 'response' decoded to binary form. */
  unq_res = get_unquoted_param (&params->response, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (_MHD_UNQ_OK != unq_res)
    return MHD_DAUTH_ERROR;
  if (digest_size != MHD_hex_to_bin (unquoted.str, unquoted.len, hash1_bin))
    return MHD_DAUTH_RESPONSE_WRONG;

  /* Update digest with ':' */
  digest_update_with_colon (da);
  /* Update digest with 'nonce' text value */
  unq_res = get_unquoted_param (&params->nonce, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (_MHD_UNQ_OK != unq_res)
    return MHD_DAUTH_ERROR;
  digest_update (da, (const uint8_t *) unquoted.str, unquoted.len);
  /* Update digest with ':' */
  digest_update_with_colon (da);
  /* Update digest with 'nc' text value */
  unq_res = get_unquoted_param (&params->nc, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (_MHD_UNQ_OK != unq_res)
    return MHD_DAUTH_ERROR;
  digest_update (da, (const uint8_t *) unquoted.str, unquoted.len);
  /* Update digest with ':' */
  digest_update_with_colon (da);
  /* Update digest with 'cnonce' value */
  unq_res = get_unquoted_param (&params->cnonce, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (_MHD_UNQ_OK != unq_res)
    return MHD_DAUTH_ERROR;
  digest_update (da, (const uint8_t *) unquoted.str, unquoted.len);
  /* Update digest with ':' */
  digest_update_with_colon (da);
  /* Update digest with 'qop' value */
  unq_res = get_unquoted_param (&params->qop, tmp1, ptmp2, &tmp2_size,
                                &unquoted);
  if (_MHD_UNQ_OK != unq_res)
    return MHD_DAUTH_ERROR;
  digest_update (da, (const uint8_t *) unquoted.str, unquoted.len);
  /* Update digest with ':' */
  digest_update_with_colon (da);
  /* Update digest with H(A2) */
  MHD_bin_to_hex (hash2_bin, digest_size, tmp1);
  digest_update (da, (const uint8_t *) tmp1, digest_size * 2);

  /* H(A2) is not needed anymore, reuse the buffer.
   * Use hash2_bin for the calculated response in binary form */
  digest_calc_hash (da, hash2_bin);

  if (0 != memcmp (hash1_bin, hash2_bin, digest_size))
    return MHD_DAUTH_RESPONSE_WRONG;

  mhd_assert (sizeof(tmp1) >= (NONCE_STD_LEN (digest_size) + 1));
  /* It was already checked that 'nonce' (including timestamp) was generated
     by MHD. The next check is mostly an overcaution. */
  calculate_nonce (nonce_time,
                   connection->method,
                   daemon->digest_auth_random,
                   daemon->digest_auth_rand_size,
                   connection->url,
                   connection->url_len,
                   connection->headers_received,
                   realm,
                   realm_len,
                   da,
                   tmp1);

  if (! is_param_equal (&params->nonce, tmp1,
                        NONCE_STD_LEN (digest_size)))
    return MHD_DAUTH_NONCE_WRONG;
  /* The 'nonce' was generated in the same conditions */

  return MHD_DAUTH_OK;
}


/**
 * Authenticates the authorization header sent by the client
 *
 * @param connection The MHD connection structure
 * @param[in,out] da digest algorithm to use for checking (written to as
 *         part of the calculations, but the values left in the struct
 *         are not actually expected to be useful for the caller)
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param password The password used in the authentication
 * @param digest An optional binary hash
 *     of the precalculated hash value "username:realm:password"
 *     (must contain "da->digest_size" bytes or be NULL)
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @return #MHD_DAUTH_OK if authenticated,
 *         error code otherwise.
 * @ingroup authentication
 */
static enum MHD_DigestAuthResult
digest_auth_check_all (struct MHD_Connection *connection,
                       struct DigestAlgorithm *da,
                       const char *realm,
                       const char *username,
                       const char *password,
                       const uint8_t *digest,
                       unsigned int nonce_timeout)
{
  enum MHD_DigestAuthResult res;
  char *buf;

  buf = NULL;
  res = digest_auth_check_all_inner (connection, da, realm, username, password,
                                     digest, nonce_timeout, &buf);
  if (NULL != buf)
    free (buf);

  return res;
}


/**
 * Authenticates the authorization header sent by the client.
 * Uses #MHD_DIGEST_ALG_MD5 (for now, for backwards-compatibility).
 * Note that this MAY change to #MHD_DIGEST_ALG_AUTO in the future.
 * If you want to be sure you get MD5, use #MHD_digest_auth_check2()
 * and specify MD5 explicitly.
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param password The password used in the authentication
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
 * @deprecated use MHD_digest_auth_check3()
 * @ingroup authentication
 */
_MHD_EXTERN int
MHD_digest_auth_check (struct MHD_Connection *connection,
                       const char *realm,
                       const char *username,
                       const char *password,
                       unsigned int nonce_timeout)
{
  return MHD_digest_auth_check2 (connection,
                                 realm,
                                 username,
                                 password,
                                 nonce_timeout,
                                 MHD_DIGEST_ALG_MD5);
}


/**
 * Authenticates the authorization header sent by the client.
 *
 * @param connection the MHD connection structure
 * @param realm the realm to be used for authorization of the client
 * @param username the username needs to be authenticated
 * @param password the password used in the authentication
 * @param nonce_timeout the nonce validity duration in seconds
 * @param algo the digest algorithms allowed for verification
 * @return #MHD_DAUTH_OK if authenticated,
 *         the error code otherwise
 * @note Available since #MHD_VERSION 0x00097513
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_DigestAuthResult
MHD_digest_auth_check3 (struct MHD_Connection *connection,
                        const char *realm,
                        const char *username,
                        const char *password,
                        unsigned int nonce_timeout,
                        enum MHD_DigestAuthAlgorithm algo)
{
  struct DigestAlgorithm da;

  mhd_assert (NULL != password);

  if ((MHD_DIGEST_ALG_MD5 == algo) || (MHD_DIGEST_ALG_AUTO == algo))
  {
    if (! digest_setup (&da, MHD_DIGEST_BASE_ALGO_MD5))
      MHD_PANIC (_ ("Error initialising hash algorithm.\n"));
  }
  else if (MHD_DIGEST_ALG_SHA256 == algo)
  {
    if (! digest_setup (&da, MHD_DIGEST_BASE_ALGO_SHA256))
      MHD_PANIC (_ ("Error initialising hash algorithm.\n"));
  }
  else
    MHD_PANIC (_ ("Wrong algo value.\n")); /* API violation! */

  return digest_auth_check_all (connection,
                                &da,
                                realm,
                                username,
                                password,
                                NULL,
                                nonce_timeout);
}


/**
 * Authenticates the authorization header sent by the client.
 *
 * @param connection the MHD connection structure
 * @param realm the realm to be used for authorization of the client
 * @param username the username needs to be authenticated
 * @param digest the pointer to the binary digest for the precalculated hash
 *        value "username:realm:password" with specified @a algo
 * @param digest_size the number of bytes in @a digest (the size must match
 *        @a algo!)
 * @param nonce_timeout the nonce validity duration in seconds
 * @param algo digest algorithms allowed for verification
 * @return #MHD_DAUTH_OK if authenticated,
 *         the error code otherwise
 * @note Available since #MHD_VERSION 0x00097513
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_DigestAuthResult
MHD_digest_auth_check_digest3 (struct MHD_Connection *connection,
                               const char *realm,
                               const char *username,
                               const uint8_t *digest,
                               size_t digest_size,
                               unsigned int nonce_timeout,
                               enum MHD_DigestAuthAlgorithm algo)
{
  struct DigestAlgorithm da;

  mhd_assert (NULL != digest);
  if ((MHD_DIGEST_ALG_MD5 == algo) || (MHD_DIGEST_ALG_AUTO == algo))
  {
    if (! digest_setup (&da, MHD_DIGEST_BASE_ALGO_MD5))
      MHD_PANIC (_ ("Error initialising hash algorithm.\n"));
  }
  else if (MHD_DIGEST_ALG_SHA256 == algo)
  {
    if (! digest_setup (&da, MHD_DIGEST_BASE_ALGO_SHA256))
      MHD_PANIC (_ ("Error initialising hash algorithm.\n"));
  }
  else
    MHD_PANIC (_ ("Wrong algo value.\n")); /* API violation! */

  if (digest_get_size (&da) != digest_size)
    MHD_PANIC (_ ("Digest size mismatch.\n")); /* API violation! */

  return digest_auth_check_all (connection,
                                &da,
                                realm,
                                username,
                                NULL,
                                digest,
                                nonce_timeout);
}


/**
 * Authenticates the authorization header sent by the client.
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param password The password used in the authentication
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @param algo digest algorithms allowed for verification
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
 * @note Available since #MHD_VERSION 0x00096200
 * @deprecated use MHD_digest_auth_check3()
 * @ingroup authentication
 */
_MHD_EXTERN int
MHD_digest_auth_check2 (struct MHD_Connection *connection,
                        const char *realm,
                        const char *username,
                        const char *password,
                        unsigned int nonce_timeout,
                        enum MHD_DigestAuthAlgorithm algo)
{
  enum MHD_DigestAuthResult res;
  res = MHD_digest_auth_check3 (connection,
                                realm,
                                username,
                                password,
                                nonce_timeout,
                                algo);
  if (MHD_DAUTH_OK == res)
    return MHD_YES;
  else if ((MHD_DAUTH_NONCE_STALE == res) || (MHD_DAUTH_NONCE_WRONG == res))
    return MHD_INVALID_NONCE;
  return MHD_NO;

}


/**
 * Authenticates the authorization header sent by the client.
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param digest An `unsigned char *' pointer to the binary MD5 sum
 *      for the precalculated hash value "username:realm:password"
 *      of @a digest_size bytes
 * @param digest_size number of bytes in @a digest (size must match @a algo!)
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @param algo digest algorithms allowed for verification
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
 * @note Available since #MHD_VERSION 0x00096200
 * @deprecated use MHD_digest_auth_check_digest3()
 * @ingroup authentication
 */
_MHD_EXTERN int
MHD_digest_auth_check_digest2 (struct MHD_Connection *connection,
                               const char *realm,
                               const char *username,
                               const uint8_t *digest,
                               size_t digest_size,
                               unsigned int nonce_timeout,
                               enum MHD_DigestAuthAlgorithm algo)
{
  enum MHD_DigestAuthResult res;

  res = MHD_digest_auth_check_digest3 (connection,
                                       realm,
                                       username,
                                       digest,
                                       digest_size,
                                       nonce_timeout,
                                       algo);
  if (MHD_DAUTH_OK == res)
    return MHD_YES;
  else if ((MHD_DAUTH_NONCE_STALE == res) || (MHD_DAUTH_NONCE_WRONG == res))
    return MHD_INVALID_NONCE;
  return MHD_NO;
}


/**
 * Authenticates the authorization header sent by the client
 * Uses #MHD_DIGEST_ALG_MD5 (required, as @a digest is of fixed
 * size).
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param digest An `unsigned char *' pointer to the binary hash
 *    for the precalculated hash value "username:realm:password";
 *    length must be #MHD_MD5_DIGEST_SIZE bytes
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
 * @note Available since #MHD_VERSION 0x00096000
 * @deprecated use #MHD_digest_auth_check_digest3()
 * @ingroup authentication
 */
_MHD_EXTERN int
MHD_digest_auth_check_digest (struct MHD_Connection *connection,
                              const char *realm,
                              const char *username,
                              const uint8_t digest[MHD_MD5_DIGEST_SIZE],
                              unsigned int nonce_timeout)
{
  return MHD_digest_auth_check_digest2 (connection,
                                        realm,
                                        username,
                                        digest,
                                        MHD_MD5_DIGEST_SIZE,
                                        nonce_timeout,
                                        MHD_DIGEST_ALG_MD5);
}


/**
 * Queues a response to request authentication from the client
 *
 * @param connection The MHD connection structure
 * @param realm the realm presented to the client
 * @param opaque string to user for opaque value
 * @param response reply to send; should contain the "access denied"
 *        body; note that this function will set the "WWW Authenticate"
 *        header and that the caller should not do this; the NULL is tolerated
 * @param signal_stale #MHD_YES if the nonce is stale to add
 *        'stale=true' to the authentication header
 * @param algo digest algorithm to use
 * @return #MHD_YES on success, #MHD_NO otherwise
 * @note Available since #MHD_VERSION 0x00096200
 * @ingroup authentication
 */
_MHD_EXTERN enum MHD_Result
MHD_queue_auth_fail_response2 (struct MHD_Connection *connection,
                               const char *realm,
                               const char *opaque,
                               struct MHD_Response *response,
                               int signal_stale,
                               enum MHD_DigestAuthAlgorithm algo)
{
  enum MHD_Result ret;
  int hlen;

  struct DigestAlgorithm da;

  if ((MHD_DIGEST_ALG_MD5 == algo) || (MHD_DIGEST_ALG_AUTO == algo))
  {
    if (! digest_setup (&da, MHD_DIGEST_BASE_ALGO_MD5))
      MHD_PANIC (_ ("Error initialising hash algorithm.\n"));
  }
  else if (MHD_DIGEST_ALG_SHA256 == algo)
  {
    if (! digest_setup (&da, MHD_DIGEST_BASE_ALGO_SHA256))
      MHD_PANIC (_ ("Error initialising hash algorithm.\n"));
  }
  else
    MHD_PANIC (_ ("Wrong algo value.\n")); /* API violation! */

  if (NULL == response)
    return MHD_NO;

  if (0 == MHD_get_master (connection->daemon)->nonce_nc_size)
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (connection->daemon,
              _ ("The nonce array size is zero.\n"));
#endif /* HAVE_MESSAGES */
    return MHD_NO;
  }

  if (1)
  {
    char nonce[NONCE_STD_LEN (VLA_ARRAY_LEN_DIGEST (digest_get_size (&da)))
               + 1];

    VLA_CHECK_LEN_DIGEST (digest_get_size (&da));
    if (! calculate_add_nonce_with_retry (connection, realm, &da, nonce))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                _ ("Could not register nonce. Client's requests with this "
                   "nonce will be always 'stale'. Probably clients' requests "
                   "are too intensive.\n"));
#else  /* ! HAVE_MESSAGES */
      (void) 0;
#endif /* ! HAVE_MESSAGES */
    }
    /* Building the authentication header */
    hlen = MHD_snprintf_ (NULL,
                          0,
                          "Digest realm=\"%s\",qop=\"auth\",nonce=\"%s\",opaque=\"%s\",algorithm=%s%s",
                          realm,
                          nonce,
                          opaque,
                          digest_get_algo_name (&da),
                          signal_stale
                          ? ",stale=\"true\""
                          : "");
    if (hlen > 0)
    {
      char *header;

      header = MHD_calloc_ (1,
                            (size_t) hlen + 1);
      if (NULL == header)
      {
#ifdef HAVE_MESSAGES
        MHD_DLOG (connection->daemon,
                  _ ("Failed to allocate memory for auth response header.\n"));
#endif /* HAVE_MESSAGES */
        return MHD_NO;
      }

      if (MHD_snprintf_ (header,
                         (size_t) hlen + 1,
                         "Digest realm=\"%s\",qop=\"auth\",nonce=\"%s\",opaque=\"%s\",algorithm=%s%s",
                         realm,
                         nonce,
                         opaque,
                         digest_get_algo_name (&da),
                         signal_stale
                         ? ",stale=\"true\""
                         : "") == hlen)
        ret = MHD_add_response_header (response,
                                       MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                                       header);
      else
        ret = MHD_NO;
#if 0
      if ( (MHD_NO != ret) && (AND in state : 100 continue aborting ...))
        ret = MHD_add_response_header (response,
                                       MHD_HTTP_HEADER_CONNECTION,
                                       "close");
#endif
      free (header);
    }
    else
      ret = MHD_NO;
  }

  if (MHD_NO != ret)
  {
    ret = MHD_queue_response (connection,
                              MHD_HTTP_UNAUTHORIZED,
                              response);
  }
  else
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (connection->daemon,
              _ ("Failed to add Digest auth header.\n"));
#endif /* HAVE_MESSAGES */
  }
  return ret;
}


/**
 * Queues a response to request authentication from the client.
 * For now uses MD5 (for backwards-compatibility). Still, if you
 * need to be sure, use #MHD_queue_auth_fail_response2().
 *
 * @param connection The MHD connection structure
 * @param realm the realm presented to the client
 * @param opaque string to user for opaque value
 * @param response reply to send; should contain the "access denied"
 *        body; note that this function will set the "WWW Authenticate"
 *        header and that the caller should not do this; the NULL is tolerated
 * @param signal_stale #MHD_YES if the nonce is stale to add
 *        'stale=true' to the authentication header
 * @return #MHD_YES on success, #MHD_NO otherwise
 * @ingroup authentication
 * @deprecated use MHD_queue_auth_fail_response2()
 */
_MHD_EXTERN enum MHD_Result
MHD_queue_auth_fail_response (struct MHD_Connection *connection,
                              const char *realm,
                              const char *opaque,
                              struct MHD_Response *response,
                              int signal_stale)
{
  return MHD_queue_auth_fail_response2 (connection,
                                        realm,
                                        opaque,
                                        response,
                                        signal_stale,
                                        MHD_DIGEST_ALG_MD5);
}


/* end of digestauth.c */
