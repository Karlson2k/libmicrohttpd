/*
     This file is part of libmicrohttpd
     Copyright (C) 2010, 2011, 2012, 2015, 2018 Daniel Pittman and Christian Grothoff

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
 */
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
 * Beginning string for any valid Digest authentication header.
 */
#define _BASE   "Digest "

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
#define MAX_AUTH_RESPONSE_LENGTH 256

/**
 * The token for MD5 algorithm.
 */
#define _MHD_MD5_TOKEN "MD5"

/**
 * The token for SHA-256 algorithm.
 */
#define _MHD_SHA256_TOKEN "SHA-256"

/**
 * The postfix token for "session" algorithms.
 */
#define _MHD_SESS_TOKEN "-sess"


/**
 * The result of digest authentication of the client.
 */
enum MHD_DigestAuthResult
{
  /**
   * Authentication OK
   */
  MHD_DAUTH_OK = 1,

  /**
   * General error, like "out of memory"
   */
  MHD_DAUTH_ERROR = 0,

  /**
   * No "Authorization" header or wrong format of the header.
   */
  MHD_DAUTH_WRONG_HEADER = -1,

  /**
   * Wrong 'username'.
   */
  MHD_DAUTH_WRONG_USERNAME = -2,

  /**
   * Wrong 'realm'.
   */
  MHD_DAUTH_WRONG_REALM = -3,

  /**
   * Wrong 'URI' (or URI parameters).
   */
  MHD_DAUTH_WRONG_URI = -4,

  /* The different form of naming is intentionally used for the results below,
   * as they are more important */

  /**
   * The 'nonce' is too old. Suggest the client to retry with the same
   * username and password to get the fresh 'nonce'.
   * The validity of the 'nonce' may not be checked.
   */
  MHD_DAUTH_NONCE_STALE = -16,

  /**
   * The 'nonce' is wrong. May indicate an attack attempt.
   */
  MHD_DAUTH_NONCE_WRONG = -32,

  /**
   * The 'response' is wrong. May indicate an attack attempt.
   */
  MHD_DAUTH_RESPONSE_WRONG = -33,
};

/**
 * Context passed to functions that need to calculate
 * a digest but are orthogonal to the specific
 * algorithm.
 */
struct DigestAlgorithm
{
  /**
   * Size of the final digest returned by @e digest.
   */
  unsigned int digest_size;

  /**
   * A context for the digest algorithm, already initialized to be
   * useful for @e init, @e update and @e digest.
   */
  void *ctx;

  /**
   * Name of the algorithm, "MD5" or "SHA-256".
   * @sa #_MHD_MD5_TOKEN, #_MHD_SHA256_TOKEN
   */
  const char *alg;

  /**
   * Buffer of @e digest_size * 2 + 1 bytes.
   */
  char *sessionkey;

  /**
   * Call to initialize @e ctx.
   */
  void
  (*init)(void *ctx);

  /**
   * Feed more data into the digest function.
   *
   * @param ctx context to feed
   * @param length number of bytes in @a data
   * @param data data to add
   */
  void
  (*update)(void *ctx,
            const uint8_t *data,
            size_t length);

  /**
   * Compute final @a digest.
   *
   * @param ctx context to use
   * @param[out] digest where to write the result,
   *        must be @e digest_length bytes long
   */
  void
  (*digest)(void *ctx,
            uint8_t *digest);
};


/**
 * calculate H(A1) from given hash as per RFC2617 spec
 * and store the * result in 'sessionkey'.
 *
 * @param alg The hash algorithm used, can be "MD5" or "MD5-sess"
 *            or "SHA-256" or "SHA-256-sess"
 *    Note that the rest of the code does not support the the "-sess" variants!
 * @param[in,out] da digest implementation, must match @a alg; the
 *          da->sessionkey will be initialized to the digest in HEX
 * @param digest An `unsigned char *' pointer to the binary MD5 sum
 *      for the precalculated hash value "username:realm:password"
 *      of #MHD_MD5_DIGEST_SIZE or #SHA256_DIGEST_SIZE bytes
 * @param nonce A `char *' pointer to the nonce value
 * @param cnonce A `char *' pointer to the cnonce value
 */
static void
digest_calc_ha1_from_digest (const char *alg,
                             struct DigestAlgorithm *da,
                             const uint8_t *digest,
                             const char *nonce,
                             const char *cnonce)
{
  const unsigned int digest_size = da->digest_size;
  if ( (MHD_str_equal_caseless_ (alg,
                                 _MHD_MD5_TOKEN _MHD_SESS_TOKEN)) ||
       (MHD_str_equal_caseless_ (alg,
                                 _MHD_SHA256_TOKEN _MHD_SESS_TOKEN)) )
  {
    uint8_t dig[VLA_ARRAY_LEN_DIGEST (digest_size)];

    VLA_CHECK_LEN_DIGEST (digest_size);
    da->init (da->ctx);
    da->update (da->ctx,
                digest,
                MHD_MD5_DIGEST_SIZE);
    da->update (da->ctx,
                (const unsigned char *) ":",
                1);
    da->update (da->ctx,
                (const unsigned char *) nonce,
                strlen (nonce));
    da->update (da->ctx,
                (const unsigned char *) ":",
                1);
    da->update (da->ctx,
                (const unsigned char *) cnonce,
                strlen (cnonce));
    da->digest (da->ctx,
                dig);
    MHD_bin_to_hex (dig,
                    digest_size,
                    da->sessionkey);
  }
  else
  {
    MHD_bin_to_hex (digest,
                    digest_size,
                    da->sessionkey);
  }
}


/**
 * calculate H(A1) from username, realm and password as per RFC2617 spec
 * and store the result in 'sessionkey'.
 *
 * @param alg The hash algorithm used, can be "MD5" or "MD5-sess"
 *             or "SHA-256" or "SHA-256-sess"
 * @param username A `char *' pointer to the username value
 * @param realm A `char *' pointer to the realm value
 * @param password A `char *' pointer to the password value
 * @param nonce A `char *' pointer to the nonce value
 * @param cnonce A `char *' pointer to the cnonce value
 * @param[in,out] da digest algorithm to use, and where to write
 *         the sessionkey to
 */
static void
digest_calc_ha1_from_user (const char *alg,
                           const char *username,
                           const char *realm,
                           const char *password,
                           const char *nonce,
                           const char *cnonce,
                           struct DigestAlgorithm *da)
{
  unsigned char ha1[VLA_ARRAY_LEN_DIGEST (da->digest_size)];

  VLA_CHECK_LEN_DIGEST (da->digest_size);
  da->init (da->ctx);
  da->update (da->ctx,
              (const unsigned char *) username,
              strlen (username));
  da->update (da->ctx,
              (const unsigned char *) ":",
              1);
  da->update (da->ctx,
              (const unsigned char *) realm,
              strlen (realm));
  da->update (da->ctx,
              (const unsigned char *) ":",
              1);
  da->update (da->ctx,
              (const unsigned char *) password,
              strlen (password));
  da->digest (da->ctx,
              ha1);
  digest_calc_ha1_from_digest (alg,
                               da,
                               ha1,
                               nonce,
                               cnonce);
}


/**
 * Calculate request-digest/response-digest as per RFC2617 / RFC7616
 * spec.
 *
 * @param ha1 H(A1), twice the @a da->digest_size + 1 bytes (0-terminated),
 *        MUST NOT be aliased with `da->sessionkey`!
 * @param nonce nonce from server
 * @param noncecount 8 hex digits
 * @param cnonce client nonce
 * @param qop qop-value: "", "auth" or "auth-int" (NOTE: only 'auth' is supported today.)
 * @param method method from request
 * @param uri requested URL
 * @param hentity H(entity body) if qop="auth-int"
 * @param[in,out] da digest algorithm to use, also
 *        we write da->sessionkey (set to response request-digest or response-digest)
 */
static void
digest_calc_response (const char *ha1,
                      const char *nonce,
                      const char *noncecount,
                      const char *cnonce,
                      const char *qop,
                      const char *method,
                      const char *uri,
                      const char *hentity,
                      struct DigestAlgorithm *da)
{
  const unsigned int digest_size = da->digest_size;
  unsigned char ha2[VLA_ARRAY_LEN_DIGEST (digest_size)];
  unsigned char resphash[VLA_ARRAY_LEN_DIGEST (digest_size)];
  (void) hentity; /* Unused. Silence compiler warning. */

  VLA_CHECK_LEN_DIGEST (digest_size);
  da->init (da->ctx);
  da->update (da->ctx,
              (const unsigned char *) method,
              strlen (method));
  da->update (da->ctx,
              (const unsigned char *) ":",
              1);
  da->update (da->ctx,
              (const unsigned char *) uri,
              strlen (uri));
#if 0
  if (0 == strcasecmp (qop,
                       "auth-int"))
  {
    /* This is dead code since the rest of this module does
 not support auth-int. */
    da->update (da->ctx,
                ":",
                1);
    if (NULL != hentity)
      da->update (da->ctx,
                  hentity,
                  strlen (hentity));
  }
#endif
  da->digest (da->ctx,
              ha2);
  MHD_bin_to_hex (ha2,
                  digest_size,
                  da->sessionkey);
  da->init (da->ctx);
  /* calculate response */
  da->update (da->ctx,
              (const unsigned char *) ha1,
              digest_size * 2);
  da->update (da->ctx,
              (const unsigned char *) ":",
              1);
  da->update (da->ctx,
              (const unsigned char *) nonce,
              strlen (nonce));
  da->update (da->ctx,
              (const unsigned char *) ":",
              1);
  if ('\0' != *qop)
  {
    da->update (da->ctx,
                (const unsigned char *) noncecount,
                strlen (noncecount));
    da->update (da->ctx,
                (const unsigned char *) ":",
                1);
    da->update (da->ctx,
                (const unsigned char *) cnonce,
                strlen (cnonce));
    da->update (da->ctx,
                (const unsigned char *) ":",
                1);
    da->update (da->ctx,
                (const unsigned char *) qop,
                strlen (qop));
    da->update (da->ctx,
                (const unsigned char *) ":",
                1);
  }
  da->update (da->ctx,
              (const unsigned char *) da->sessionkey,
              digest_size * 2);
  da->digest (da->ctx,
              resphash);
  MHD_bin_to_hex (resphash,
                  digest_size,
                  da->sessionkey);
}


/**
 * Lookup subvalue off of the HTTP Authorization header.
 *
 * A description of the input format for 'data' is at
 * http://en.wikipedia.org/wiki/Digest_access_authentication
 *
 *
 * @param dest where to store the result (possibly truncated if
 *             the buffer is not big enough).
 * @param size size of dest
 * @param data pointer to the Authorization header
 * @param key key to look up in data
 * @return size of the located value, 0 if otherwise
 */
static size_t
lookup_sub_value (char *dest,
                  size_t size,
                  const char *data,
                  const char *key)
{
  size_t keylen;
  size_t len;
  const char *ptr;
  const char *eq;
  const char *q1;
  const char *q2;
  const char *qn;

  if (0 == size)
    return 0;
  keylen = strlen (key);
  ptr = data;
  while ('\0' != *ptr)
  {
    if (NULL == (eq = strchr (ptr,
                              '=')))
      return 0;
    q1 = eq + 1;
    while (' ' == *q1)
      q1++;
    if ('\"' != *q1)
    {
      q2 = strchr (q1,
                   ',');
      qn = q2;
    }
    else
    {
      q1++;
      q2 = strchr (q1,
                   '\"');
      if (NULL == q2)
        return 0; /* end quote not found */
      qn = q2 + 1;
    }
    if ( (MHD_str_equal_caseless_n_ (ptr,
                                     key,
                                     keylen)) &&
         (eq == &ptr[keylen]) )
    {
      if (NULL == q2)
      {
        len = strlen (q1) + 1;
        if (size > len)
          size = len;
        size--;
        memcpy (dest,
                q1,
                size);
        dest[size] = '\0';
        return size;
      }
      else
      {
        if (size > (size_t) ((q2 - q1) + 1))
          size = (size_t) (q2 - q1) + 1;
        size--;
        memcpy (dest,
                q1,
                size);
        dest[size] = '\0';
        return size;
      }
    }
    if (NULL == qn)
      return 0;
    ptr = strchr (qn,
                  ',');
    if (NULL == ptr)
      return 0;
    ptr++;
    while (' ' == *ptr)
      ptr++;
  }
  return 0;
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
 * @param noncelen the lenth of @a nonce, in characters
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
 * Check nonce-nc map array with either new nonce counter
 * or a whole new nonce.
 *
 * @param connection The MHD connection structure
 * @param nonce A pointer that referenced a zero-terminated array of nonce
 * @param noncelen the lenth of @a nonce, in characters
 * @param nc The nonce counter, zero to add the nonce to the array
 * @return #MHD_YES if successful, #MHD_NO if invalid (or we have no NC array)
 */
static bool
check_nonce_nc (struct MHD_Connection *connection,
                const char *nonce,
                size_t noncelen,
                uint64_t nc)
{
  struct MHD_Daemon *daemon = MHD_get_master (connection->daemon);
  struct MHD_NonceNc *nn;
  uint32_t mod;
  bool ret;

  mhd_assert (noncelen == strlen (nonce));
  mhd_assert (0 != nc);
  if (MAX_NONCE_LENGTH < noncelen)
    return false; /* This should be impossible, but static analysis
                      tools have a hard time with it *and* this also
                      protects against unsafe modifications that may
                      happen in the future... */
  mod = daemon->nonce_nc_size;
  if (0 == mod)
    return false;  /* no array! */
  if (nc + 64 < nc)
    return false;  /* Overflow, unrealistically high value */

  /*
   * Look for the nonce, if it does exist and its corresponding
   * nonce counter is less than the current nonce counter by 1,
   * then only increase the nonce counter by one.
   */
  nn = &daemon->nnc[get_nonce_nc_idx (mod, nonce, noncelen)];

  MHD_mutex_lock_chk_ (&daemon->nnc_lock);

  if ( (0 != memcmp (nn->nonce, nonce, noncelen)) ||
       (0 != nn->nonce[noncelen]) )
    ret = false;     /* Nonce does not match, fail */
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
    ret = true;
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
      ret = true;
    }
    else
      /* 'nc' was already used or too old (more then 64 values ago) */
      ret = false;
  }
  else /* if (nc == nn->nc) */
    /* 'nc' was already used */
    ret = false;

  MHD_mutex_unlock_chk_ (&daemon->nnc_lock);
#ifdef HAVE_MESSAGES
  if (! ret)
    MHD_DLOG (daemon,
              _ ("Stale nonce received. If this happens a lot, you should "
                 "probably increase the size of the nonce array.\n"));
#endif
  return ret;
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
  char user[MAX_USERNAME_LENGTH];
  const char *header;

  if (MHD_NO == MHD_lookup_connection_value_n (connection,
                                               MHD_HEADER_KIND,
                                               MHD_HTTP_HEADER_AUTHORIZATION,
                                               MHD_STATICSTR_LEN_ (
                                                 MHD_HTTP_HEADER_AUTHORIZATION),
                                               &header,
                                               NULL))
    return NULL;
  if (0 != strncmp (header,
                    _BASE,
                    MHD_STATICSTR_LEN_ (_BASE)))
    return NULL;
  header += MHD_STATICSTR_LEN_ (_BASE);
  if (0 == lookup_sub_value (user,
                             sizeof (user),
                             header,
                             "username"))
    return NULL;
  return strdup (user);
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
                 const char *realm,
                 struct DigestAlgorithm *da,
                 char *nonce)
{
  uint8_t timestamp[TIMESTAMP_BIN_SIZE];
  const unsigned int digest_size = da->digest_size;
  char tmpnonce[VLA_ARRAY_LEN_DIGEST (digest_size)];

  mhd_assert (0 == (digest_size % 2));
  mhd_assert (0 != digest_size);
  VLA_CHECK_LEN_DIGEST (digest_size);
  da->init (da->ctx);
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
  da->update (da->ctx,
              timestamp,
              sizeof (timestamp));
  da->update (da->ctx,
              (const unsigned char *) ":",
              1);
  da->update (da->ctx,
              (const unsigned char *) method,
              strlen (method));
  da->update (da->ctx,
              (const unsigned char *) ":",
              1);
  if (rnd_size > 0)
    da->update (da->ctx,
                (const unsigned char *) rnd,
                rnd_size);
  da->update (da->ctx,
              (const unsigned char *) ":",
              1);
  da->update (da->ctx,
              (const unsigned char *) uri,
              strlen (uri));
  da->update (da->ctx,
              (const unsigned char *) ":",
              1);
  da->update (da->ctx,
              (const unsigned char *) realm,
              strlen (realm));
  da->digest (da->ctx,
              (uint8_t *) tmpnonce);
  MHD_bin_to_hex (tmpnonce,
                  digest_size,
                  nonce);
  MHD_bin_to_hex (timestamp,
                  sizeof (timestamp),
                  nonce + digest_size * 2);
}


/**
 * Extract timestamp from the given nonce.
 * @param nonce the nonce to check
 * @param noncelen the lenght of the nonce, zero for autodetect
 * @param[out] ptimestamp the pointer to store extracted timestamp
 * @return true if timestamp was extracted,
 *         false if nonce does not have valid timestamp.
 */
static bool
get_nonce_timestamp (const char *const nonce,
                     size_t noncelen,
                     uint64_t *const ptimestamp)
{
  mhd_assert ((0 == noncelen) || (strlen (nonce) == noncelen));
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
  mhd_assert (NONCE_STD_LEN (MAX_DIGEST) < MAX_NONCE_LENGTH);
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
                     struct DigestAlgorithm *da,
                     char *nonce)
{
  struct MHD_Daemon *const daemon = MHD_get_master (connection->daemon);
  struct MHD_NonceNc *nn;
  const size_t nonce_size = NONCE_STD_LEN (da->digest_size);
  bool ret;

  mhd_assert (MAX_NONCE_LENGTH >= nonce_size);
  mhd_assert (0 != nonce_size);

  calculate_nonce (timestamp,
                   connection->method,
                   daemon->digest_auth_random,
                   daemon->digest_auth_rand_size,
                   connection->url,
                   realm,
                   da,
                   nonce);

  if (0 == daemon->nonce_nc_size)
    return false;

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

  if (! calculate_add_nonce (connection, timestamp1, realm, da, nonce))
  {
    /* Either:
     * 1. The same nonce was already generated. If it will be used then one
     * of the clients will fail (as no initial 'nc' value could be given to
     * the client, the second client which will use 'nc=00000001' will fail).
     * 2. Another nonce uses the same slot, and this nonce never has been
     * used by the client and this nonce is still fresh enough.
     */
    const size_t digest_size = da->digest_size;
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
        timestamp2 -= 2;
    }
    if (! calculate_add_nonce (connection, timestamp2, realm, da, nonce2))
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


/**
 * Test if the given key-value pair is in the headers for the
 * given connection.
 *
 * @param connection the connection
 * @param key the key
 * @param key_size number of bytes in @a key
 * @param value the value, can be NULL
 * @param value_size number of bytes in @a value
 * @param kind type of the header
 * @return #MHD_YES if the key-value pair is in the headers,
 *         #MHD_NO if not
 */
static enum MHD_Result
test_header (struct MHD_Connection *connection,
             const char *key,
             size_t key_size,
             const char *value,
             size_t value_size,
             enum MHD_ValueKind kind)
{
  struct MHD_HTTP_Req_Header *pos;

  for (pos = connection->headers_received; NULL != pos; pos = pos->next)
  {
    if (kind != pos->kind)
      continue;
    if (key_size != pos->header_size)
      continue;
    if (value_size != pos->value_size)
      continue;
    if (0 != memcmp (key,
                     pos->header,
                     key_size))
      continue;
    if ( (NULL == value) &&
         (NULL == pos->value) )
      return MHD_YES;
    if ( (NULL == value) ||
         (NULL == pos->value) ||
         (0 != memcmp (value,
                       pos->value,
                       value_size)) )
      continue;
    return MHD_YES;
  }
  return MHD_NO;
}


/**
 * Check that the arguments given by the client as part
 * of the authentication header match the arguments we
 * got as part of the HTTP request URI.
 *
 * @param connection connections with headers to compare against
 * @param args argument URI string (after "?" in URI)
 * @return #MHD_YES if the arguments match,
 *         #MHD_NO if not
 */
static enum MHD_Result
check_argument_match (struct MHD_Connection *connection,
                      const char *args)
{
  struct MHD_HTTP_Req_Header *pos;
  char *argb;
  unsigned int num_headers;
  enum MHD_Result ret;

  argb = strdup (args);
  if (NULL == argb)
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (connection->daemon,
              _ ("Failed to allocate memory for copy of URI arguments.\n"));
#endif /* HAVE_MESSAGES */
    return MHD_NO;
  }
  ret = MHD_parse_arguments_ (connection,
                              MHD_GET_ARGUMENT_KIND,
                              argb,
                              &test_header,
                              &num_headers);
  free (argb);
  if (MHD_NO == ret)
  {
    return MHD_NO;
  }
  /* also check that the number of headers matches */
  for (pos = connection->headers_received; NULL != pos; pos = pos->next)
  {
    if (MHD_GET_ARGUMENT_KIND != pos->kind)
      continue;
    num_headers--;
  }
  if (0 != num_headers)
  {
    /* argument count mismatch */
    return MHD_NO;
  }
  return MHD_YES;
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
  struct MHD_Daemon *daemon = MHD_get_master (connection->daemon);
  size_t len;
  const char *header;
  char nonce[MAX_NONCE_LENGTH];
  size_t nonce_len;
  char cnonce[MAX_NONCE_LENGTH];
  const unsigned int digest_size = da->digest_size;
  char ha1[VLA_ARRAY_LEN_DIGEST (digest_size) * 2 + 1];
  char qop[15]; /* auth,auth-int */
  char nc[20];
  char response[MAX_AUTH_RESPONSE_LENGTH];
  const char *hentity = NULL; /* "auth-int" is not supported */
  char noncehashexp[NONCE_STD_LEN (VLA_ARRAY_LEN_DIGEST (digest_size)) + 1];
  uint64_t nonce_time;
  uint64_t t;
  size_t left; /* number of characters left in 'header' for 'uri' */
  uint64_t nci;
  char *qmark;

  VLA_CHECK_LEN_DIGEST (digest_size);
  if (MHD_NO == MHD_lookup_connection_value_n (connection,
                                               MHD_HEADER_KIND,
                                               MHD_HTTP_HEADER_AUTHORIZATION,
                                               MHD_STATICSTR_LEN_ (
                                                 MHD_HTTP_HEADER_AUTHORIZATION),
                                               &header,
                                               NULL))
    return MHD_DAUTH_WRONG_HEADER;
  if (0 != strncmp (header,
                    _BASE,
                    MHD_STATICSTR_LEN_ (_BASE)))
    return MHD_DAUTH_WRONG_HEADER;
  header += MHD_STATICSTR_LEN_ (_BASE);
  left = strlen (header);

  if (1)
  {
    char un[MAX_USERNAME_LENGTH];

    len = lookup_sub_value (un,
                            sizeof (un),
                            header,
                            "username");
    if (0 == len)
      return MHD_DAUTH_WRONG_HEADER;
    if (0 != strcmp (username,
                     un))
      return MHD_DAUTH_WRONG_USERNAME;
    left -= strlen ("username") + len;
  }

  if (1)
  {
    char r[MAX_REALM_LENGTH];

    len = lookup_sub_value (r,
                            sizeof (r),
                            header,
                            "realm");
    if (0 == len)
      return MHD_DAUTH_WRONG_HEADER;
    if (0 != strcmp (realm,
                     r))
      return MHD_DAUTH_WRONG_REALM;
    left -= strlen ("realm") + len;
  }

  if (0 == (len = lookup_sub_value (nonce,
                                    sizeof (nonce),
                                    header,
                                    "nonce")))
    return MHD_DAUTH_WRONG_HEADER;
  nonce_len = len;
  left -= strlen ("nonce") + len;
  if (left > 32 * 1024)
  {
    /* we do not permit URIs longer than 32k, as we want to
       make sure to not blow our stack (or per-connection
       heap memory limit).  Besides, 32k is already insanely
       large, but of course in theory the
       #MHD_OPTION_CONNECTION_MEMORY_LIMIT might be very large
       and would thus permit sending a >32k authorization
       header value. */
    return MHD_DAUTH_WRONG_HEADER;
  }
  if (! get_nonce_timestamp (nonce, nonce_len, &nonce_time))
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (daemon,
              _ ("Authentication failed, invalid timestamp format.\n"));
#endif
    return MHD_DAUTH_WRONG_HEADER;
  }

  t = MHD_monotonic_msec_counter ();
  /*
   * First level vetting for the nonce validity: if the timestamp
   * attached to the nonce exceeds `nonce_timeout', then the nonce is
   * invalid.
   */
  if (TRIM_TO_TIMESTAMP (t - nonce_time) > (nonce_timeout * 1000))
  {
    /* too old */
    return MHD_DAUTH_NONCE_STALE;
  }

  calculate_nonce (nonce_time,
                   connection->method,
                   daemon->digest_auth_random,
                   daemon->digest_auth_rand_size,
                   connection->url,
                   realm,
                   da,
                   noncehashexp);
  /*
   * Second level vetting for the nonce validity
   * if the timestamp attached to the nonce is valid
   * and possibly fabricated (in case of an attack)
   * the attacker must also know the random seed to be
   * able to generate a "sane" nonce, which if he does
   * not, the nonce fabrication process going to be
   * very hard to achieve.
   */
  if (0 != strcmp (nonce,
                   noncehashexp))
  {
    return MHD_DAUTH_NONCE_WRONG;
  }
  if ( (0 == lookup_sub_value (cnonce,
                               sizeof (cnonce),
                               header,
                               "cnonce")) ||
       (0 == lookup_sub_value (qop,
                               sizeof (qop),
                               header,
                               "qop")) ||
       ( (0 != strcmp (qop,
                       "auth")) &&
         (0 != strcmp (qop,
                       "")) ) ||
       (0 == (len = lookup_sub_value (nc,
                                      sizeof (nc),
                                      header,
                                      "nc")) ) ||
       (0 == lookup_sub_value (response,
                               sizeof (response),
                               header,
                               "response")) )
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (daemon,
              _ ("Authentication failed, invalid format.\n"));
#endif
    return MHD_DAUTH_WRONG_HEADER;
  }
  if (len != MHD_strx_to_uint64_n_ (nc,
                                    len,
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

  /*
   * Checking if that combination of nonce and nc is sound
   * and not a replay attack attempt. Refuse if nonce was not
   * generated previously.
   */
  if (! check_nonce_nc (connection,
                        nonce,
                        nonce_len,
                        nci))
  {
    return MHD_DAUTH_NONCE_STALE;
  }

  if (1)
  {
    char *uri;

    uri = malloc (left + 1);
    if (NULL == uri)
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _ ("Failed to allocate memory for auth header processing.\n"));
#endif /* HAVE_MESSAGES */
      return MHD_DAUTH_ERROR;
    }
    if (0 == lookup_sub_value (uri,
                               left + 1,
                               header,
                               "uri"))
    {
      free (uri);
      return MHD_DAUTH_WRONG_HEADER;
    }
    if (NULL != digest)
    {
      /* This will initialize da->sessionkey (ha1) */
      digest_calc_ha1_from_digest (da->alg,
                                   da,
                                   digest,
                                   nonce,
                                   cnonce);
    }
    else
    {
      /* This will initialize da->sessionkey (ha1) */
      mhd_assert (NULL != password);   /* NULL == digest => password != NULL */
      digest_calc_ha1_from_user (da->alg,
                                 username,
                                 realm,
                                 password,
                                 nonce,
                                 cnonce,
                                 da);
    }
    memcpy (ha1,
            da->sessionkey,
            digest_size * 2 + 1);
    /* This will initialize da->sessionkey (respexp) */
    digest_calc_response (ha1,
                          nonce,
                          nc,
                          cnonce,
                          qop,
                          connection->method,
                          uri,
                          hentity,
                          da);
    qmark = strchr (uri,
                    '?');
    if (NULL != qmark)
      *qmark = '\0';

    /* Need to unescape URI before comparing with connection->url */
    daemon->unescape_callback (daemon->unescape_callback_cls,
                               connection,
                               uri);
    if (0 != strcmp (uri,
                     connection->url))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _ ("Authentication failed, URI does not match.\n"));
#endif
      free (uri);
      return MHD_DAUTH_WRONG_URI;
    }

    if (1)
    {
      const char *args = qmark;

      if (NULL == args)
        args = "";
      else
        args++;
      if (MHD_NO ==
          check_argument_match (connection,
                                args) )
      {
#ifdef HAVE_MESSAGES
        MHD_DLOG (daemon,
                  _ ("Authentication failed, arguments do not match.\n"));
#endif
        free (uri);
        return MHD_DAUTH_WRONG_URI;
      }
    }
    free (uri);
  }
  return (0 == strcmp (response,
                       da->sessionkey))
         ? MHD_DAUTH_OK
         : MHD_DAUTH_RESPONSE_WRONG;
}


/**
 * Authenticates the authorization header sent by the client.
 * Uses #MHD_DIGEST_ALG_MD5 (for now, for backwards-compatibility).
 * Note that this MAY change to #MHD_DIGEST_ALG_AUTO in the future.
 * If you want to be sure you get MD5, use #MHD_digest_auth_check2
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
 * Setup digest authentication data structures (on the
 * stack, hence must be done inline!).  Initializes a
 * "struct DigestAlgorithm da" for algorithm @a algo.
 *
 * @param algo digest algorithm to provide
 * @param da data structure to setup
 */
#define SETUP_DA(algo,da)                         \
  union {                                         \
    struct MD5Context md5;                        \
    struct sha256_ctx sha256;                     \
  } ctx;                                          \
  union {                                         \
    char md5[MD5_DIGEST_SIZE * 2 + 1];            \
    char sha256[SHA256_DIGEST_SIZE * 2 + 1];      \
  } skey;                                         \
  struct DigestAlgorithm da;                      \
                                                  \
  do {                                            \
    switch (algo) {                                 \
    case MHD_DIGEST_ALG_MD5:                        \
      da.digest_size = MD5_DIGEST_SIZE;             \
      da.ctx = &ctx.md5;                            \
      da.alg = _MHD_MD5_TOKEN;                               \
      da.sessionkey = skey.md5;                     \
      da.init = &MHD_MD5Init;                           \
      da.update = &MHD_MD5Update;                       \
      da.digest = &MHD_MD5Final;                        \
      break;                                        \
    case MHD_DIGEST_ALG_AUTO:                             \
  /* auto == SHA256, fall-though thus intentional! */ \
    case MHD_DIGEST_ALG_SHA256:                           \
      da.digest_size = SHA256_DIGEST_SIZE;                \
      da.ctx = &ctx.sha256;                               \
      da.alg = _MHD_SHA256_TOKEN;                                 \
      da.sessionkey = skey.sha256;                        \
      da.init = &MHD_SHA256_init;                             \
      da.update = &MHD_SHA256_update;                         \
      da.digest = &MHD_SHA256_finish;                         \
      break;                                              \
    default:                                              \
      da.digest_size = 0;                                 \
      mhd_assert (false);                                 \
      break;                                              \
    }                                                     \
  } while (0)


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
  SETUP_DA (algo, da);

  mhd_assert (NULL != password);
  if (0 == da.digest_size)
    MHD_PANIC (_ ("Wrong algo value.\n")); /* API violation! */
  res = digest_auth_check_all (connection,
                               &da,
                               realm,
                               username,
                               password,
                               NULL,
                               nonce_timeout);
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
 *      of #MHD_MD5_DIGEST_SIZE bytes
 * @param digest_size number of bytes in @a digest
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @param algo digest algorithms allowed for verification
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
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
  SETUP_DA (algo, da);

  mhd_assert (NULL != digest);
  if ((da.digest_size != digest_size) || (0 == digest_size))
    MHD_PANIC (_ ("Digest size mismatch.\n")); /* API violation! */
  res = digest_auth_check_all (connection,
                               &da,
                               realm,
                               username,
                               NULL,
                               digest,
                               nonce_timeout);
  if (MHD_DAUTH_OK == res)
    return MHD_YES;
  else if ((MHD_DAUTH_NONCE_STALE == res) || (MHD_DAUTH_NONCE_WRONG == res))
    return MHD_INVALID_NONCE;
  return MHD_NO;
}


/**
 * Authenticates the authorization header sent by the client.
 * Uses #MHD_DIGEST_ALG_MD5 (required, as @a digest is of fixed
 * size).
 *
 * @param connection The MHD connection structure
 * @param realm The realm presented to the client
 * @param username The username needs to be authenticated
 * @param digest An `unsigned char *' pointer to the binary digest
 *      for the precalculated hash value "username:realm:password"
 *      of @a digest_size bytes
 * @param nonce_timeout The amount of time for a nonce to be
 *      invalid in seconds
 * @return #MHD_YES if authenticated, #MHD_NO if not,
 *         #MHD_INVALID_NONCE if nonce is invalid or stale
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
 * @param signal_stale #MHD_YES if the nonce is invalid to add
 *      'stale=true' to the authentication header
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
  int ret;
  int hlen;
  SETUP_DA (algo, da);

  if (0 == da.digest_size)
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
    char nonce[NONCE_STD_LEN (VLA_ARRAY_LEN_DIGEST (da.digest_size)) + 1];

    VLA_CHECK_LEN_DIGEST (da.digest_size);
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
                          da.alg,
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
                         da.alg,
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
 *        header and that the caller should not do this
 * @param signal_stale #MHD_YES if the nonce is invalid to add
 *      'stale=true' to the authentication header
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
