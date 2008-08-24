/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* This file handles all the internal functions that cope with hashes
 * and HMACs.
 */

#include <gnutls_int.h>
#include <gnutls_hash_int.h>
#include <gnutls_errors.h>

static inline Gc_hash
_gnutls_mac2gc (enum MHD_GNUTLS_HashAlgorithm mac)
{
  switch (mac)
    {
    case MHD_GNUTLS_MAC_NULL:
      return -1;
      break;
    case MHD_GNUTLS_MAC_SHA1:
      return GC_SHA1;
      break;
    case MHD_GNUTLS_MAC_SHA256:
      return GC_SHA256;
      break;
    case MHD_GNUTLS_MAC_MD5:
      return GC_MD5;
      break;
    default:
      gnutls_assert ();
      return -1;
    }
  return -1;
}

GNUTLS_HASH_HANDLE
mhd_gtls_hash_init (enum MHD_GNUTLS_HashAlgorithm algorithm)
{
  mac_hd_t ret;
  int result;

  ret = gnutls_malloc (sizeof (mac_hd_st));
  if (ret == NULL)
    {
      gnutls_assert ();
      return GNUTLS_HASH_FAILED;
    }

  ret->algorithm = algorithm;

  result = gc_hash_open (_gnutls_mac2gc (algorithm), 0, &ret->handle);
  if (result)
    {
      gnutls_assert ();
      gnutls_free (ret);
      ret = GNUTLS_HASH_FAILED;
    }

  return ret;
}

int
mhd_gnutls_hash_get_algo_len (enum MHD_GNUTLS_HashAlgorithm algorithm)
{
  int ret;

  ret = gc_hash_digest_length (_gnutls_mac2gc (algorithm));

  return ret;

}

int
mhd_gnutls_hash (GNUTLS_HASH_HANDLE handle, const void *text, size_t textlen)
{
  if (textlen > 0)
    gc_hash_write (handle->handle, textlen, text);
  return 0;
}

GNUTLS_HASH_HANDLE
mhd_gnutls_hash_copy (GNUTLS_HASH_HANDLE handle)
{
  GNUTLS_HASH_HANDLE ret;
  int result;

  ret = gnutls_malloc (sizeof (mac_hd_st));

  if (ret == NULL)
    return GNUTLS_HASH_FAILED;

  ret->algorithm = handle->algorithm;
  ret->key = NULL;              /* it's a hash anyway */
  ret->keysize = 0;

  result = gc_hash_clone (handle->handle, &ret->handle);

  if (result)
    {
      gnutls_free (ret);
      return GNUTLS_HASH_FAILED;
    }

  return ret;
}

void
mhd_gnutls_hash_deinit (GNUTLS_HASH_HANDLE handle, void *digest)
{
  const opaque *mac;
  int maclen;

  maclen = mhd_gnutls_hash_get_algo_len (handle->algorithm);

  mac = gc_hash_read (handle->handle);
  if (digest != NULL)
    memcpy (digest, mac, maclen);

  gc_hash_close (handle->handle);

  gnutls_free (handle);
}


mac_hd_t
mhd_gtls_hmac_init (enum MHD_GNUTLS_HashAlgorithm algorithm,
                    const void *key, int keylen)
{
  mac_hd_t ret;
  int result;

  ret = gnutls_malloc (sizeof (mac_hd_st));
  if (ret == NULL)
    return GNUTLS_MAC_FAILED;

  result = gc_hash_open (_gnutls_mac2gc (algorithm), GC_HMAC, &ret->handle);
  if (result)
    {
      gnutls_free (ret);
      return GNUTLS_MAC_FAILED;
    }

  gc_hash_hmac_setkey (ret->handle, keylen, key);

  ret->algorithm = algorithm;
  ret->key = key;
  ret->keysize = keylen;

  return ret;
}

void
mhd_gnutls_hmac_deinit (mac_hd_t handle, void *digest)
{
  const opaque *mac;
  int maclen;

  maclen = mhd_gnutls_hash_get_algo_len (handle->algorithm);

  mac = gc_hash_read (handle->handle);

  if (digest != NULL)
    memcpy (digest, mac, maclen);

  gc_hash_close (handle->handle);

  gnutls_free (handle);
}

inline static int
get_padsize (enum MHD_GNUTLS_HashAlgorithm algorithm)
{
  switch (algorithm)
    {
    case MHD_GNUTLS_MAC_MD5:
      return 48;
    case MHD_GNUTLS_MAC_SHA1:
      return 40;
    default:
      return 0;
    }
}

mac_hd_t
mhd_gnutls_mac_init_ssl3 (enum MHD_GNUTLS_HashAlgorithm algorithm, void *key,
                          int keylen)
{
  mac_hd_t ret;
  opaque ipad[48];
  int padsize;

  padsize = get_padsize (algorithm);
  if (padsize == 0)
    {
      gnutls_assert ();
      return GNUTLS_MAC_FAILED;
    }

  memset (ipad, 0x36, padsize);

  ret = mhd_gtls_hash_init (algorithm);
  if (ret != GNUTLS_HASH_FAILED)
    {
      ret->key = key;
      ret->keysize = keylen;

      if (keylen > 0)
        mhd_gnutls_hash (ret, key, keylen);
      mhd_gnutls_hash (ret, ipad, padsize);
    }

  return ret;
}

void
mhd_gnutls_mac_deinit_ssl3 (mac_hd_t handle, void *digest)
{
  opaque ret[MAX_HASH_SIZE];
  mac_hd_t td;
  opaque opad[48];
  int padsize;
  int block;

  padsize = get_padsize (handle->algorithm);
  if (padsize == 0)
    {
      gnutls_assert ();
      return;
    }

  memset (opad, 0x5C, padsize);

  td = mhd_gtls_hash_init (handle->algorithm);
  if (td != GNUTLS_MAC_FAILED)
    {
      if (handle->keysize > 0)
        mhd_gnutls_hash (td, handle->key, handle->keysize);

      mhd_gnutls_hash (td, opad, padsize);
      block = mhd_gnutls_hash_get_algo_len (handle->algorithm);
      mhd_gnutls_hash_deinit (handle, ret);     /* get the previous hash */
      mhd_gnutls_hash (td, ret, block);

      mhd_gnutls_hash_deinit (td, digest);
    }
}

void
mhd_gnutls_mac_deinit_ssl3_handshake (mac_hd_t handle,
                                      void *digest, opaque * key,
                                      uint32_t key_size)
{
  opaque ret[MAX_HASH_SIZE];
  mac_hd_t td;
  opaque opad[48];
  opaque ipad[48];
  int padsize;
  int block;

  padsize = get_padsize (handle->algorithm);
  if (padsize == 0)
    {
      gnutls_assert ();
      return;
    }

  memset (opad, 0x5C, padsize);
  memset (ipad, 0x36, padsize);

  td = mhd_gtls_hash_init (handle->algorithm);
  if (td != GNUTLS_HASH_FAILED)
    {
      if (key_size > 0)
        mhd_gnutls_hash (td, key, key_size);

      mhd_gnutls_hash (td, opad, padsize);
      block = mhd_gnutls_hash_get_algo_len (handle->algorithm);

      if (key_size > 0)
        mhd_gnutls_hash (handle, key, key_size);
      mhd_gnutls_hash (handle, ipad, padsize);
      mhd_gnutls_hash_deinit (handle, ret);     /* get the previous hash */

      mhd_gnutls_hash (td, ret, block);

      mhd_gnutls_hash_deinit (td, digest);
    }
}

static int
ssl3_sha (int i, opaque * secret, int secret_len,
          opaque * rnd, int rnd_len, void *digest)
{
  int j;
  opaque text1[26];

  GNUTLS_HASH_HANDLE td;

  for (j = 0; j < i + 1; j++)
    {
      text1[j] = 65 + i;        /* A==65 */
    }

  td = mhd_gtls_hash_init (MHD_GNUTLS_MAC_SHA1);
  if (td == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  mhd_gnutls_hash (td, text1, i + 1);
  mhd_gnutls_hash (td, secret, secret_len);
  mhd_gnutls_hash (td, rnd, rnd_len);

  mhd_gnutls_hash_deinit (td, digest);
  return 0;
}

static int
ssl3_md5 (int i, opaque * secret, int secret_len,
          opaque * rnd, int rnd_len, void *digest)
{
  opaque tmp[MAX_HASH_SIZE];
  mac_hd_t td;
  int ret;

  td = mhd_gtls_hash_init (MHD_GNUTLS_MAC_MD5);
  if (td == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  mhd_gnutls_hash (td, secret, secret_len);

  ret = ssl3_sha (i, secret, secret_len, rnd, rnd_len, tmp);
  if (ret < 0)
    {
      gnutls_assert ();
      mhd_gnutls_hash_deinit (td, digest);
      return ret;
    }

  mhd_gnutls_hash (td, tmp,
                   mhd_gnutls_hash_get_algo_len (MHD_GNUTLS_MAC_SHA1));

  mhd_gnutls_hash_deinit (td, digest);
  return 0;
}

int
mhd_gnutls_ssl3_hash_md5 (void *first, int first_len,
                          void *second, int second_len, int ret_len,
                          opaque * ret)
{
  opaque digest[MAX_HASH_SIZE];
  mac_hd_t td;
  int block = mhd_gnutls_hash_get_algo_len (MHD_GNUTLS_MAC_MD5);

  td = mhd_gtls_hash_init (MHD_GNUTLS_MAC_MD5);
  if (td == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  mhd_gnutls_hash (td, first, first_len);
  mhd_gnutls_hash (td, second, second_len);

  mhd_gnutls_hash_deinit (td, digest);

  if (ret_len > block)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  memcpy (ret, digest, ret_len);

  return 0;

}

int
mhd_gnutls_ssl3_generate_random (void *secret, int secret_len,
                                 void *rnd, int rnd_len,
                                 int ret_bytes, opaque * ret)
{
  int i = 0, copy, output_bytes;
  opaque digest[MAX_HASH_SIZE];
  int block = mhd_gnutls_hash_get_algo_len (MHD_GNUTLS_MAC_MD5);
  int result, times;

  output_bytes = 0;
  do
    {
      output_bytes += block;
    }
  while (output_bytes < ret_bytes);

  times = output_bytes / block;

  for (i = 0; i < times; i++)
    {

      result = ssl3_md5 (i, secret, secret_len, rnd, rnd_len, digest);
      if (result < 0)
        {
          gnutls_assert ();
          return result;
        }

      if ((1 + i) * block < ret_bytes)
        {
          copy = block;
        }
      else
        {
          copy = ret_bytes - (i) * block;
        }

      memcpy (&ret[i * block], digest, copy);
    }

  return 0;
}
