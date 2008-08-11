/*
 * Copyright (C) 2000, 2004, 2005 Free Software Foundation
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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_cipher_int.h>
#include <gnutls_datum.h>

cipher_hd_t
mhd_gtls_cipher_init (gnutls_cipher_algorithm_t cipher,
                     const gnutls_datum_t * key, const gnutls_datum_t * iv)
{
  cipher_hd_t ret = NULL;
  int err = GC_INVALID_CIPHER;  /* doesn't matter */

  switch (cipher)
    {
    case MHD_GNUTLS_CIPHER_AES_128_CBC:
      err = gc_cipher_open (GC_AES128, GC_CBC, &ret);
      break;

    case MHD_GNUTLS_CIPHER_AES_256_CBC:
      err = gc_cipher_open (GC_AES256, GC_CBC, &ret);
      break;

    case MHD_GNUTLS_CIPHER_3DES_CBC:
      err = gc_cipher_open (GC_3DES, GC_CBC, &ret);
      break;

    case MHD_GNUTLS_CIPHER_DES_CBC:
      err = gc_cipher_open (GC_DES, GC_CBC, &ret);
      break;

    case MHD_GNUTLS_CIPHER_ARCFOUR_128:
      err = gc_cipher_open (GC_ARCFOUR128, GC_STREAM, &ret);
      break;

    case MHD_GNUTLS_CIPHER_ARCFOUR_40:
      err = gc_cipher_open (GC_ARCFOUR40, GC_STREAM, &ret);
      break;

    case MHD_GNUTLS_CIPHER_RC2_40_CBC:
      err = gc_cipher_open (GC_ARCTWO40, GC_CBC, &ret);
      break;

#ifdef	ENABLE_CAMELLIA
    case MHD_GNUTLS_CIPHER_CAMELLIA_128_CBC:
      err = gc_cipher_open (GC_CAMELLIA128, GC_CBC, &ret);
      break;

    case MHD_GNUTLS_CIPHER_CAMELLIA_256_CBC:
      err = gc_cipher_open (GC_CAMELLIA256, GC_CBC, &ret);
      break;
#endif

    default:
      return NULL;
    }

  if (err == 0)
    {
      gc_cipher_setkey (ret, key->size, key->data);
      if (iv->data != NULL && iv->size > 0)
        gc_cipher_setiv (ret, iv->size, iv->data);
    }
  else if (cipher != MHD_GNUTLS_CIPHER_NULL)
    {
      gnutls_assert ();
      _gnutls_x509_log ("Crypto cipher[%d] error: %d\n", cipher, err);
      /* FIXME: gc_strerror */
    }

  return ret;
}

int
mhd_gtls_cipher_encrypt (cipher_hd_t handle, void *text, int textlen)
{
  if (handle != GNUTLS_CIPHER_FAILED)
    {
      if (gc_cipher_encrypt_inline (handle, textlen, text) != 0)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
    }
  return 0;
}

int
mhd_gtls_cipher_decrypt (cipher_hd_t handle, void *ciphertext,
                        int ciphertextlen)
{
  if (handle != GNUTLS_CIPHER_FAILED)
    {
      if (gc_cipher_decrypt_inline (handle, ciphertextlen, ciphertext) != 0)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
    }
  return 0;
}

void
mhd_gnutls_cipher_deinit (cipher_hd_t handle)
{
  if (handle != GNUTLS_CIPHER_FAILED)
    {
      gc_cipher_close (handle);
    }
}
