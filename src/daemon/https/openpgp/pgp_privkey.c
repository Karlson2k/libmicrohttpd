/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS-EXTRA.
 *
 * GNUTLS-EXTRA is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *               
 * GNUTLS-EXTRA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *                               
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Functions on OpenPGP privkey parsing
 */

#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include "openpgp.h"
#include <gnutls_openpgp.h>
#include <gnutls_cert.h>
/* x509 */
#include <rfc2818.h>

/**
 * gnutls_openpgp_privkey_init - This function initializes a gnutls_openpgp_privkey_t structure
 * @key: The structure to be initialized
 *
 * This function will initialize an OpenPGP key structure. 
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_openpgp_privkey_init (gnutls_openpgp_privkey_t * key)
{
  *key = gnutls_calloc (1, sizeof (gnutls_openpgp_privkey_int));

  if (*key)
    return 0;                   /* success */
  return GNUTLS_E_MEMORY_ERROR;
}

/**
 * gnutls_openpgp_privkey_deinit - This function deinitializes memory used by a gnutls_openpgp_privkey_t structure
 * @key: The structure to be initialized
 *
 * This function will deinitialize a key structure. 
 *
 **/
void
gnutls_openpgp_privkey_deinit (gnutls_openpgp_privkey_t key)
{
  if (!key)
    return;

  _gnutls_gkey_deinit (&key->pkey);
  gnutls_free (key);
}

/**
 * gnutls_openpgp_privkey_import - This function will import a RAW or BASE64 encoded key
 * @key: The structure to store the parsed key.
 * @data: The RAW or BASE64 encoded key.
 * @format: One of gnutls_openpgp_crt_fmt_t elements.
 * @pass: Unused for now
 * @flags: should be zero
 *
 * This function will convert the given RAW or Base64 encoded key
 * to the native gnutls_openpgp_privkey_t format. The output will be stored in 'key'.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_openpgp_privkey_import (gnutls_openpgp_privkey_t key,
                               const gnutls_datum_t * data,
                               gnutls_openpgp_crt_fmt_t format,
                               const char *pass, unsigned int flags)
{
  int rc;

  rc = _gnutls_openpgp_raw_privkey_to_gkey (&key->pkey, data, format);
  if (rc)
    {
      gnutls_assert ();
      return rc;
    }

  return 0;
}


/**
 * gnutls_openpgp_privkey_get_pk_algorithm - This function returns the key's PublicKey algorithm
 * @key: is an OpenPGP key
 * @bits: if bits is non null it will hold the size of the parameters' in bits
 *
 * This function will return the public key algorithm of an OpenPGP
 * certificate.
 *
 * If bits is non null, it should have enough size to hold the parameters
 * size in bits. For RSA the bits returned is the modulus. 
 * For DSA the bits returned are of the public exponent.
 *
 * Returns a member of the GNUTLS_PKAlgorithm enumeration on success,
 * or a negative value on error.
 *
 **/
gnutls_pk_algorithm_t
gnutls_openpgp_privkey_get_pk_algorithm (gnutls_openpgp_privkey_t key,
                                         unsigned int *bits)
{
  int pk = key->pkey.pk_algorithm;

  if (bits)
    {
      *bits = 0;
      if (pk == GNUTLS_PK_RSA)
        *bits = _gnutls_mpi_get_nbits (key->pkey.params[0]);
    }

  return pk;
}
