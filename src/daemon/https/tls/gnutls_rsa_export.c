/*
 * Copyright (C) 2002, 2003, 2004, 2005 Free Software Foundation
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

/* This file contains code for RSA temporary keys. These keys are
 * only used in export cipher suites.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <gnutls_rsa_export.h>
#include "debug.h"
/* x509 */
#include "x509.h"
#include "privkey.h"

/* This function takes a number of bits and returns a supported
 * number of bits. Ie a number of bits that we have a prime in the
 * dh_primes structure.
 */

#define MAX_SUPPORTED_BITS 512

/* returns e and m, depends on the requested bits.
 * We only support limited key sizes.
 */
const mpi_t *
_gnutls_rsa_params_to_mpi (mhd_gtls_rsa_params_t rsa_params)
{
  if (rsa_params == NULL)
    {
      return NULL;
    }

  return rsa_params->params;

}

/* resarr will contain: modulus(0), public exponent(1), private exponent(2),
 * prime1 - p (3), prime2 - q(4), u (5).
 */
int
_gnutls_rsa_generate_params (mpi_t * resarr, int *resarr_len, int bits)
{

  int ret;
  gcry_sexp_t parms, key, list;

  ret = gcry_sexp_build (&parms, NULL, "(genkey(rsa(nbits %d)))", bits);
  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* generate the RSA key */
  ret = gcry_pk_genkey (&key, parms);
  gcry_sexp_release (parms);

  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  list = gcry_sexp_find_token (key, "n", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[0] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "e", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[1] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "d", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[2] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "p", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[3] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);


  list = gcry_sexp_find_token (key, "q", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[4] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);


  list = gcry_sexp_find_token (key, "u", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[5] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  gcry_sexp_release (key);

  _gnutls_dump_mpi ("n: ", resarr[0]);
  _gnutls_dump_mpi ("e: ", resarr[1]);
  _gnutls_dump_mpi ("d: ", resarr[2]);
  _gnutls_dump_mpi ("p: ", resarr[3]);
  _gnutls_dump_mpi ("q: ", resarr[4]);
  _gnutls_dump_mpi ("u: ", resarr[5]);

  *resarr_len = 6;

  return 0;

}

/**
  * MHD_gnutls_rsa_params_init - This function will initialize the temporary RSA parameters
  * @rsa_params: Is a structure that will hold the parameters
  *
  * This function will initialize the temporary RSA parameters structure.
  *
  **/
int
MHD_gnutls_rsa_params_init (mhd_gtls_rsa_params_t * rsa_params)
{
  int ret;

  ret = gnutls_x509_privkey_init (rsa_params);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  (*rsa_params)->crippled = 1;

  return 0;
}

/**
  * MHD_gnutls_rsa_params_deinit - This function will deinitialize the RSA parameters
  * @rsa_params: Is a structure that holds the parameters
  *
  * This function will deinitialize the RSA parameters structure.
  *
  **/
void
MHD_gnutls_rsa_params_deinit (mhd_gtls_rsa_params_t rsa_params)
{
  gnutls_x509_privkey_deinit (rsa_params);
}

/**
  * MHD_gnutls_rsa_params_generate2 - This function will generate temporary RSA parameters
  * @params: The structure where the parameters will be stored
  * @bits: is the prime's number of bits
  *
  * This function will generate new temporary RSA parameters for use in
  * RSA-EXPORT ciphersuites.  This function is normally slow.
  *
  * Note that if the parameters are to be used in export cipher suites the
  * bits value should be 512 or less.
  * Also note that the generation of new RSA parameters is only useful
  * to servers. Clients use the parameters sent by the server, thus it's
  * no use calling this in client side.
  *
  **/
int
MHD_gnutls_rsa_params_generate2 (mhd_gtls_rsa_params_t params, unsigned int bits)
{
  return gnutls_x509_privkey_generate (params, MHD_GNUTLS_PK_RSA, bits, 0);
}
