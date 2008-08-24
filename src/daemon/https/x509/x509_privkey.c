/*
 * Copyright (C) 2003, 2004, 2005, 2007 Free Software Foundation
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
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <gnutls_rsa_export.h>
#include <gnutls_sig.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <x509.h>
#include <dn.h>
#include <mpi.h>
#include <extensions.h>
#include <sign.h>
#include <dsa.h>
#include <verify.h>

static int _gnutls_asn1_encode_rsa (ASN1_TYPE * c2, mpi_t * params);
int _gnutls_asn1_encode_dsa (ASN1_TYPE * c2, mpi_t * params);

/* remove this when libgcrypt can handle the PKCS #1 coefficients from
 * rsa keys
 */
#define CALC_COEFF 1

/**
 * gnutls_x509_privkey_init - This function initializes a gnutls_crl structure
 * @key: The structure to be initialized
 *
 * This function will initialize an private key structure.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_x509_privkey_init (gnutls_x509_privkey_t * key)
{
  *key = gnutls_calloc (1, sizeof (gnutls_x509_privkey_int));

  if (*key)
    {
      (*key)->key = ASN1_TYPE_EMPTY;
      (*key)->pk_algorithm = MHD_GNUTLS_PK_UNKNOWN;
      return 0;                 /* success */
    }

  return GNUTLS_E_MEMORY_ERROR;
}

/**
 * gnutls_x509_privkey_deinit - This function deinitializes memory used by a gnutls_x509_privkey_t structure
 * @key: The structure to be initialized
 *
 * This function will deinitialize a private key structure.
 *
 **/
void
gnutls_x509_privkey_deinit (gnutls_x509_privkey_t key)
{
  int i;

  if (!key)
    return;

  for (i = 0; i < key->params_size; i++)
    {
      mhd_gtls_mpi_release (&key->params[i]);
    }

  asn1_delete_structure (&key->key);
  gnutls_free (key);
}

/**
 * gnutls_x509_privkey_cpy - This function copies a private key
 * @dst: The destination key, which should be initialized.
 * @src: The source key
 *
 * This function will copy a private key from source to destination key.
 *
 **/
int
gnutls_x509_privkey_cpy (gnutls_x509_privkey_t dst, gnutls_x509_privkey_t src)
{
  int i, ret;

  if (!src || !dst)
    return GNUTLS_E_INVALID_REQUEST;

  for (i = 0; i < src->params_size; i++)
    {
      dst->params[i] = _gnutls_mpi_copy (src->params[i]);
      if (dst->params[i] == NULL)
        return GNUTLS_E_MEMORY_ERROR;
    }

  dst->params_size = src->params_size;
  dst->pk_algorithm = src->pk_algorithm;
  dst->crippled = src->crippled;

  if (!src->crippled)
    {
      switch (dst->pk_algorithm)
        {
        case MHD_GNUTLS_PK_RSA:
          ret = _gnutls_asn1_encode_rsa (&dst->key, dst->params);
          if (ret < 0)
            {
              gnutls_assert ();
              return ret;
            }
          break;
        default:
          gnutls_assert ();
          return GNUTLS_E_INVALID_REQUEST;
        }
    }

  return 0;
}

/* Converts an RSA PKCS#1 key to
 * an internal structure (gnutls_private_key)
 */
ASN1_TYPE
_gnutls_privkey_decode_pkcs1_rsa_key (const gnutls_datum_t * raw_key,
                                      gnutls_x509_privkey_t pkey)
{
  int result;
  ASN1_TYPE pkey_asn;

  if ((result = asn1_create_element (_gnutls_get_gnutls_asn (),
                                     "GNUTLS.RSAPrivateKey",
                                     &pkey_asn)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return NULL;
    }

  if ((sizeof (pkey->params) / sizeof (mpi_t)) < RSA_PRIVATE_PARAMS)
    {
      gnutls_assert ();
      /* internal error. Increase the mpi_ts in params */
      return NULL;
    }

  result = asn1_der_decoding (&pkey_asn, raw_key->data, raw_key->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (pkey_asn, "modulus", &pkey->params[0]))
      < 0)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (pkey_asn, "publicExponent",
                                       &pkey->params[1])) < 0)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (pkey_asn, "privateExponent",
                                       &pkey->params[2])) < 0)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (pkey_asn, "prime1", &pkey->params[3]))
      < 0)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (pkey_asn, "prime2", &pkey->params[4]))
      < 0)
    {
      gnutls_assert ();
      goto error;
    }

#ifdef CALC_COEFF
  /* Calculate the coefficient. This is because the gcrypt
   * library is uses the p,q in the reverse order.
   */
  pkey->params[5] =
    _gnutls_mpi_snew (_gnutls_mpi_get_nbits (pkey->params[0]));

  if (pkey->params[5] == NULL)
    {
      gnutls_assert ();
      goto error;
    }

  _gnutls_mpi_invm (pkey->params[5], pkey->params[3], pkey->params[4]);
  /* p, q */
#else
  if ((result = _gnutls_x509_read_int (pkey_asn, "coefficient",
                                       &pkey->params[5])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
#endif
  pkey->params_size = 6;

  return pkey_asn;

error:asn1_delete_structure (&pkey_asn);
  mhd_gtls_mpi_release (&pkey->params[0]);
  mhd_gtls_mpi_release (&pkey->params[1]);
  mhd_gtls_mpi_release (&pkey->params[2]);
  mhd_gtls_mpi_release (&pkey->params[3]);
  mhd_gtls_mpi_release (&pkey->params[4]);
  mhd_gtls_mpi_release (&pkey->params[5]);
  return NULL;

}

static ASN1_TYPE
decode_dsa_key (const gnutls_datum_t * raw_key, gnutls_x509_privkey_t pkey)
{
  int result;
  ASN1_TYPE dsa_asn;

  if ((result = asn1_create_element (_gnutls_get_gnutls_asn (),
                                     "GNUTLS.DSAPrivateKey",
                                     &dsa_asn)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return NULL;
    }

  if ((sizeof (pkey->params) / sizeof (mpi_t)) < DSA_PRIVATE_PARAMS)
    {
      gnutls_assert ();
      /* internal error. Increase the mpi_ts in params */
      return NULL;
    }

  result = asn1_der_decoding (&dsa_asn, raw_key->data, raw_key->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (dsa_asn, "p", &pkey->params[0])) < 0)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (dsa_asn, "q", &pkey->params[1])) < 0)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (dsa_asn, "g", &pkey->params[2])) < 0)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result = _gnutls_x509_read_int (dsa_asn, "Y", &pkey->params[3])) < 0)
    {
      gnutls_assert ();
      goto error;
    }

  if ((result =
       _gnutls_x509_read_int (dsa_asn, "priv", &pkey->params[4])) < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pkey->params_size = 5;

  return dsa_asn;

error:asn1_delete_structure (&dsa_asn);
  mhd_gtls_mpi_release (&pkey->params[0]);
  mhd_gtls_mpi_release (&pkey->params[1]);
  mhd_gtls_mpi_release (&pkey->params[2]);
  mhd_gtls_mpi_release (&pkey->params[3]);
  mhd_gtls_mpi_release (&pkey->params[4]);
  return NULL;

}

#define PEM_KEY_DSA "DSA PRIVATE KEY"
#define PEM_KEY_RSA "RSA PRIVATE KEY"

/**
 * gnutls_x509_privkey_import - This function will import a DER or PEM encoded key
 * @key: The structure to store the parsed key
 * @data: The DER or PEM encoded certificate.
 * @format: One of DER or PEM
 *
 * This function will convert the given DER or PEM encoded key
 * to the native gnutls_x509_privkey_t format. The output will be stored in @key .
 *
 * If the key is PEM encoded it should have a header of "RSA PRIVATE KEY", or
 * "DSA PRIVATE KEY".
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_x509_privkey_import (gnutls_x509_privkey_t key,
                            const gnutls_datum_t * data,
                            gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  gnutls_datum_t _data;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _data.data = data->data;
  _data.size = data->size;

  key->pk_algorithm = MHD_GNUTLS_PK_UNKNOWN;

  /* If the Certificate is in PEM format then decode it */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      /* Try the first header */
      result
        = _gnutls_fbase64_decode (PEM_KEY_RSA, data->data, data->size, &out);
      key->pk_algorithm = MHD_GNUTLS_PK_RSA;

      // TODO rm
//      if (result == GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR)
//        {
//          /* try for the second header */
//          result = _gnutls_fbase64_decode(PEM_KEY_DSA, data->data, data->size,
//          &out);
//          key->pk_algorithm = GNUTLS_PK_DSA;
//
//          if (result <= 0)
//            {
//              if (result == 0)
//                result = GNUTLS_E_INTERNAL_ERROR;
//              gnutls_assert ();
//              return result;
//            }
//        }

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }

  if (key->pk_algorithm == MHD_GNUTLS_PK_RSA)
    {
      key->key = _gnutls_privkey_decode_pkcs1_rsa_key (&_data, key);
      if (key->key == NULL)
        gnutls_assert ();
    }
  else
    {
      /* Try decoding with both, and accept the one that succeeds. */
      key->pk_algorithm = MHD_GNUTLS_PK_RSA;
      key->key = _gnutls_privkey_decode_pkcs1_rsa_key (&_data, key);

      // TODO rm
//      if (key->key == NULL)
//        {
//          key->pk_algorithm = GNUTLS_PK_DSA;
//          key->key = decode_dsa_key(&_data, key);
//          if (key->key == NULL)
//            gnutls_assert();
//        }
    }

  if (key->key == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_ASN1_DER_ERROR;
      key->pk_algorithm = MHD_GNUTLS_PK_UNKNOWN;
      return result;
    }

  if (need_free)
    _gnutls_free_datum (&_data);

  /* The key has now been decoded.
   */

  return 0;
}

#define FREE_RSA_PRIVATE_PARAMS for (i=0;i<RSA_PRIVATE_PARAMS;i++) \
		mhd_gtls_mpi_release(&key->params[i])
#define FREE_DSA_PRIVATE_PARAMS for (i=0;i<DSA_PRIVATE_PARAMS;i++) \
		mhd_gtls_mpi_release(&key->params[i])

/**
 * gnutls_x509_privkey_import_rsa_raw - This function will import a raw RSA key
 * @key: The structure to store the parsed key
 * @m: holds the modulus
 * @e: holds the public exponent
 * @d: holds the private exponent
 * @p: holds the first prime (p)
 * @q: holds the second prime (q)
 * @u: holds the coefficient
 *
 * This function will convert the given RSA raw parameters
 * to the native gnutls_x509_privkey_t format. The output will be stored in @key.
 * 
 **/
int
gnutls_x509_privkey_import_rsa_raw (gnutls_x509_privkey_t key,
                                    const gnutls_datum_t * m,
                                    const gnutls_datum_t * e,
                                    const gnutls_datum_t * d,
                                    const gnutls_datum_t * p,
                                    const gnutls_datum_t * q,
                                    const gnutls_datum_t * u)
{
  int i = 0, ret;
  size_t siz = 0;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  siz = m->size;
  if (mhd_gtls_mpi_scan_nz (&key->params[0], m->data, &siz))
    {
      gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = e->size;
  if (mhd_gtls_mpi_scan_nz (&key->params[1], e->data, &siz))
    {
      gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = d->size;
  if (mhd_gtls_mpi_scan_nz (&key->params[2], d->data, &siz))
    {
      gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = p->size;
  if (mhd_gtls_mpi_scan_nz (&key->params[3], p->data, &siz))
    {
      gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = q->size;
  if (mhd_gtls_mpi_scan_nz (&key->params[4], q->data, &siz))
    {
      gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

#ifdef CALC_COEFF
  key->params[5] = _gnutls_mpi_snew (_gnutls_mpi_get_nbits (key->params[0]));

  if (key->params[5] == NULL)
    {
      gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MEMORY_ERROR;
    }

  _gnutls_mpi_invm (key->params[5], key->params[3], key->params[4]);
#else
  siz = u->size;
  if (mhd_gtls_mpi_scan_nz (&key->params[5], u->data, &siz))
    {
      gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }
#endif

  if (!key->crippled)
    {
      ret = _gnutls_asn1_encode_rsa (&key->key, key->params);
      if (ret < 0)
        {
          gnutls_assert ();
          FREE_RSA_PRIVATE_PARAMS;
          return ret;
        }
    }

  key->params_size = RSA_PRIVATE_PARAMS;
  key->pk_algorithm = MHD_GNUTLS_PK_RSA;

  return 0;

}

/**
 * gnutls_x509_privkey_get_pk_algorithm - This function returns the key's PublicKey algorithm
 * @key: should contain a gnutls_x509_privkey_t structure
 *
 * This function will return the public key algorithm of a private
 * key.
 *
 * Returns a member of the enum MHD_GNUTLS_PublicKeyAlgorithm enumeration on success,
 * or a negative value on error.
 *
 **/
int
gnutls_x509_privkey_get_pk_algorithm (gnutls_x509_privkey_t key)
{
  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return key->pk_algorithm;
}

/**
 * gnutls_x509_privkey_export - This function will export the private key
 * @key: Holds the key
 * @format: the format of output params. One of PEM or DER.
 * @output_data: will contain a private key PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the private key to a PKCS1 structure for
 * RSA keys, or an integer sequence for DSA keys. The DSA keys are in
 * the same format with the parameters used by openssl.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN RSA PRIVATE KEY".
 *
 * Return value: In case of failure a negative value will be
 *   returned, and 0 on success.
 *
 **/
int
gnutls_x509_privkey_export (gnutls_x509_privkey_t key,
                            gnutls_x509_crt_fmt_t format,
                            void *output_data, size_t * output_data_size)
{
  char *msg;
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (key->pk_algorithm == MHD_GNUTLS_PK_RSA)
    msg = PEM_KEY_RSA;
  else
    msg = NULL;

  if (key->crippled)
    {                           /* encode the parameters on the fly.
                                 */
      switch (key->pk_algorithm)
        {
        case MHD_GNUTLS_PK_RSA:
          ret = _gnutls_asn1_encode_rsa (&key->key, key->params);
          if (ret < 0)
            {
              gnutls_assert ();
              return ret;
            }
          break;
        default:
          gnutls_assert ();
          return GNUTLS_E_INVALID_REQUEST;
        }
    }

  return _gnutls_x509_export_int (key->key, format, msg, output_data,
                                  output_data_size);
}

/**
 * gnutls_x509_privkey_export_rsa_raw - This function will export the RSA private key
 * @key: a structure that holds the rsa parameters
 * @m: will hold the modulus
 * @e: will hold the public exponent
 * @d: will hold the private exponent
 * @p: will hold the first prime (p)
 * @q: will hold the second prime (q)
 * @u: will hold the coefficient
 *
 * This function will export the RSA private key's parameters found in the given
 * structure. The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 * 
 **/
int
gnutls_x509_privkey_export_rsa_raw (gnutls_x509_privkey_t key,
                                    gnutls_datum_t * m,
                                    gnutls_datum_t * e,
                                    gnutls_datum_t * d,
                                    gnutls_datum_t * p,
                                    gnutls_datum_t * q, gnutls_datum_t * u)
{
  int ret;
  mpi_t coeff = NULL;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  m->data = e->data = d->data = p->data = q->data = u->data = NULL;
  m->size = e->size = d->size = p->size = q->size = u->size = 0;

  ret = mhd_gtls_mpi_dprint (m, key->params[0]);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* E */
  ret = mhd_gtls_mpi_dprint (e, key->params[1]);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* D */
  ret = mhd_gtls_mpi_dprint (d, key->params[2]);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* P */
  ret = mhd_gtls_mpi_dprint (p, key->params[3]);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  /* Q */
  ret = mhd_gtls_mpi_dprint (q, key->params[4]);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

#ifdef CALC_COEFF
  coeff = _gnutls_mpi_snew (_gnutls_mpi_get_nbits (key->params[0]));

  if (coeff == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_MEMORY_ERROR;
      goto error;
    }

  _gnutls_mpi_invm (coeff, key->params[4], key->params[3]);
  ret = mhd_gtls_mpi_dprint (u, coeff);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }

  mhd_gtls_mpi_release (&coeff);
#else
  /* U */
  ret = mhd_gtls_mpi_dprint (u, key->params[5]);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
#endif

  return 0;

error:_gnutls_free_datum (m);
  _gnutls_free_datum (d);
  _gnutls_free_datum (e);
  _gnutls_free_datum (p);
  _gnutls_free_datum (q);
  mhd_gtls_mpi_release (&coeff);

  return ret;
}

/**
 * gnutls_x509_privkey_export_dsa_raw - This function will export the DSA private key
 * @params: a structure that holds the DSA parameters
 * @p: will hold the p
 * @q: will hold the q
 * @g: will hold the g
 * @y: will hold the y
 * @x: will hold the x
 *
 * This function will export the DSA private key's parameters found in the given
 * structure. The new parameters will be allocated using
 * gnutls_malloc() and will be stored in the appropriate datum.
 * 
 **/
int
gnutls_x509_privkey_export_dsa_raw (gnutls_x509_privkey_t key,
                                    gnutls_datum_t * p,
                                    gnutls_datum_t * q,
                                    gnutls_datum_t * g,
                                    gnutls_datum_t * y, gnutls_datum_t * x)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* P */
  ret = mhd_gtls_mpi_dprint (p, key->params[0]);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* Q */
  ret = mhd_gtls_mpi_dprint (q, key->params[1]);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (p);
      return ret;
    }

  /* G */
  ret = mhd_gtls_mpi_dprint (g, key->params[2]);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (p);
      _gnutls_free_datum (q);
      return ret;
    }

  /* Y */
  ret = mhd_gtls_mpi_dprint (y, key->params[3]);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (p);
      _gnutls_free_datum (g);
      _gnutls_free_datum (q);
      return ret;
    }

  /* X */
  ret = mhd_gtls_mpi_dprint (x, key->params[4]);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (y);
      _gnutls_free_datum (p);
      _gnutls_free_datum (g);
      _gnutls_free_datum (q);
      return ret;
    }

  return 0;
}

/* Encodes the RSA parameters into an ASN.1 RSA private key structure.
 */
static int
_gnutls_asn1_encode_rsa (ASN1_TYPE * c2, mpi_t * params)
{
  int result, i;
  size_t size[8], total;
  opaque *m_data, *pube_data, *prie_data;
  opaque *p1_data, *p2_data, *u_data, *exp1_data, *exp2_data;
  opaque *all_data = NULL, *p;
  mpi_t exp1 = NULL, exp2 = NULL, q1 = NULL, p1 = NULL, u = NULL;
  opaque null = '\0';

  /* Read all the sizes */
  total = 0;
  for (i = 0; i < 5; i++)
    {
      mhd_gtls_mpi_print_lz (NULL, &size[i], params[i]);
      total += size[i];
    }

  /* Now generate exp1 and exp2
   */
  exp1 = _gnutls_mpi_salloc_like (params[0]);   /* like modulus */
  if (exp1 == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  exp2 = _gnutls_mpi_salloc_like (params[0]);
  if (exp2 == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  q1 = _gnutls_mpi_salloc_like (params[4]);
  if (q1 == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  p1 = _gnutls_mpi_salloc_like (params[3]);
  if (p1 == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  u = _gnutls_mpi_salloc_like (params[3]);
  if (u == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  _gnutls_mpi_invm (u, params[4], params[3]);
  /* inverse of q mod p */
  mhd_gtls_mpi_print_lz (NULL, &size[5], u);
  total += size[5];

  _gnutls_mpi_sub_ui (p1, params[3], 1);
  _gnutls_mpi_sub_ui (q1, params[4], 1);

  _gnutls_mpi_mod (exp1, params[2], p1);
  _gnutls_mpi_mod (exp2, params[2], q1);

  /* calculate exp's size */
  mhd_gtls_mpi_print_lz (NULL, &size[6], exp1);
  total += size[6];

  mhd_gtls_mpi_print_lz (NULL, &size[7], exp2);
  total += size[7];

  /* Encoding phase.
   * allocate data enough to hold everything
   */
  all_data = gnutls_secure_malloc (total);
  if (all_data == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  p = all_data;
  m_data = p;
  p += size[0];
  pube_data = p;
  p += size[1];
  prie_data = p;
  p += size[2];
  p1_data = p;
  p += size[3];
  p2_data = p;
  p += size[4];
  u_data = p;
  p += size[5];
  exp1_data = p;
  p += size[6];
  exp2_data = p;

  mhd_gtls_mpi_print_lz (m_data, &size[0], params[0]);
  mhd_gtls_mpi_print_lz (pube_data, &size[1], params[1]);
  mhd_gtls_mpi_print_lz (prie_data, &size[2], params[2]);
  mhd_gtls_mpi_print_lz (p1_data, &size[3], params[3]);
  mhd_gtls_mpi_print_lz (p2_data, &size[4], params[4]);
  mhd_gtls_mpi_print_lz (u_data, &size[5], u);
  mhd_gtls_mpi_print_lz (exp1_data, &size[6], exp1);
  mhd_gtls_mpi_print_lz (exp2_data, &size[7], exp2);

  /* Ok. Now we have the data. Create the asn1 structures
   */

  if ((result =
       asn1_create_element (_gnutls_get_gnutls_asn (), "GNUTLS.RSAPrivateKey",
                            c2)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  /* Write PRIME 
   */
  if ((result = asn1_write_value (*c2, "modulus", m_data, size[0]))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "publicExponent", pube_data, size[1]))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "privateExponent", prie_data, size[2]))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "prime1", p1_data, size[3]))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "prime2", p2_data, size[4]))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "exponent1", exp1_data, size[6]))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "exponent2", exp2_data, size[7]))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "coefficient", u_data, size[5]))
      != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  mhd_gtls_mpi_release (&exp1);
  mhd_gtls_mpi_release (&exp2);
  mhd_gtls_mpi_release (&q1);
  mhd_gtls_mpi_release (&p1);
  mhd_gtls_mpi_release (&u);
  gnutls_free (all_data);

  if ((result = asn1_write_value (*c2, "otherPrimeInfos",
                                  NULL, 0)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "version", &null, 1)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  return 0;

cleanup:mhd_gtls_mpi_release (&u);
  mhd_gtls_mpi_release (&exp1);
  mhd_gtls_mpi_release (&exp2);
  mhd_gtls_mpi_release (&q1);
  mhd_gtls_mpi_release (&p1);
  asn1_delete_structure (c2);
  gnutls_free (all_data);

  return result;
}

/* Encodes the DSA parameters into an ASN.1 DSAPrivateKey structure.
 */
int
_gnutls_asn1_encode_dsa (ASN1_TYPE * c2, mpi_t * params)
{
  int result, i;
  size_t size[DSA_PRIVATE_PARAMS], total;
  opaque *p_data, *q_data, *g_data, *x_data, *y_data;
  opaque *all_data = NULL, *p;
  opaque null = '\0';

  /* Read all the sizes */
  total = 0;
  for (i = 0; i < DSA_PRIVATE_PARAMS; i++)
    {
      mhd_gtls_mpi_print_lz (NULL, &size[i], params[i]);
      total += size[i];
    }

  /* Encoding phase.
   * allocate data enough to hold everything
   */
  all_data = gnutls_secure_malloc (total);
  if (all_data == NULL)
    {
      gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  p = all_data;
  p_data = p;
  p += size[0];
  q_data = p;
  p += size[1];
  g_data = p;
  p += size[2];
  y_data = p;
  p += size[3];
  x_data = p;

  mhd_gtls_mpi_print_lz (p_data, &size[0], params[0]);
  mhd_gtls_mpi_print_lz (q_data, &size[1], params[1]);
  mhd_gtls_mpi_print_lz (g_data, &size[2], params[2]);
  mhd_gtls_mpi_print_lz (y_data, &size[3], params[3]);
  mhd_gtls_mpi_print_lz (x_data, &size[4], params[4]);

  /* Ok. Now we have the data. Create the asn1 structures
   */

  if ((result =
       asn1_create_element (_gnutls_get_gnutls_asn (), "GNUTLS.DSAPrivateKey",
                            c2)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  /* Write PRIME 
   */
  if ((result = asn1_write_value (*c2, "p", p_data, size[0])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "q", q_data, size[1])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "g", g_data, size[2])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = asn1_write_value (*c2, "Y", y_data, size[3])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result =
       asn1_write_value (*c2, "priv", x_data, size[4])) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  gnutls_free (all_data);

  if ((result = asn1_write_value (*c2, "version", &null, 1)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  return 0;

cleanup:asn1_delete_structure (c2);
  gnutls_free (all_data);

  return result;
}

/**
 * gnutls_x509_privkey_generate - This function will generate a private key
 * @key: should contain a gnutls_x509_privkey_t structure
 * @algo: is one of RSA or DSA.
 * @bits: the size of the modulus
 * @flags: unused for now. Must be 0.
 *
 * This function will generate a random private key. Note that
 * this function must be called on an empty private key. 
 *
 * Returns 0 on success or a negative value on error.
 *
 **/
int
gnutls_x509_privkey_generate (gnutls_x509_privkey_t key,
                              enum MHD_GNUTLS_PublicKeyAlgorithm algo,
                              unsigned int bits, unsigned int flags)
{
  int ret, params_len;
  int i;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  switch (algo)
    {
    case MHD_GNUTLS_PK_RSA:
      ret = _gnutls_rsa_generate_params (key->params, &params_len, bits);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      if (!key->crippled)
        {
          ret = _gnutls_asn1_encode_rsa (&key->key, key->params);
          if (ret < 0)
            {
              gnutls_assert ();
              goto cleanup;
            }
        }

      key->params_size = params_len;
      key->pk_algorithm = MHD_GNUTLS_PK_RSA;

      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return 0;

cleanup:key->pk_algorithm = MHD_GNUTLS_PK_UNKNOWN;
  key->params_size = 0;
  for (i = 0; i < params_len; i++)
    mhd_gtls_mpi_release (&key->params[i]);

  return ret;
}

/**
 * gnutls_x509_privkey_get_key_id - Return unique ID of the key's parameters
 * @key: Holds the key
 * @flags: should be 0 for now
 * @output_data: will contain the key ID
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will return a unique ID the depends on the public key
 * parameters. This ID can be used in checking whether a certificate
 * corresponds to the given key.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.  The output will normally be a SHA-1 hash output,
 * which is 20 bytes.
 *
 * Return value: In case of failure a negative value will be
 *   returned, and 0 on success.
 *
 **/
int
gnutls_x509_privkey_get_key_id (gnutls_x509_privkey_t key,
                                unsigned int flags,
                                unsigned char *output_data,
                                size_t * output_data_size)
{
  int result;
  GNUTLS_HASH_HANDLE hd;
  gnutls_datum_t der = { NULL,
    0
  };

  if (key == NULL || key->crippled)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (*output_data_size < 20)
    {
      gnutls_assert ();
      *output_data_size = 20;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  if (key->pk_algorithm == MHD_GNUTLS_PK_RSA)
    {
      result = _gnutls_x509_write_rsa_params (key->params, key->params_size,
                                              &der);
      if (result < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }
    }
  else
    return GNUTLS_E_INTERNAL_ERROR;

  hd = mhd_gtls_hash_init (MHD_GNUTLS_MAC_SHA1);
  if (hd == GNUTLS_HASH_FAILED)
    {
      gnutls_assert ();
      result = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  mhd_gnutls_hash (hd, der.data, der.size);

  mhd_gnutls_hash_deinit (hd, output_data);
  *output_data_size = 20;

  result = 0;

cleanup:

  _gnutls_free_datum (&der);
  return result;
}

#ifdef ENABLE_PKI

/**
 * gnutls_x509_privkey_sign_data - This function will sign the given data using the private key params
 * @key: Holds the key
 * @digest: should be MD5 or SHA1
 * @flags: should be 0 for now
 * @data: holds the data to be signed
 * @signature: will contain the signature
 * @signature_size: holds the size of signature (and will be replaced
 *   by the new size)
 *
 * This function will sign the given data using a signature algorithm
 * supported by the private key. Signature algorithms are always used
 * together with a hash functions.  Different hash functions may be
 * used for the RSA algorithm, but only SHA-1 for the DSA keys.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *signature_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * In case of failure a negative value will be returned, and
 * 0 on success.
 *
 **/
int
gnutls_x509_privkey_sign_data (gnutls_x509_privkey_t key,
                               enum MHD_GNUTLS_HashAlgorithm digest,
                               unsigned int flags,
                               const gnutls_datum_t * data,
                               void *signature, size_t * signature_size)
{
  int result;
  gnutls_datum_t sig = { NULL, 0 };

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_sign (data, digest, key, &sig);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  if (*signature_size < sig.size)
    {
      *signature_size = sig.size;
      _gnutls_free_datum (&sig);
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  *signature_size = sig.size;
  memcpy (signature, sig.data, sig.size);

  _gnutls_free_datum (&sig);

  return 0;
}

/**
 * gnutls_x509_privkey_sign_hash - This function will sign the given data using the private key params
 * @key: Holds the key
 * @hash: holds the data to be signed
 * @signature: will contain newly allocated signature
 *
 * This function will sign the given hash using the private key.
 *
 * Return value: In case of failure a negative value will be returned,
 * and 0 on success.
 **/
int
gnutls_x509_privkey_sign_hash (gnutls_x509_privkey_t key,
                               const gnutls_datum_t * hash,
                               gnutls_datum_t * signature)
{
  int result;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = mhd_gtls_sign (key->pk_algorithm, key->params,
                         key->params_size, hash, signature);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * gnutls_x509_privkey_verify_data - This function will verify the given signed data.
 * @key: Holds the key
 * @flags: should be 0 for now
 * @data: holds the data to be signed
 * @signature: contains the signature
 *
 * This function will verify the given signed data, using the parameters in the
 * private key.
 *
 * In case of a verification failure 0 is returned, and
 * 1 on success.
 *
 **/
int
gnutls_x509_privkey_verify_data (gnutls_x509_privkey_t key,
                                 unsigned int flags,
                                 const gnutls_datum_t * data,
                                 const gnutls_datum_t * signature)
{
  int result;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_privkey_verify_signature (data, signature, key);
  if (result < 0)
    {
      gnutls_assert ();
      return 0;
    }

  return result;
}

/**
 * gnutls_x509_privkey_fix - This function will recalculate some parameters of the key.
 * @key: Holds the key
 *
 * This function will recalculate the secondary parameters in a key.
 * In RSA keys, this can be the coefficient and exponent1,2.
 *
 * Return value: In case of failure a negative value will be
 *   returned, and 0 on success.
 *
 **/
int
gnutls_x509_privkey_fix (gnutls_x509_privkey_t key)
{
  int ret;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (!key->crippled)
    asn1_delete_structure (&key->key);
  switch (key->pk_algorithm)
    {
    case MHD_GNUTLS_PK_RSA:
      ret = _gnutls_asn1_encode_rsa (&key->key, key->params);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return 0;
}

#endif
