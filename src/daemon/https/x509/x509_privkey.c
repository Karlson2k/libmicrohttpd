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

static int MHD__gnutls_asn1_encode_rsa (ASN1_TYPE * c2, mpi_t * params);
int MHD__gnutls_asn1_encode_dsa (ASN1_TYPE * c2, mpi_t * params);

/* remove this when libgcrypt can handle the PKCS #1 coefficients from
 * rsa keys
 */
#define CALC_COEFF 1

/**
 * MHD_gnutls_x509_privkey_init - This function initializes a MHD_gnutls_crl structure
 * @key: The structure to be initialized
 *
 * This function will initialize an private key structure.
 *
 * Returns 0 on success.
 *
 **/
int
MHD_gnutls_x509_privkey_init (MHD_gnutls_x509_privkey_t * key)
{
  *key = MHD_gnutls_calloc (1, sizeof (MHD_gnutls_x509_privkey_int));

  if (*key)
    {
      (*key)->key = ASN1_TYPE_EMPTY;
      (*key)->pk_algorithm = MHD_GNUTLS_PK_UNKNOWN;
      return 0;                 /* success */
    }

  return GNUTLS_E_MEMORY_ERROR;
}

/**
 * MHD_gnutls_x509_privkey_deinit - This function deinitializes memory used by a MHD_gnutls_x509_privkey_t structure
 * @key: The structure to be initialized
 *
 * This function will deinitialize a private key structure.
 *
 **/
void
MHD_gnutls_x509_privkey_deinit (MHD_gnutls_x509_privkey_t key)
{
  int i;

  if (!key)
    return;

  for (i = 0; i < key->params_size; i++)
    {
      MHD_gtls_mpi_release (&key->params[i]);
    }

  MHD__asn1_delete_structure (&key->key);
  MHD_gnutls_free (key);
}

/**
 * MHD_gnutls_x509_privkey_cpy - This function copies a private key
 * @dst: The destination key, which should be initialized.
 * @src: The source key
 *
 * This function will copy a private key from source to destination key.
 *
 **/
int
MHD_gnutls_x509_privkey_cpy (MHD_gnutls_x509_privkey_t dst,
                             MHD_gnutls_x509_privkey_t src)
{
  int i, ret;

  if (!src || !dst)
    return GNUTLS_E_INVALID_REQUEST;

  for (i = 0; i < src->params_size; i++)
    {
      dst->params[i] = MHD__gnutls_mpi_copy (src->params[i]);
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
          ret = MHD__gnutls_asn1_encode_rsa (&dst->key, dst->params);
          if (ret < 0)
            {
              MHD_gnutls_assert ();
              return ret;
            }
          break;
        default:
          MHD_gnutls_assert ();
          return GNUTLS_E_INVALID_REQUEST;
        }
    }

  return 0;
}

/* Converts an RSA PKCS#1 key to
 * an internal structure (MHD_gnutls_private_key)
 */
ASN1_TYPE
MHD__gnutls_privkey_decode_pkcs1_rsa_key (const MHD_gnutls_datum_t * raw_key,
                                          MHD_gnutls_x509_privkey_t pkey)
{
  int result;
  ASN1_TYPE pkey_asn;

  if ((result = MHD__asn1_create_element (MHD__gnutls_getMHD__gnutls_asn (),
                                          "GNUTLS.RSAPrivateKey",
                                          &pkey_asn)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return NULL;
    }

  if ((sizeof (pkey->params) / sizeof (mpi_t)) < RSA_PRIVATE_PARAMS)
    {
      MHD_gnutls_assert ();
      /* internal error. Increase the mpi_ts in params */
      return NULL;
    }

  result =
    MHD__asn1_der_decoding (&pkey_asn, raw_key->data, raw_key->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  if ((result =
       MHD__gnutls_x509_read_int (pkey_asn, "modulus", &pkey->params[0])) < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  if ((result = MHD__gnutls_x509_read_int (pkey_asn, "publicExponent",
                                           &pkey->params[1])) < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  if ((result = MHD__gnutls_x509_read_int (pkey_asn, "privateExponent",
                                           &pkey->params[2])) < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  if ((result =
       MHD__gnutls_x509_read_int (pkey_asn, "prime1", &pkey->params[3])) < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  if ((result =
       MHD__gnutls_x509_read_int (pkey_asn, "prime2", &pkey->params[4])) < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

#ifdef CALC_COEFF
  /* Calculate the coefficient. This is because the gcrypt
   * library is uses the p,q in the reverse order.
   */
  pkey->params[5] =
    MHD__gnutls_mpi_snew (MHD__gnutls_mpi_get_nbits (pkey->params[0]));

  if (pkey->params[5] == NULL)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  MHD__gnutls_mpi_invm (pkey->params[5], pkey->params[3], pkey->params[4]);
  /* p, q */
#else
  if ((result = MHD__gnutls_x509_read_int (pkey_asn, "coefficient",
                                           &pkey->params[5])) < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }
#endif
  pkey->params_size = 6;

  return pkey_asn;

error:MHD__asn1_delete_structure (&pkey_asn);
  MHD_gtls_mpi_release (&pkey->params[0]);
  MHD_gtls_mpi_release (&pkey->params[1]);
  MHD_gtls_mpi_release (&pkey->params[2]);
  MHD_gtls_mpi_release (&pkey->params[3]);
  MHD_gtls_mpi_release (&pkey->params[4]);
  MHD_gtls_mpi_release (&pkey->params[5]);
  return NULL;

}

#define PEM_KEY_RSA "RSA PRIVATE KEY"

/**
 * MHD_gnutls_x509_privkey_import - This function will import a DER or PEM encoded key
 * @key: The structure to store the parsed key
 * @data: The DER or PEM encoded certificate.
 * @format: One of DER or PEM
 *
 * This function will convert the given DER or PEM encoded key
 * to the native MHD_gnutls_x509_privkey_t format. The output will be stored in @key .
 *
 * If the key is PEM encoded it should have a header of "RSA PRIVATE KEY", or
 * "DSA PRIVATE KEY".
 *
 * Returns 0 on success.
 *
 **/
int
MHD_gnutls_x509_privkey_import (MHD_gnutls_x509_privkey_t key,
                                const MHD_gnutls_datum_t * data,
                                MHD_gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  MHD_gnutls_datum_t _data;

  if (key == NULL)
    {
      MHD_gnutls_assert ();
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
        =
        MHD__gnutls_fbase64_decode (PEM_KEY_RSA, data->data, data->size,
                                    &out);
      key->pk_algorithm = MHD_GNUTLS_PK_RSA;

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }

  if (key->pk_algorithm == MHD_GNUTLS_PK_RSA)
    {
      key->key = MHD__gnutls_privkey_decode_pkcs1_rsa_key (&_data, key);
      if (key->key == NULL)
        MHD_gnutls_assert ();
    }
  else
    {
      /* Try decoding with both, and accept the one that succeeds. */
      key->pk_algorithm = MHD_GNUTLS_PK_RSA;
      key->key = MHD__gnutls_privkey_decode_pkcs1_rsa_key (&_data, key);

      // TODO rm
//      if (key->key == NULL)
//        {
//          key->pk_algorithm = GNUTLS_PK_DSA;
//          key->key = decode_dsa_key(&_data, key);
//          if (key->key == NULL)
//            MHD_gnutls_assert();
//        }
    }

  if (key->key == NULL)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_ASN1_DER_ERROR;
      key->pk_algorithm = MHD_GNUTLS_PK_UNKNOWN;
      return result;
    }

  if (need_free)
    MHD__gnutls_free_datum (&_data);

  /* The key has now been decoded.
   */

  return 0;
}

#define FREE_RSA_PRIVATE_PARAMS for (i=0;i<RSA_PRIVATE_PARAMS;i++) \
		MHD_gtls_mpi_release(&key->params[i])
#define FREE_DSA_PRIVATE_PARAMS for (i=0;i<DSA_PRIVATE_PARAMS;i++) \
		MHD_gtls_mpi_release(&key->params[i])

/**
 * MHD_gnutls_x509_privkey_import_rsa_raw - This function will import a raw RSA key
 * @key: The structure to store the parsed key
 * @m: holds the modulus
 * @e: holds the public exponent
 * @d: holds the private exponent
 * @p: holds the first prime (p)
 * @q: holds the second prime (q)
 * @u: holds the coefficient
 *
 * This function will convert the given RSA raw parameters
 * to the native MHD_gnutls_x509_privkey_t format. The output will be stored in @key.
 *
 **/
int
MHD_gnutls_x509_privkey_import_rsa_raw (MHD_gnutls_x509_privkey_t key,
                                        const MHD_gnutls_datum_t * m,
                                        const MHD_gnutls_datum_t * e,
                                        const MHD_gnutls_datum_t * d,
                                        const MHD_gnutls_datum_t * p,
                                        const MHD_gnutls_datum_t * q,
                                        const MHD_gnutls_datum_t * u)
{
  int i = 0, ret;
  size_t siz = 0;

  if (key == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  siz = m->size;
  if (MHD_gtls_mpi_scan_nz (&key->params[0], m->data, &siz))
    {
      MHD_gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = e->size;
  if (MHD_gtls_mpi_scan_nz (&key->params[1], e->data, &siz))
    {
      MHD_gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = d->size;
  if (MHD_gtls_mpi_scan_nz (&key->params[2], d->data, &siz))
    {
      MHD_gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = p->size;
  if (MHD_gtls_mpi_scan_nz (&key->params[3], p->data, &siz))
    {
      MHD_gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  siz = q->size;
  if (MHD_gtls_mpi_scan_nz (&key->params[4], q->data, &siz))
    {
      MHD_gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

#ifdef CALC_COEFF
  key->params[5] =
    MHD__gnutls_mpi_snew (MHD__gnutls_mpi_get_nbits (key->params[0]));

  if (key->params[5] == NULL)
    {
      MHD_gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MEMORY_ERROR;
    }

  MHD__gnutls_mpi_invm (key->params[5], key->params[3], key->params[4]);
#else
  siz = u->size;
  if (MHD_gtls_mpi_scan_nz (&key->params[5], u->data, &siz))
    {
      MHD_gnutls_assert ();
      FREE_RSA_PRIVATE_PARAMS;
      return GNUTLS_E_MPI_SCAN_FAILED;
    }
#endif

  if (!key->crippled)
    {
      ret = MHD__gnutls_asn1_encode_rsa (&key->key, key->params);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          FREE_RSA_PRIVATE_PARAMS;
          return ret;
        }
    }

  key->params_size = RSA_PRIVATE_PARAMS;
  key->pk_algorithm = MHD_GNUTLS_PK_RSA;

  return 0;

}

/**
 * MHD_gnutls_x509_privkey_get_pk_algorithm - This function returns the key's PublicKey algorithm
 * @key: should contain a MHD_gnutls_x509_privkey_t structure
 *
 * This function will return the public key algorithm of a private
 * key.
 *
 * Returns a member of the enum MHD_GNUTLS_PublicKeyAlgorithm enumeration on success,
 * or a negative value on error.
 *
 **/
int
MHD_gnutls_x509_privkey_get_pk_algorithm (MHD_gnutls_x509_privkey_t key)
{
  if (key == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return key->pk_algorithm;
}

/* Encodes the RSA parameters into an ASN.1 RSA private key structure.
 */
static int
MHD__gnutls_asn1_encode_rsa (ASN1_TYPE * c2, mpi_t * params)
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
      MHD_gtls_mpi_print_lz (NULL, &size[i], params[i]);
      total += size[i];
    }

  /* Now generate exp1 and exp2
   */
  exp1 = MHD__gnutls_mpi_salloc_like (params[0]);       /* like modulus */
  if (exp1 == NULL)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  exp2 = MHD__gnutls_mpi_salloc_like (params[0]);
  if (exp2 == NULL)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  q1 = MHD__gnutls_mpi_salloc_like (params[4]);
  if (q1 == NULL)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  p1 = MHD__gnutls_mpi_salloc_like (params[3]);
  if (p1 == NULL)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  u = MHD__gnutls_mpi_salloc_like (params[3]);
  if (u == NULL)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  MHD__gnutls_mpi_invm (u, params[4], params[3]);
  /* inverse of q mod p */
  MHD_gtls_mpi_print_lz (NULL, &size[5], u);
  total += size[5];

  MHD__gnutls_mpi_sub_ui (p1, params[3], 1);
  MHD__gnutls_mpi_sub_ui (q1, params[4], 1);

  MHD__gnutls_mpi_mod (exp1, params[2], p1);
  MHD__gnutls_mpi_mod (exp2, params[2], q1);

  /* calculate exp's size */
  MHD_gtls_mpi_print_lz (NULL, &size[6], exp1);
  total += size[6];

  MHD_gtls_mpi_print_lz (NULL, &size[7], exp2);
  total += size[7];

  /* Encoding phase.
   * allocate data enough to hold everything
   */
  all_data = MHD_gnutls_secure_malloc (total);
  if (all_data == NULL)
    {
      MHD_gnutls_assert ();
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

  MHD_gtls_mpi_print_lz (m_data, &size[0], params[0]);
  MHD_gtls_mpi_print_lz (pube_data, &size[1], params[1]);
  MHD_gtls_mpi_print_lz (prie_data, &size[2], params[2]);
  MHD_gtls_mpi_print_lz (p1_data, &size[3], params[3]);
  MHD_gtls_mpi_print_lz (p2_data, &size[4], params[4]);
  MHD_gtls_mpi_print_lz (u_data, &size[5], u);
  MHD_gtls_mpi_print_lz (exp1_data, &size[6], exp1);
  MHD_gtls_mpi_print_lz (exp2_data, &size[7], exp2);

  /* Ok. Now we have the data. Create the asn1 structures
   */

  if ((result =
       MHD__asn1_create_element (MHD__gnutls_getMHD__gnutls_asn (),
                                 "GNUTLS.RSAPrivateKey", c2)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* Write PRIME
   */
  if ((result = MHD__asn1_write_value (*c2, "modulus", m_data, size[0]))
      != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result =
       MHD__asn1_write_value (*c2, "publicExponent", pube_data,
                              size[1])) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result =
       MHD__asn1_write_value (*c2, "privateExponent", prie_data,
                              size[2])) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = MHD__asn1_write_value (*c2, "prime1", p1_data, size[3]))
      != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = MHD__asn1_write_value (*c2, "prime2", p2_data, size[4]))
      != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = MHD__asn1_write_value (*c2, "exponent1", exp1_data, size[6]))
      != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = MHD__asn1_write_value (*c2, "exponent2", exp2_data, size[7]))
      != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result = MHD__asn1_write_value (*c2, "coefficient", u_data, size[5]))
      != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  MHD_gtls_mpi_release (&exp1);
  MHD_gtls_mpi_release (&exp2);
  MHD_gtls_mpi_release (&q1);
  MHD_gtls_mpi_release (&p1);
  MHD_gtls_mpi_release (&u);
  MHD_gnutls_free (all_data);

  if ((result = MHD__asn1_write_value (*c2, "otherPrimeInfos",
                                       NULL, 0)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result =
       MHD__asn1_write_value (*c2, "version", &null, 1)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  return 0;

cleanup:MHD_gtls_mpi_release (&u);
  MHD_gtls_mpi_release (&exp1);
  MHD_gtls_mpi_release (&exp2);
  MHD_gtls_mpi_release (&q1);
  MHD_gtls_mpi_release (&p1);
  MHD__asn1_delete_structure (c2);
  MHD_gnutls_free (all_data);

  return result;
}

/* Encodes the DSA parameters into an ASN.1 DSAPrivateKey structure.
 */
int
MHD__gnutls_asn1_encode_dsa (ASN1_TYPE * c2, mpi_t * params)
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
      MHD_gtls_mpi_print_lz (NULL, &size[i], params[i]);
      total += size[i];
    }

  /* Encoding phase.
   * allocate data enough to hold everything
   */
  all_data = MHD_gnutls_secure_malloc (total);
  if (all_data == NULL)
    {
      MHD_gnutls_assert ();
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

  MHD_gtls_mpi_print_lz (p_data, &size[0], params[0]);
  MHD_gtls_mpi_print_lz (q_data, &size[1], params[1]);
  MHD_gtls_mpi_print_lz (g_data, &size[2], params[2]);
  MHD_gtls_mpi_print_lz (y_data, &size[3], params[3]);
  MHD_gtls_mpi_print_lz (x_data, &size[4], params[4]);

  /* Ok. Now we have the data. Create the asn1 structures
   */

  if ((result =
       MHD__asn1_create_element (MHD__gnutls_getMHD__gnutls_asn (),
                                 "GNUTLS.DSAPrivateKey", c2)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* Write PRIME
   */
  if ((result =
       MHD__asn1_write_value (*c2, "p", p_data, size[0])) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result =
       MHD__asn1_write_value (*c2, "q", q_data, size[1])) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result =
       MHD__asn1_write_value (*c2, "g", g_data, size[2])) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result =
       MHD__asn1_write_value (*c2, "Y", y_data, size[3])) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if ((result =
       MHD__asn1_write_value (*c2, "priv", x_data, size[4])) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  MHD_gnutls_free (all_data);

  if ((result =
       MHD__asn1_write_value (*c2, "version", &null, 1)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  return 0;

cleanup:MHD__asn1_delete_structure (c2);
  MHD_gnutls_free (all_data);

  return result;
}
