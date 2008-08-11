/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006 Free Software Foundation
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

/* This file contains the functions needed for RSA/DSA public key
 * encryption and signatures. 
 */

#include <gnutls_int.h>
#include <gnutls_mpi.h>
#include <gnutls_pk.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_num.h>
#include "debug.h"
#include <gc.h>

/* x509 */
#include "common.h"
#include "mpi.h"

static int _gnutls_pk_encrypt (int algo, mpi_t * resarr, mpi_t data,
                               mpi_t * pkey, int pkey_len);
static int _gnutls_pk_sign (int algo, mpi_t * data, mpi_t hash,
                            mpi_t * pkey, int);
static int _gnutls_pk_verify (int algo, mpi_t hash, mpi_t * data,
                              mpi_t * pkey, int);
static int _gnutls_pk_decrypt (int algo, mpi_t * resarr, mpi_t data,
                               mpi_t * pkey, int);


/* Do PKCS-1 RSA encryption. 
 * params is modulus, public exp.
 */
int
mhd_gtls_pkcs1_rsa_encrypt (gnutls_datum_t * ciphertext,
                           const gnutls_datum_t * plaintext,
                           mpi_t * params, unsigned params_len,
                           unsigned btype)
{
  unsigned int i, pad;
  int ret;
  mpi_t m, res;
  opaque *edata, *ps;
  size_t k, psize;
  size_t mod_bits;

  mod_bits = _gnutls_mpi_get_nbits (params[0]);
  k = mod_bits / 8;
  if (mod_bits % 8 != 0)
    k++;

  if (plaintext->size > k - 11)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_ENCRYPTION_FAILED;
    }

  edata = gnutls_alloca (k);
  if (edata == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* EB = 00||BT||PS||00||D 
   * (use block type 'btype')
   */

  edata[0] = 0;
  edata[1] = btype;
  psize = k - 3 - plaintext->size;

  ps = &edata[2];
  switch (btype)
    {
    case 2:
      /* using public key */
      if (params_len < RSA_PUBLIC_PARAMS)
        {
          gnutls_assert ();
          gnutls_afree (edata);
          return GNUTLS_E_INTERNAL_ERROR;
        }

      if (gc_pseudo_random (ps, psize) != GC_OK)
        {
          gnutls_assert ();
          gnutls_afree (edata);
          return GNUTLS_E_RANDOM_FAILED;
        }
      for (i = 0; i < psize; i++)
        while (ps[i] == 0)
          {
            if (gc_pseudo_random (&ps[i], 1) != GC_OK)
              {
                gnutls_assert ();
                gnutls_afree (edata);
                return GNUTLS_E_RANDOM_FAILED;
              }
          }
      break;
    case 1:
      /* using private key */

      if (params_len < RSA_PRIVATE_PARAMS)
        {
          gnutls_assert ();
          gnutls_afree (edata);
          return GNUTLS_E_INTERNAL_ERROR;
        }

      for (i = 0; i < psize; i++)
        ps[i] = 0xff;
      break;
    default:
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ps[psize] = 0;
  memcpy (&ps[psize + 1], plaintext->data, plaintext->size);

  if (mhd_gtls_mpi_scan_nz (&m, edata, &k) != 0)
    {
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_MPI_SCAN_FAILED;
    }
  gnutls_afree (edata);

  if (btype == 2)               /* encrypt */
    ret = _gnutls_pk_encrypt (GCRY_PK_RSA, &res, m, params, params_len);
  else                          /* sign */
    ret = _gnutls_pk_sign (GCRY_PK_RSA, &res, m, params, params_len);

  mhd_gtls_mpi_release (&m);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  mhd_gtls_mpi_print (NULL, &psize, res);

  if (psize < k)
    {
      /* padding psize */
      pad = k - psize;
      psize = k;
    }
  else if (psize == k)
    {
      pad = 0;
    }
  else
    {                           /* psize > k !!! */
      /* This is an impossible situation */
      gnutls_assert ();
      mhd_gtls_mpi_release (&res);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ciphertext->data = gnutls_malloc (psize);
  if (ciphertext->data == NULL)
    {
      gnutls_assert ();
      mhd_gtls_mpi_release (&res);
      return GNUTLS_E_MEMORY_ERROR;
    }
  mhd_gtls_mpi_print (&ciphertext->data[pad], &psize, res);
  for (i = 0; i < pad; i++)
    ciphertext->data[i] = 0;

  ciphertext->size = k;

  mhd_gtls_mpi_release (&res);

  return 0;
}


/* Do PKCS-1 RSA decryption. 
 * params is modulus, public exp., private key
 * Can decrypt block type 1 and type 2 packets.
 */
int
mhd_gtls_pkcs1_rsa_decrypt (gnutls_datum_t * plaintext,
                           const gnutls_datum_t * ciphertext,
                           mpi_t * params, unsigned params_len,
                           unsigned btype)
{
  unsigned k, i;
  int ret;
  mpi_t c, res;
  opaque *edata;
  size_t esize, mod_bits;

  mod_bits = _gnutls_mpi_get_nbits (params[0]);
  k = mod_bits / 8;
  if (mod_bits % 8 != 0)
    k++;

  esize = ciphertext->size;

  if (esize != k)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_DECRYPTION_FAILED;
    }

  if (mhd_gtls_mpi_scan_nz (&c, ciphertext->data, &esize) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  /* we can use btype to see if the private key is
   * available.
   */
  if (btype == 2)
    ret = _gnutls_pk_decrypt (GCRY_PK_RSA, &res, c, params, params_len);
  else
    {
      ret = _gnutls_pk_encrypt (GCRY_PK_RSA, &res, c, params, params_len);
    }
  mhd_gtls_mpi_release (&c);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  mhd_gtls_mpi_print (NULL, &esize, res);
  edata = gnutls_alloca (esize + 1);
  if (edata == NULL)
    {
      gnutls_assert ();
      mhd_gtls_mpi_release (&res);
      return GNUTLS_E_MEMORY_ERROR;
    }
  mhd_gtls_mpi_print (&edata[1], &esize, res);

  mhd_gtls_mpi_release (&res);

  /* EB = 00||BT||PS||00||D
   * (use block type 'btype')
   *
   * From now on, return GNUTLS_E_DECRYPTION_FAILED on errors, to
   * avoid attacks similar to the one described by Bleichenbacher in:
   * "Chosen Ciphertext Attacks against Protocols Based on RSA
   * Encryption Standard PKCS #1".
   */


  edata[0] = 0;
  esize++;

  if (edata[0] != 0 || edata[1] != btype)
    {
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_DECRYPTION_FAILED;
    }

  ret = GNUTLS_E_DECRYPTION_FAILED;
  switch (btype)
    {
    case 2:
      for (i = 2; i < esize; i++)
        {
          if (edata[i] == 0)
            {
              ret = 0;
              break;
            }
        }
      break;
    case 1:
      for (i = 2; i < esize; i++)
        {
          if (edata[i] == 0 && i > 2)
            {
              ret = 0;
              break;
            }
          if (edata[i] != 0xff)
            {
              _gnutls_handshake_log ("PKCS #1 padding error");
              /* PKCS #1 padding error.  Don't use
                 GNUTLS_E_PKCS1_WRONG_PAD here.  */
              break;
            }
        }
      break;
    default:
      gnutls_assert ();
      gnutls_afree (edata);
      break;
    }
  i++;

  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_DECRYPTION_FAILED;
    }

  if (_gnutls_sset_datum (plaintext, &edata[i], esize - i) < 0)
    {
      gnutls_assert ();
      gnutls_afree (edata);
      return GNUTLS_E_MEMORY_ERROR;
    }

  gnutls_afree (edata);

  return 0;
}


int
mhd_gtls_rsa_verify (const gnutls_datum_t * vdata,
                    const gnutls_datum_t * ciphertext, mpi_t * params,
                    int params_len, int btype)
{

  gnutls_datum_t plain;
  int ret;

  /* decrypt signature */
  if ((ret =
       mhd_gtls_pkcs1_rsa_decrypt (&plain, ciphertext, params, params_len,
                                  btype)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (plain.size != vdata->size)
    {
      gnutls_assert ();
      _gnutls_free_datum (&plain);
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  if (memcmp (plain.data, vdata->data, plain.size) != 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (&plain);
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  _gnutls_free_datum (&plain);

  return 0;                     /* ok */
}

/* encodes the Dss-Sig-Value structure
 */
static int
encode_ber_rs (gnutls_datum_t * sig_value, mpi_t r, mpi_t s)
{
  ASN1_TYPE sig;
  int result, tot_len;

  if ((result =
       asn1_create_element (_gnutls_get_gnutls_asn (),
                            "GNUTLS.DSASignatureValue",
                            &sig)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_write_int (sig, "r", r, 1);
  if (result < 0)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return result;
    }

  result = _gnutls_x509_write_int (sig, "s", s, 1);
  if (result < 0)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return result;
    }

  tot_len = 0;

  result = _gnutls_x509_der_encode (sig, "", sig_value, 0);

  asn1_delete_structure (&sig);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}


/* Do DSA signature calculation. params is p, q, g, y, x in that order.
 */
int
mhd_gtls_dsa_sign (gnutls_datum_t * signature,
                  const gnutls_datum_t * hash, mpi_t * params,
                  unsigned params_len)
{
  mpi_t rs[2], mdata;
  int ret;
  size_t k;

  k = hash->size;
  if (k < 20)
    {                           /* SHA1 or better only */
      gnutls_assert ();
      return GNUTLS_E_PK_SIGN_FAILED;
    }

  if (mhd_gtls_mpi_scan_nz (&mdata, hash->data, &k) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  ret = _gnutls_pk_sign (GCRY_PK_DSA, rs, mdata, params, params_len);
  /* rs[0], rs[1] now hold r,s */
  mhd_gtls_mpi_release (&mdata);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = encode_ber_rs (signature, rs[0], rs[1]);

  /* free r,s */
  mhd_gtls_mpi_release (&rs[0]);
  mhd_gtls_mpi_release (&rs[1]);

  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  return 0;
}

/* decodes the Dss-Sig-Value structure
 */
static int
decode_ber_rs (const gnutls_datum_t * sig_value, mpi_t * r, mpi_t * s)
{
  ASN1_TYPE sig;
  int result;

  if ((result =
       asn1_create_element (_gnutls_get_gnutls_asn (),
                            "GNUTLS.DSASignatureValue",
                            &sig)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&sig, sig_value->data, sig_value->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return _gnutls_asn2err (result);
    }

  result = _gnutls_x509_read_int (sig, "r", r);
  if (result < 0)
    {
      gnutls_assert ();
      asn1_delete_structure (&sig);
      return result;
    }

  result = _gnutls_x509_read_int (sig, "s", s);
  if (result < 0)
    {
      gnutls_assert ();
      mhd_gtls_mpi_release (s);
      asn1_delete_structure (&sig);
      return result;
    }

  asn1_delete_structure (&sig);

  return 0;
}

/* params is p, q, g, y in that order
 */
int
mhd_gtls_dsa_verify (const gnutls_datum_t * vdata,
                    const gnutls_datum_t * sig_value, mpi_t * params,
                    int params_len)
{

  mpi_t mdata;
  int ret;
  size_t k;
  mpi_t rs[2];

  if (vdata->size != 20)
    {                           /* sha-1 only */
      gnutls_assert ();
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  if (decode_ber_rs (sig_value, &rs[0], &rs[1]) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  k = vdata->size;
  if (mhd_gtls_mpi_scan_nz (&mdata, vdata->data, &k) != 0)
    {
      gnutls_assert ();
      mhd_gtls_mpi_release (&rs[0]);
      mhd_gtls_mpi_release (&rs[1]);
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  /* decrypt signature */
  ret = _gnutls_pk_verify (GCRY_PK_DSA, mdata, rs, params, params_len);
  mhd_gtls_mpi_release (&mdata);
  mhd_gtls_mpi_release (&rs[0]);
  mhd_gtls_mpi_release (&rs[1]);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;                     /* ok */
}


/* this is taken from gnupg 
 */

/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
static int
_gnutls_pk_encrypt (int algo, mpi_t * resarr, mpi_t data,
                    mpi_t * pkey, int pkey_len)
{
  gcry_sexp_t s_ciph, s_data, s_pkey;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GCRY_PK_RSA:
      if (pkey_len >= 2)
        rc = gcry_sexp_build (&s_pkey, NULL,
                              "(public-key(rsa(n%m)(e%m)))",
                              pkey[0], pkey[1]);
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_data, NULL, "%m", data))
    {
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_ENCRYPTION_FAILED;

    }
  else
    {                           /* add better error handling or make gnupg use S-Exp directly */
      gcry_sexp_t list = gcry_sexp_find_token (s_ciph, "a", 0);
      if (list == NULL)
        {
          gnutls_assert ();
          gcry_sexp_release (s_ciph);
          return GNUTLS_E_INTERNAL_ERROR;
        }

      resarr[0] = gcry_sexp_nth_mpi (list, 1, 0);
      gcry_sexp_release (list);

      if (resarr[0] == NULL)
        {
          gnutls_assert ();
          gcry_sexp_release (s_ciph);
          return GNUTLS_E_INTERNAL_ERROR;
        }
    }

  gcry_sexp_release (s_ciph);
  return rc;
}

static int
_gnutls_pk_decrypt (int algo, mpi_t * resarr, mpi_t data, mpi_t * pkey,
                    int pkey_len)
{
  gcry_sexp_t s_plain, s_data, s_pkey;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GCRY_PK_RSA:
      if (pkey_len >= 6)
        rc = gcry_sexp_build (&s_pkey, NULL,
                              "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
                              pkey[0], pkey[1], pkey[2], pkey[3],
                              pkey[4], pkey[5]);
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_data, NULL, "(enc-val(rsa(a%m)))", data))
    {
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_decrypt (&s_plain, s_data, s_pkey);
  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_DECRYPTION_FAILED;

    }
  else
    {                           /* add better error handling or make gnupg use S-Exp directly */
      resarr[0] = gcry_sexp_nth_mpi (s_plain, 0, 0);

      if (resarr[0] == NULL)
        {
          gnutls_assert ();
          gcry_sexp_release (s_plain);
          return GNUTLS_E_INTERNAL_ERROR;
        }
    }

  gcry_sexp_release (s_plain);
  return rc;
}


/* in case of DSA puts into data, r,s
 */
static int
_gnutls_pk_sign (int algo, mpi_t * data, mpi_t hash, mpi_t * pkey,
                 int pkey_len)
{
  gcry_sexp_t s_hash, s_key, s_sig;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GCRY_PK_DSA:
      if (pkey_len >= 5)
        rc = gcry_sexp_build (&s_key, NULL,
                              "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
                              pkey[0], pkey[1], pkey[2], pkey[3], pkey[4]);
      else
        {
          gnutls_assert ();
        }

      break;
    case GCRY_PK_RSA:
      if (pkey_len >= 6)
        rc = gcry_sexp_build (&s_key, NULL,
                              "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
                              pkey[0], pkey[1], pkey[2], pkey[3],
                              pkey[4], pkey[5]);
      else
        {
          gnutls_assert ();
        }
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_sign (&s_sig, s_hash, s_key);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_key);

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_SIGN_FAILED;

    }
  else
    {
      gcry_sexp_t list;

      if (algo == GCRY_PK_DSA)
        {
          list = gcry_sexp_find_token (s_sig, "r", 0);
          if (list == NULL)
            {
              gnutls_assert ();
              gcry_sexp_release (s_sig);
              return GNUTLS_E_INTERNAL_ERROR;
            }

          data[0] = gcry_sexp_nth_mpi (list, 1, 0);
          gcry_sexp_release (list);

          list = gcry_sexp_find_token (s_sig, "s", 0);
          if (list == NULL)
            {
              gnutls_assert ();
              gcry_sexp_release (s_sig);
              return GNUTLS_E_INTERNAL_ERROR;
            }

          data[1] = gcry_sexp_nth_mpi (list, 1, 0);
          gcry_sexp_release (list);
        }
      else
        {                       /* GCRY_PK_RSA */
          list = gcry_sexp_find_token (s_sig, "s", 0);
          if (list == NULL)
            {
              gnutls_assert ();
              gcry_sexp_release (s_sig);
              return GNUTLS_E_INTERNAL_ERROR;
            }

          data[0] = gcry_sexp_nth_mpi (list, 1, 0);
          gcry_sexp_release (list);
        }
    }

  gcry_sexp_release (s_sig);
  return 0;
}


static int
_gnutls_pk_verify (int algo, mpi_t hash, mpi_t * data,
                   mpi_t * pkey, int pkey_len)
{
  gcry_sexp_t s_sig, s_hash, s_pkey;
  int rc = -1;

  /* make a sexp from pkey */
  switch (algo)
    {
    case GCRY_PK_DSA:
      if (pkey_len >= 4)
        rc = gcry_sexp_build (&s_pkey, NULL,
                              "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                              pkey[0], pkey[1], pkey[2], pkey[3]);
      break;
    case GCRY_PK_RSA:
      if (pkey_len >= 2)
        rc = gcry_sexp_build (&s_pkey, NULL,
                              "(public-key(rsa(n%m)(e%m)))",
                              pkey[0], pkey[1]);
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
    {
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  switch (algo)
    {
    case GCRY_PK_DSA:
      rc = gcry_sexp_build (&s_sig, NULL,
                            "(sig-val(dsa(r%m)(s%m)))", data[0], data[1]);
      break;
    case GCRY_PK_RSA:
      rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%m)))", data[0]);
      break;

    default:
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      gcry_sexp_release (s_hash);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      gcry_sexp_release (s_pkey);
      gcry_sexp_release (s_hash);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  rc = gcry_pk_verify (s_sig, s_hash, s_pkey);

  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);

  if (rc != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  return 0;
}
