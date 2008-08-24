/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007 Free Software Foundation
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

/* All functions which relate to X.509 certificate signing stuff are
 * included here
 */

#include <gnutls_int.h>

#ifdef ENABLE_PKI

#include <gnutls_errors.h>
#include <gnutls_cert.h>
#include <libtasn1.h>
#include <gnutls_global.h>
#include <gnutls_num.h>         /* MAX */
#include <gnutls_sig.h>
#include <gnutls_str.h>
#include <gnutls_datum.h>
#include <dn.h>
#include <x509.h>
#include <mpi.h>
#include <sign.h>
#include <common.h>
#include <verify.h>

/* Writes the digest information and the digest in a DER encoded
 * structure. The digest info is allocated and stored into the info structure.
 */
static int
encode_ber_digest_info (enum MHD_GNUTLS_HashAlgorithm hash,
                        const gnutls_datum_t * digest, gnutls_datum_t * info)
{
  ASN1_TYPE dinfo = ASN1_TYPE_EMPTY;
  int result;
  const char *algo;

  algo = mhd_gtls_x509_mac_to_oid ((enum MHD_GNUTLS_HashAlgorithm) hash);
  if (algo == NULL)
    {
      gnutls_assert ();
      _gnutls_x509_log ("Hash algorithm: %d\n", hash);
      return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
    }

  if ((result = asn1_create_element (_gnutls_get_gnutls_asn (),
                                     "GNUTLS.DigestInfo",
                                     &dinfo)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  result = asn1_write_value (dinfo, "digestAlgorithm.algorithm", algo, 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return mhd_gtls_asn2err (result);
    }

  /* Write an ASN.1 NULL in the parameters field.  This matches RFC
     3279 and RFC 4055, although is arguable incorrect from a historic
     perspective (see those documents for more information).
     Regardless of what is correct, this appears to be what most
     implementations do.  */
  result = asn1_write_value (dinfo, "digestAlgorithm.parameters",
                             "\x05\x00", 2);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return mhd_gtls_asn2err (result);
    }

  result = asn1_write_value (dinfo, "digest", digest->data, digest->size);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return mhd_gtls_asn2err (result);
    }

  info->size = 0;
  asn1_der_coding (dinfo, "", NULL, &info->size, NULL);

  info->data = gnutls_malloc (info->size);
  if (info->data == NULL)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = asn1_der_coding (dinfo, "", info->data, &info->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return mhd_gtls_asn2err (result);
    }

  asn1_delete_structure (&dinfo);

  return 0;
}

/* if hash==MD5 then we do RSA-MD5
 * if hash==SHA then we do RSA-SHA
 * params[0] is modulus
 * params[1] is public key
 */
static int
pkcs1_rsa_sign (enum MHD_GNUTLS_HashAlgorithm hash, const gnutls_datum_t * text,
                mpi_t * params, int params_len, gnutls_datum_t * signature)
{
  int ret;
  opaque _digest[MAX_HASH_SIZE];
  GNUTLS_HASH_HANDLE hd;
  gnutls_datum_t digest, info;

  hd = mhd_gtls_hash_init (HASH2MAC (hash));
  if (hd == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  mhd_gnutls_hash (hd, text->data, text->size);
  mhd_gnutls_hash_deinit (hd, _digest);

  digest.data = _digest;
  digest.size = mhd_gnutls_hash_get_algo_len (HASH2MAC (hash));

  /* Encode the digest as a DigestInfo
   */
  if ((ret = encode_ber_digest_info (hash, &digest, &info)) != 0)
    {
      gnutls_assert ();
      return ret;
    }

  if ((ret =
       mhd_gtls_sign (MHD_GNUTLS_PK_RSA, params, params_len, &info,
                     signature)) < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (&info);
      return ret;
    }

  _gnutls_free_datum (&info);

  return 0;
}

/* Signs the given data using the parameters from the signer's
 * private key.
 *
 * returns 0 on success.
 * 
 * 'tbs' is the data to be signed
 * 'signature' will hold the signature!
 * 'hash' is only used in PKCS1 RSA signing.
 */
int
_gnutls_x509_sign (const gnutls_datum_t * tbs,
                   enum MHD_GNUTLS_HashAlgorithm hash,
                   gnutls_x509_privkey_t signer, gnutls_datum_t * signature)
{
  int ret;

  switch (signer->pk_algorithm)
    {
    case MHD_GNUTLS_PK_RSA:
      ret =
        pkcs1_rsa_sign (hash, tbs, signer->params, signer->params_size,
                        signature);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      return 0;
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

}

/* This is the same as the _gnutls_x509_sign, but this one will decode
 * the ASN1_TYPE given, and sign the DER data. Actually used to get the DER
 * of the TBS and sign it on the fly.
 */
int
_gnutls_x509_sign_tbs (ASN1_TYPE cert, const char *tbs_name,
                       enum MHD_GNUTLS_HashAlgorithm hash,
                       gnutls_x509_privkey_t signer,
                       gnutls_datum_t * signature)
{
  int result;
  opaque *buf;
  int buf_size;
  gnutls_datum_t tbs;

  buf_size = 0;
  asn1_der_coding (cert, tbs_name, NULL, &buf_size, NULL);

  buf = gnutls_alloca (buf_size);
  if (buf == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = asn1_der_coding (cert, tbs_name, buf, &buf_size, NULL);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      gnutls_afree (buf);
      return mhd_gtls_asn2err (result);
    }

  tbs.data = buf;
  tbs.size = buf_size;

  result = _gnutls_x509_sign (&tbs, hash, signer, signature);
  gnutls_afree (buf);

  return result;
}

/*-
 * _gnutls_x509_pkix_sign - This function will sign a CRL or a certificate with a key
 * @src: should contain an ASN1_TYPE
 * @issuer: is the certificate of the certificate issuer
 * @issuer_key: holds the issuer's private key
 *
 * This function will sign a CRL or a certificate with the issuer's private key, and
 * will copy the issuer's information into the CRL or certificate.
 *
 * Returns 0 on success.
 *
 -*/
int
_gnutls_x509_pkix_sign (ASN1_TYPE src, const char *src_name,
                        enum MHD_GNUTLS_HashAlgorithm dig,
                        gnutls_x509_crt_t issuer,
                        gnutls_x509_privkey_t issuer_key)
{
  int result;
  gnutls_datum_t signature;
  char name[128];

  /* Step 1. Copy the issuer's name into the certificate.
   */
  mhd_gtls_str_cpy (name, sizeof (name), src_name);
  mhd_gtls_str_cat (name, sizeof (name), ".issuer");

  result = asn1_copy_node (src, name, issuer->cert, "tbsCertificate.subject");
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  /* Step 1.5. Write the signature stuff in the tbsCertificate.
   */
  mhd_gtls_str_cpy (name, sizeof (name), src_name);
  mhd_gtls_str_cat (name, sizeof (name), ".signature");

  result = _gnutls_x509_write_sig_params (src, name,
                                          issuer_key->pk_algorithm, dig,
                                          issuer_key->params,
                                          issuer_key->params_size);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  /* Step 2. Sign the certificate.
   */
  result = _gnutls_x509_sign_tbs (src, src_name, dig, issuer_key, &signature);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  /* write the signature (bits)
   */
  result =
    asn1_write_value (src, "signature", signature.data, signature.size * 8);

  _gnutls_free_datum (&signature);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  /* Step 3. Move up and write the AlgorithmIdentifier, which is also
   * the same. 
   */

  result = _gnutls_x509_write_sig_params (src, "signatureAlgorithm",
                                          issuer_key->pk_algorithm, dig,
                                          issuer_key->params,
                                          issuer_key->params_size);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

#endif
