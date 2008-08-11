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

/* All functions which relate to X.509 certificate verification stuff are
 * included here
 */

#include <gnutls_int.h>
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
#include <common.h>
#include <verify.h>

static int _gnutls_verify_certificate2 (gnutls_x509_crt_t cert,
                                        const gnutls_x509_crt_t * trusted_cas,
                                        int tcas_size,
                                        unsigned int flags,
                                        unsigned int *output);
int _gnutls_x509_verify_signature (const gnutls_datum_t * signed_data,
                                   const gnutls_datum_t * signature,
                                   gnutls_x509_crt_t issuer);

static
  int is_crl_issuer (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer_cert);
static int _gnutls_verify_crl2 (gnutls_x509_crl_t crl,
                                const gnutls_x509_crt_t * trusted_cas,
                                int tcas_size,
                                unsigned int flags, unsigned int *output);

/* Checks if the issuer of a certificate is a
 * Certificate Authority, or if the certificate is the same
 * as the issuer (and therefore it doesn't need to be a CA).
 *
 * Returns true or false, if the issuer is a CA,
 * or not.
 */
static int
check_if_ca (gnutls_x509_crt_t cert,
             gnutls_x509_crt_t issuer, unsigned int flags)
{
  gnutls_datum_t cert_signed_data = { NULL,
    0
  };
  gnutls_datum_t issuer_signed_data = { NULL,
    0
  };
  gnutls_datum_t cert_signature = { NULL,
    0
  };
  gnutls_datum_t issuer_signature = { NULL,
    0
  };
  int result;

  /* Check if the issuer is the same with the
   * certificate. This is added in order for trusted
   * certificates to be able to verify themselves.
   */

  result = _gnutls_x509_get_signed_data (issuer->cert, "tbsCertificate",
                                         &issuer_signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_get_signed_data (cert->cert, "tbsCertificate",
                                         &cert_signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_get_signature (issuer->cert, "signature",
                                       &issuer_signature);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result =
    _gnutls_x509_get_signature (cert->cert, "signature", &cert_signature);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  /* If the subject certificate is the same as the issuer
   * return true.
   */
  if (!(flags & GNUTLS_VERIFY_DO_NOT_ALLOW_SAME))
    if (cert_signed_data.size == issuer_signed_data.size)
      {
        if ((memcmp (cert_signed_data.data, issuer_signed_data.data,
                     cert_signed_data.size) == 0) && (cert_signature.size
                                                      ==
                                                      issuer_signature.size)
            &&
            (memcmp
             (cert_signature.data, issuer_signature.data,
              cert_signature.size) == 0))
          {
            result = 1;
            goto cleanup;
          }
      }

  if (gnutls_x509_crt_get_ca_status (issuer, NULL) == 1)
    {
      result = 1;
      goto cleanup;
    }
  else
    gnutls_assert ();

  result = 0;

cleanup:_gnutls_free_datum (&cert_signed_data);
  _gnutls_free_datum (&issuer_signed_data);
  _gnutls_free_datum (&cert_signature);
  _gnutls_free_datum (&issuer_signature);
  return result;
}

/* This function checks if 'certs' issuer is 'issuer_cert'.
 * This does a straight (DER) compare of the issuer/subject fields in
 * the given certificates.
 *
 * Returns 1 if they match and zero if they don't match. Otherwise
 * a negative value is returned to indicate error.
 */
static int
is_issuer (gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer_cert)
{
  gnutls_datum_t dn1 = { NULL,
    0
  }, dn2 =
  {
  NULL, 0};
  int ret;

  ret = gnutls_x509_crt_get_raw_issuer_dn (cert, &dn1);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = gnutls_x509_crt_get_raw_dn (issuer_cert, &dn2);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_x509_compare_raw_dn (&dn1, &dn2);

cleanup:_gnutls_free_datum (&dn1);
  _gnutls_free_datum (&dn2);
  return ret;

}

static inline gnutls_x509_crt_t
find_issuer (gnutls_x509_crt_t cert,
             const gnutls_x509_crt_t * trusted_cas, int tcas_size)
{
  int i;

  /* this is serial search. 
   */

  for (i = 0; i < tcas_size; i++)
    {
      if (is_issuer (cert, trusted_cas[i]) == 1)
        return trusted_cas[i];
    }

  gnutls_assert ();
  return NULL;
}

/* 
 * Verifies the given certificate again a certificate list of
 * trusted CAs.
 *
 * Returns only 0 or 1. If 1 it means that the certificate 
 * was successfuly verified.
 *
 * 'flags': an OR of the gnutls_certificate_verify_flags enumeration.
 *
 * Output will hold some extra information about the verification
 * procedure.
 */
static int
_gnutls_verify_certificate2 (gnutls_x509_crt_t cert,
                             const gnutls_x509_crt_t * trusted_cas,
                             int tcas_size,
                             unsigned int flags, unsigned int *output)
{
  gnutls_datum_t cert_signed_data = { NULL,
    0
  };
  gnutls_datum_t cert_signature = { NULL,
    0
  };
  gnutls_x509_crt_t issuer;
  int ret, issuer_version, result;

  if (output)
    *output = 0;

  if (tcas_size >= 1)
    issuer = find_issuer (cert, trusted_cas, tcas_size);
  else
    {
      gnutls_assert ();
      if (output)
        *output |= GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_INVALID;
      return 0;
    }

  /* issuer is not in trusted certificate
   * authorities.
   */
  if (issuer == NULL)
    {
      if (output)
        *output |= GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_INVALID;
      gnutls_assert ();
      return 0;
    }

  issuer_version = gnutls_x509_crt_get_version (issuer);
  if (issuer_version < 0)
    {
      gnutls_assert ();
      return issuer_version;
    }

  if (!(flags & GNUTLS_VERIFY_DISABLE_CA_SIGN) && !((flags
                                                     &
                                                     GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT)
                                                    && issuer_version == 1))
    {
      if (check_if_ca (cert, issuer, flags) == 0)
        {
          gnutls_assert ();
          if (output)
            *output |= GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INVALID;
          return 0;
        }
    }

  result = _gnutls_x509_get_signed_data (cert->cert, "tbsCertificate",
                                         &cert_signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result =
    _gnutls_x509_get_signature (cert->cert, "signature", &cert_signature);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = _gnutls_x509_verify_signature (&cert_signed_data, &cert_signature,
                                       issuer);
  if (ret < 0)
    {
      gnutls_assert ();
    }
  else if (ret == 0)
    {
      gnutls_assert ();
      /* error. ignore it */
      if (output)
        *output |= GNUTLS_CERT_INVALID;
      ret = 0;
    }

  /* If the certificate is not self signed check if the algorithms
   * used are secure. If the certificate is self signed it doesn't
   * really matter.
   */
  if (is_issuer (cert, cert) == 0)
    {
      int sigalg;

      sigalg = gnutls_x509_crt_get_signature_algorithm (cert);

      if (((sigalg == GNUTLS_SIGN_RSA_MD2) && !(flags
                                                &
                                                GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2))
          || ((sigalg == GNUTLS_SIGN_RSA_MD5)
              && !(flags & GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5)))
        {
          if (output)
            *output |= GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID;
        }
    }

  result = ret;

cleanup:_gnutls_free_datum (&cert_signed_data);
  _gnutls_free_datum (&cert_signature);

  return result;
}

/**
 * gnutls_x509_crt_check_issuer - This function checks if the certificate given has the given issuer
 * @cert: is the certificate to be checked
 * @issuer: is the certificate of a possible issuer
 *
 * This function will check if the given certificate was issued by the
 * given issuer. It will return true (1) if the given certificate is issued
 * by the given issuer, and false (0) if not.
 *
 * A negative value is returned in case of an error.
 *
 **/
int
gnutls_x509_crt_check_issuer (gnutls_x509_crt_t cert,
                              gnutls_x509_crt_t issuer)
{
  return is_issuer (cert, issuer);
}

/* The algorithm used is:
 * 1. Check last certificate in the chain. If it is not verified return.
 * 2. Check if any certificates in the chain are revoked. If yes return.
 * 3. Try to verify the rest of certificates in the chain. If not verified return.
 * 4. Return 0.
 *
 * Note that the return value is an OR of GNUTLS_CERT_* elements.
 *
 * This function verifies a X.509 certificate list. The certificate list should
 * lead to a trusted CA in order to be trusted.
 */
static unsigned int
_gnutls_x509_verify_certificate (const gnutls_x509_crt_t * certificate_list,
                                 int clist_size,
                                 const gnutls_x509_crt_t * trusted_cas,
                                 int tcas_size,
                                 const gnutls_x509_crl_t * CRLs,
                                 int crls_size, unsigned int flags)
{
  int i = 0, ret;
  unsigned int status = 0, output;

  /* Verify the last certificate in the certificate path
   * against the trusted CA certificate list.
   *
   * If no CAs are present returns CERT_INVALID. Thus works
   * in self signed etc certificates.
   */
  ret = _gnutls_verify_certificate2 (certificate_list[clist_size - 1],
                                     trusted_cas, tcas_size, flags, &output);

  if (ret == 0)
    {
      /* if the last certificate in the certificate
       * list is invalid, then the certificate is not
       * trusted.
       */
      gnutls_assert ();
      status |= output;
      status |= GNUTLS_CERT_INVALID;
      return status;
    }

  /* Check for revoked certificates in the chain
   */
#ifdef ENABLE_PKI
  for (i = 0; i < clist_size; i++)
    {
      ret = gnutls_x509_crt_check_revocation (certificate_list[i],
                                              CRLs, crls_size);
      if (ret == 1)
        {                       /* revoked */
          status |= GNUTLS_CERT_REVOKED;
          status |= GNUTLS_CERT_INVALID;
          return status;
        }
    }
#endif

  /* Check if the last certificate in the path is self signed.
   * In that case ignore it (a certificate is trusted only if it
   * leads to a trusted party by us, not the server's).
   */
  if (gnutls_x509_crt_check_issuer (certificate_list[clist_size - 1],
                                    certificate_list[clist_size - 1]) > 0
      && clist_size > 0)
    {
      clist_size--;
    }

  /* Verify the certificate path (chain) 
   */
  for (i = clist_size - 1; i > 0; i--)
    {
      if (i - 1 < 0)
        break;

      /* note that here we disable this V1 CA flag. So that no version 1
       * certificates can exist in a supplied chain.
       */
      if (!(flags & GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT))
        flags ^= GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT;
      if ((ret = _gnutls_verify_certificate2 (certificate_list[i - 1],
                                              &certificate_list[i], 1, flags,
                                              NULL)) == 0)
        {
          status |= GNUTLS_CERT_INVALID;
          return status;
        }
    }

  return 0;
}

/* Reads the digest information.
 * we use DER here, although we should use BER. It works fine
 * anyway.
 */
static int
decode_ber_digest_info (const gnutls_datum_t * info,
                        gnutls_mac_algorithm_t * hash,
                        opaque * digest, int *digest_size)
{
  ASN1_TYPE dinfo = ASN1_TYPE_EMPTY;
  int result;
  char str[1024];
  int len;

  if ((result = asn1_create_element (_gnutls_get_gnutls_asn (),
                                     "GNUTLS.DigestInfo",
                                     &dinfo)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&dinfo, info->data, info->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  len = sizeof (str) - 1;
  result = asn1_read_value (dinfo, "digestAlgorithm.algorithm", str, &len);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
    }

  *hash = mhd_gtls_x509_oid2mac_algorithm (str);

  if (*hash == MHD_GNUTLS_MAC_UNKNOWN)
    {

      _gnutls_x509_log ("verify.c: HASH OID: %s\n", str);

      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return GNUTLS_E_UNKNOWN_ALGORITHM;
    }

  len = sizeof (str) - 1;
  result = asn1_read_value (dinfo, "digestAlgorithm.parameters", str, &len);
  /* To avoid permitting garbage in the parameters field, either the
     parameters field is not present, or it contains 0x05 0x00. */
  if (!
      (result == ASN1_ELEMENT_NOT_FOUND
       || (result == ASN1_SUCCESS && len == 2 && str[0] == 0x05
           && str[1] == 0x00)))
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return GNUTLS_E_ASN1_GENERIC_ERROR;
    }

  result = asn1_read_value (dinfo, "digest", digest, digest_size);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      asn1_delete_structure (&dinfo);
      return _gnutls_asn2err (result);
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
_pkcs1_rsa_verify_sig (const gnutls_datum_t * text,
                       const gnutls_datum_t * signature,
                       mpi_t * params, int params_len)
{
  gnutls_mac_algorithm_t hash = MHD_GNUTLS_MAC_UNKNOWN;
  int ret;
  opaque digest[MAX_HASH_SIZE], md[MAX_HASH_SIZE];
  int digest_size;
  GNUTLS_HASH_HANDLE hd;
  gnutls_datum_t decrypted;

  ret =
    mhd_gtls_pkcs1_rsa_decrypt (&decrypted, signature, params, params_len, 1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* decrypted is a BER encoded data of type DigestInfo
   */

  digest_size = sizeof (digest);
  if ((ret = decode_ber_digest_info (&decrypted, &hash, digest, &digest_size))
      != 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (&decrypted);
      return ret;
    }

  _gnutls_free_datum (&decrypted);

  if (digest_size != mhd_gnutls_hash_get_algo_len (hash))
    {
      gnutls_assert ();
      return GNUTLS_E_ASN1_GENERIC_ERROR;
    }

  hd = mhd_gtls_hash_init (hash);
  if (hd == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  mhd_gnutls_hash (hd, text->data, text->size);
  mhd_gnutls_hash_deinit (hd, md);

  if (memcmp (md, digest, digest_size) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_PK_SIG_VERIFY_FAILED;
    }

  return 0;
}

/* Hashes input data and verifies a DSA signature.
 */
static int
dsa_verify_sig (const gnutls_datum_t * text,
                const gnutls_datum_t * signature,
                mpi_t * params, int params_len)
{
  int ret;
  opaque _digest[MAX_HASH_SIZE];
  gnutls_datum_t digest;
  GNUTLS_HASH_HANDLE hd;

  hd = mhd_gtls_hash_init (MHD_GNUTLS_MAC_SHA1);
  if (hd == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  mhd_gnutls_hash (hd, text->data, text->size);
  mhd_gnutls_hash_deinit (hd, _digest);

  digest.data = _digest;
  digest.size = 20;

  ret = mhd_gtls_dsa_verify (&digest, signature, params, params_len);

  return ret;
}

/* Verifies the signature data, and returns 0 if not verified,
 * or 1 otherwise.
 */
static int
verify_sig (const gnutls_datum_t * tbs,
            const gnutls_datum_t * signature,
            gnutls_pk_algorithm_t pk,
            mpi_t * issuer_params, int issuer_params_size)
{

  switch (pk)
    {
    case MHD_GNUTLS_PK_RSA:

      if (_pkcs1_rsa_verify_sig
          (tbs, signature, issuer_params, issuer_params_size) != 0)
        {
          gnutls_assert ();
          return 0;
        }

      return 1;
      break;

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;

    }
}

/* verifies if the certificate is properly signed.
 * returns 0 on failure and 1 on success.
 * 
 * 'tbs' is the signed data
 * 'signature' is the signature!
 */
int
_gnutls_x509_verify_signature (const gnutls_datum_t * tbs,
                               const gnutls_datum_t * signature,
                               gnutls_x509_crt_t issuer)
{
  mpi_t issuer_params[MAX_PUBLIC_PARAMS_SIZE];
  int ret, issuer_params_size, i;

  /* Read the MPI parameters from the issuer's certificate.
   */
  issuer_params_size = MAX_PUBLIC_PARAMS_SIZE;
  ret =
    _gnutls_x509_crt_get_mpis (issuer, issuer_params, &issuer_params_size);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = verify_sig (tbs, signature, gnutls_x509_crt_get_pk_algorithm (issuer,
                                                                      NULL),
                    issuer_params, issuer_params_size);
  if (ret < 0)
    {
      gnutls_assert ();
    }

  /* release all allocated MPIs
   */
  for (i = 0; i < issuer_params_size; i++)
    {
      mhd_gtls_mpi_release (&issuer_params[i]);
    }

  return ret;
}

/* verifies if the certificate is properly signed.
 * returns 0 on failure and 1 on success.
 * 
 * 'tbs' is the signed data
 * 'signature' is the signature!
 */
int
_gnutls_x509_privkey_verify_signature (const gnutls_datum_t * tbs,
                                       const gnutls_datum_t * signature,
                                       gnutls_x509_privkey_t issuer)
{
  int ret;

  ret = verify_sig (tbs, signature, issuer->pk_algorithm, issuer->params,
                    issuer->params_size);
  if (ret < 0)
    {
      gnutls_assert ();
    }

  return ret;
}

/**
 * gnutls_x509_crt_list_verify - This function verifies the given certificate list
 * @cert_list: is the certificate list to be verified
 * @cert_list_length: holds the number of certificate in cert_list
 * @CA_list: is the CA list which will be used in verification
 * @CA_list_length: holds the number of CA certificate in CA_list
 * @CRL_list: holds a list of CRLs.
 * @CRL_list_length: the length of CRL list.
 * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
 * @verify: will hold the certificate verification output.
 *
 * This function will try to verify the given certificate list and return its status.
 * Note that expiration and activation dates are not checked
 * by this function, you should check them using the appropriate functions.
 *
 * If no flags are specified (0), this function will use the 
 * basicConstraints (2.5.29.19) PKIX extension. This means that only a certificate 
 * authority is allowed to sign a certificate.
 *
 * You must also check the peer's name in order to check if the verified 
 * certificate belongs to the actual peer. 
 *
 * The certificate verification output will be put in @verify and will be
 * one or more of the gnutls_certificate_status_t enumerated elements bitwise or'd.
 * For a more detailed verification status use gnutls_x509_crt_verify() per list
 * element.
 *
 * GNUTLS_CERT_INVALID: the certificate chain is not valid.
 *
 * GNUTLS_CERT_REVOKED: a certificate in the chain has been revoked.
 *
 * Returns 0 on success and a negative value in case of an error.
 *
 **/
int
gnutls_x509_crt_list_verify (const gnutls_x509_crt_t * cert_list,
                             int cert_list_length,
                             const gnutls_x509_crt_t * CA_list,
                             int CA_list_length,
                             const gnutls_x509_crl_t * CRL_list,
                             int CRL_list_length,
                             unsigned int flags, unsigned int *verify)
{
  if (cert_list == NULL || cert_list_length == 0)
    return GNUTLS_E_NO_CERTIFICATE_FOUND;

  /* Verify certificate 
   */
  *verify = _gnutls_x509_verify_certificate (cert_list, cert_list_length,
                                             CA_list, CA_list_length,
                                             CRL_list, CRL_list_length,
                                             flags);

  return 0;
}

/**
 * gnutls_x509_crt_verify - This function verifies the given certificate against a given trusted one
 * @cert: is the certificate to be verified
 * @CA_list: is one certificate that is considered to be trusted one
 * @CA_list_length: holds the number of CA certificate in CA_list
 * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
 * @verify: will hold the certificate verification output.
 *
 * This function will try to verify the given certificate and return its status. 
 * The verification output in this functions cannot be GNUTLS_CERT_NOT_VALID.
 *
 * Returns 0 on success and a negative value in case of an error.
 *
 **/
int
gnutls_x509_crt_verify (gnutls_x509_crt_t cert,
                        const gnutls_x509_crt_t * CA_list,
                        int CA_list_length,
                        unsigned int flags, unsigned int *verify)
{
  int ret;
  /* Verify certificate 
   */
  ret = _gnutls_verify_certificate2 (cert, CA_list, CA_list_length, flags,
                                     verify);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

#ifdef ENABLE_PKI

/**
 * gnutls_x509_crl_check_issuer - This function checks if the CRL given has the given issuer
 * @crl: is the CRL to be checked
 * @issuer: is the certificate of a possible issuer
 *
 * This function will check if the given CRL was issued by the
 * given issuer certificate. It will return true (1) if the given CRL was issued
 * by the given issuer, and false (0) if not.
 *
 * A negative value is returned in case of an error.
 *
 **/
int
gnutls_x509_crl_check_issuer (gnutls_x509_crl_t cert,
                              gnutls_x509_crt_t issuer)
{
  return is_crl_issuer (cert, issuer);
}

/**
 * gnutls_x509_crl_verify - This function verifies the given crl against a given trusted one
 * @crl: is the crl to be verified
 * @CA_list: is a certificate list that is considered to be trusted one
 * @CA_list_length: holds the number of CA certificates in CA_list
 * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
 * @verify: will hold the crl verification output.
 *
 * This function will try to verify the given crl and return its status.
 * See gnutls_x509_crt_list_verify() for a detailed description of
 * return values.
 *
 * Returns 0 on success and a negative value in case of an error.
 *
 **/
int
gnutls_x509_crl_verify (gnutls_x509_crl_t crl,
                        const gnutls_x509_crt_t * CA_list,
                        int CA_list_length, unsigned int flags,
                        unsigned int *verify)
{
  int ret;
  /* Verify crl 
   */
  ret = _gnutls_verify_crl2 (crl, CA_list, CA_list_length, flags, verify);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

/* The same as above, but here we've got a CRL.
 */
static int
is_crl_issuer (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer_cert)
{
  gnutls_datum_t dn1 = { NULL, 0 }, dn2 =
  {
  NULL, 0};
  int ret;

  ret = _gnutls_x509_crl_get_raw_issuer_dn (crl, &dn1);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = gnutls_x509_crt_get_raw_dn (issuer_cert, &dn2);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_x509_compare_raw_dn (&dn1, &dn2);

cleanup:
  _gnutls_free_datum (&dn1);
  _gnutls_free_datum (&dn2);

  return ret;
}

static inline gnutls_x509_crt_t
find_crl_issuer (gnutls_x509_crl_t crl,
                 const gnutls_x509_crt_t * trusted_cas, int tcas_size)
{
  int i;

  /* this is serial search. 
   */

  for (i = 0; i < tcas_size; i++)
    {
      if (is_crl_issuer (crl, trusted_cas[i]) == 1)
        return trusted_cas[i];
    }

  gnutls_assert ();
  return NULL;
}

/* 
 * Returns only 0 or 1. If 1 it means that the CRL
 * was successfuly verified.
 *
 * 'flags': an OR of the gnutls_certificate_verify_flags enumeration.
 *
 * Output will hold information about the verification
 * procedure. 
 */
static int
_gnutls_verify_crl2 (gnutls_x509_crl_t crl,
                     const gnutls_x509_crt_t * trusted_cas,
                     int tcas_size, unsigned int flags, unsigned int *output)
{
  /* CRL is ignored for now */
  gnutls_datum_t crl_signed_data = { NULL, 0 };
  gnutls_datum_t crl_signature = { NULL, 0 };
  gnutls_x509_crt_t issuer;
  int ret, result;

  if (output)
    *output = 0;

  if (tcas_size >= 1)
    issuer = find_crl_issuer (crl, trusted_cas, tcas_size);
  else
    {
      gnutls_assert ();
      if (output)
        *output |= GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_INVALID;
      return 0;
    }

  /* issuer is not in trusted certificate
   * authorities.
   */
  if (issuer == NULL)
    {
      gnutls_assert ();
      if (output)
        *output |= GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_INVALID;
      return 0;
    }

  if (!(flags & GNUTLS_VERIFY_DISABLE_CA_SIGN))
    {
      if (gnutls_x509_crt_get_ca_status (issuer, NULL) != 1)
        {
          gnutls_assert ();
          if (output)
            *output |= GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INVALID;
          return 0;
        }
    }

  result =
    _gnutls_x509_get_signed_data (crl->crl, "tbsCertList", &crl_signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result = _gnutls_x509_get_signature (crl->crl, "signature", &crl_signature);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret =
    _gnutls_x509_verify_signature (&crl_signed_data, &crl_signature, issuer);
  if (ret < 0)
    {
      gnutls_assert ();
    }
  else if (ret == 0)
    {
      gnutls_assert ();
      /* error. ignore it */
      if (output)
        *output |= GNUTLS_CERT_INVALID;
      ret = 0;
    }

  {
    int sigalg;

    sigalg = gnutls_x509_crl_get_signature_algorithm (crl);

    if (((sigalg == GNUTLS_SIGN_RSA_MD2) &&
         !(flags & GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2)) ||
        ((sigalg == GNUTLS_SIGN_RSA_MD5) &&
         !(flags & GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5)))
      {
        if (output)
          *output |= GNUTLS_CERT_INSECURE_ALGORITHM | GNUTLS_CERT_INVALID;
      }
  }

  result = ret;

cleanup:
  _gnutls_free_datum (&crl_signed_data);
  _gnutls_free_datum (&crl_signature);

  return result;
}

#endif
