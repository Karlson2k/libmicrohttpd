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

#ifdef ENABLE_PKI

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <gnutls_rsa_export.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <x509.h>
#include <pkcs12.h>
#include <dn.h>
#include <privkey.h>
#include <extensions.h>
#include <mpi.h>
#include <gnutls_algorithms.h>
#include <gnutls_num.h>
#include "gc.h"

#define PBES2_OID "1.2.840.113549.1.5.13"
#define PBKDF2_OID "1.2.840.113549.1.5.12"
#define DES_EDE3_CBC_OID "1.2.840.113549.3.7"
#define DES_CBC_OID "1.3.14.3.2.7"

/* oid_pbeWithSHAAnd3_KeyTripleDES_CBC */
#define PKCS12_PBE_3DES_SHA1_OID "1.2.840.113549.1.12.1.3"
#define PKCS12_PBE_ARCFOUR_SHA1_OID "1.2.840.113549.1.12.1.1"
#define PKCS12_PBE_RC2_40_SHA1_OID "1.2.840.113549.1.12.1.6"

struct pbkdf2_params
{
  opaque salt[32];
  int salt_size;
  unsigned int iter_count;
  unsigned int key_size;
};

struct pbe_enc_params
{
  enum MHD_GNUTLS_CipherAlgorithm cipher;
  opaque iv[8];
  int iv_size;
};

static int read_pbkdf2_params (ASN1_TYPE pbes2_asn,
                               const MHD_gnutls_datum_t * der,
                               struct pbkdf2_params *params);
static int read_pbe_enc_params (ASN1_TYPE pbes2_asn,
                                const MHD_gnutls_datum_t * der,
                                struct pbe_enc_params *params);
static int decrypt_data (schema_id, ASN1_TYPE pkcs8_asn, const char *root,
                         const char *password,
                         const struct pbkdf2_params *kdf_params,
                         const struct pbe_enc_params *enc_params,
                         MHD_gnutls_datum_t * decrypted_data);
static int decode_private_key_info (const MHD_gnutls_datum_t * der,
                                    MHD_gnutls_x509_privkey_t pkey);
static int readMHD_pkcs12_kdf_params (ASN1_TYPE pbes2_asn,
                                   struct pbkdf2_params *params);

#define PEM_PKCS8 "ENCRYPTED PRIVATE KEY"
#define PEM_UNENCRYPTED_PKCS8 "PRIVATE KEY"

/* Returns a negative error code if the encryption schema in
 * the OID is not supported. The schema ID is returned.
 */
static int
check_schema (const char *oid)
{

  if (strcmp (oid, PBES2_OID) == 0)
    return PBES2;

  if (strcmp (oid, PKCS12_PBE_3DES_SHA1_OID) == 0)
    return PKCS12_3DES_SHA1;

  if (strcmp (oid, PKCS12_PBE_ARCFOUR_SHA1_OID) == 0)
    return PKCS12_ARCFOUR_SHA1;

  if (strcmp (oid, PKCS12_PBE_RC2_40_SHA1_OID) == 0)
    return PKCS12_RC2_40_SHA1;

  MHD__gnutls_x509_log ("PKCS encryption schema OID '%s' is unsupported.\n", oid);

  return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
}

/* Read the parameters cipher, IV, salt etc using the given
 * schema ID.
 */
static int
read_pkcs_schema_params (schema_id schema, const char *password,
                         const opaque * data, int data_size,
                         struct pbkdf2_params *kdf_params,
                         struct pbe_enc_params *enc_params)
{
  ASN1_TYPE pbes2_asn = ASN1_TYPE_EMPTY;
  int result;
  MHD_gnutls_datum_t tmp;

  switch (schema)
    {

    case PBES2:

      /* Now check the key derivation and the encryption
       * functions.
       */
      if ((result =
           MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                                "PKIX1.pkcs-5-PBES2-params",
                                &pbes2_asn)) != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto error;
        }

      /* Decode the parameters.
       */
      result = MHD__asn1_der_decoding (&pbes2_asn, data, data_size, NULL);
      if (result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto error;
        }

      tmp.data = (opaque *) data;
      tmp.size = data_size;

      result = read_pbkdf2_params (pbes2_asn, &tmp, kdf_params);
      if (result < 0)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto error;
        }

      result = read_pbe_enc_params (pbes2_asn, &tmp, enc_params);
      if (result < 0)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto error;
        }

      MHD__asn1_delete_structure (&pbes2_asn);
      return 0;
      break;

    case PKCS12_3DES_SHA1:
    case PKCS12_ARCFOUR_SHA1:
    case PKCS12_RC2_40_SHA1:

      if ((schema) == PKCS12_3DES_SHA1)
        {
          enc_params->cipher = MHD_GNUTLS_CIPHER_3DES_CBC;
          enc_params->iv_size = 8;
        }
      else if ((schema) == PKCS12_ARCFOUR_SHA1)
        {
          enc_params->cipher = MHD_GNUTLS_CIPHER_ARCFOUR_128;
          enc_params->iv_size = 0;
        }
      else if ((schema) == PKCS12_RC2_40_SHA1)
        {
          enc_params->cipher = MHD_GNUTLS_CIPHER_RC2_40_CBC;
          enc_params->iv_size = 8;
        }

      if ((result =
           MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                                "PKIX1.pkcs-12-PbeParams",
                                &pbes2_asn)) != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto error;
        }

      /* Decode the parameters.
       */
      result = MHD__asn1_der_decoding (&pbes2_asn, data, data_size, NULL);
      if (result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto error;
        }

      result = readMHD_pkcs12_kdf_params (pbes2_asn, kdf_params);
      if (result < 0)
        {
          MHD_gnutls_assert ();
          goto error;
        }

      if (enc_params->iv_size)
        {
          result =
            MHD_pkcs12_string_to_key (2 /*IV*/, kdf_params->salt,
                                   kdf_params->salt_size,
                                   kdf_params->iter_count, password,
                                   enc_params->iv_size, enc_params->iv);
          if (result < 0)
            {
              MHD_gnutls_assert ();
              goto error;
            }

        }

      MHD__asn1_delete_structure (&pbes2_asn);

      return 0;
      break;

    }                           /* switch */

  return GNUTLS_E_UNKNOWN_CIPHER_TYPE;

error:
  MHD__asn1_delete_structure (&pbes2_asn);
  return result;
}

/* Converts a PKCS #8 key to
 * an internal structure (MHD_gnutls_private_key)
 * (normally a PKCS #1 encoded RSA key)
 */
static int
decode_pkcs8_key (const MHD_gnutls_datum_t * raw_key,
                  const char *password, MHD_gnutls_x509_privkey_t pkey)
{
  int result, len;
  char enc_oid[64];
  MHD_gnutls_datum_t tmp;
  ASN1_TYPE pbes2_asn = ASN1_TYPE_EMPTY, pkcs8_asn = ASN1_TYPE_EMPTY;
  int params_start, params_end, params_len;
  struct pbkdf2_params kdf_params;
  struct pbe_enc_params enc_params;
  schema_id schema;

  if ((result =
       MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                            "PKIX1.pkcs-8-EncryptedPrivateKeyInfo",
                            &pkcs8_asn)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }

  result = MHD__asn1_der_decoding (&pkcs8_asn, raw_key->data, raw_key->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }

  /* Check the encryption schema OID
   */
  len = sizeof (enc_oid);
  result =
    MHD__asn1_read_value (pkcs8_asn, "encryptionAlgorithm.algorithm",
                     enc_oid, &len);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  if ((result = check_schema (enc_oid)) < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  schema = result;

  /* Get the DER encoding of the parameters.
   */
  result =
    MHD__asn1_der_decoding_startEnd (pkcs8_asn, raw_key->data,
                                raw_key->size,
                                "encryptionAlgorithm.parameters",
                                &params_start, &params_end);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }
  params_len = params_end - params_start + 1;

  result =
    read_pkcs_schema_params (schema, password,
                             &raw_key->data[params_start],
                             params_len, &kdf_params, &enc_params);

  /* Parameters have been decoded. Now
   * decrypt the EncryptedData.
   */
  result =
    decrypt_data (schema, pkcs8_asn, "encryptedData", password,
                  &kdf_params, &enc_params, &tmp);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  MHD__asn1_delete_structure (&pkcs8_asn);

  result = decode_private_key_info (&tmp, pkey);
  MHD__gnutls_free_datum (&tmp);

  if (result < 0)
    {
      /* We've gotten this far. In the real world it's almost certain
       * that we're dealing with a good file, but wrong password.
       * Sadly like 90% of random data is somehow valid DER for the
       * a first small number of bytes, so no easy way to guarantee. */
      if (result == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND ||
          result == GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND ||
          result == GNUTLS_E_ASN1_DER_ERROR ||
          result == GNUTLS_E_ASN1_VALUE_NOT_FOUND ||
          result == GNUTLS_E_ASN1_GENERIC_ERROR ||
          result == GNUTLS_E_ASN1_VALUE_NOT_VALID ||
          result == GNUTLS_E_ASN1_TAG_ERROR ||
          result == GNUTLS_E_ASN1_TAG_IMPLICIT ||
          result == GNUTLS_E_ASN1_TYPE_ANY_ERROR ||
          result == GNUTLS_E_ASN1_SYNTAX_ERROR ||
          result == GNUTLS_E_ASN1_DER_OVERFLOW)
        {
          result = GNUTLS_E_DECRYPTION_FAILED;
        }

      MHD_gnutls_assert ();
      goto error;
    }

  return 0;

error:
  MHD__asn1_delete_structure (&pbes2_asn);
  MHD__asn1_delete_structure (&pkcs8_asn);
  return result;
}

/* Decodes an RSA privateKey from a PKCS8 structure.
 */
static int
_decode_pkcs8_rsa_key (ASN1_TYPE pkcs8_asn, MHD_gnutls_x509_privkey_t pkey)
{
  int ret;
  MHD_gnutls_datum_t tmp;

  ret = MHD__gnutls_x509_read_value (pkcs8_asn, "privateKey", &tmp, 0);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  pkey->key = MHD__gnutls_privkey_decode_pkcs1_rsa_key (&tmp, pkey);
  MHD__gnutls_free_datum (&tmp);
  if (pkey->key == NULL)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  return 0;

error:
  MHD_gnutls_x509_privkey_deinit (pkey);
  return ret;
}

static int
decode_private_key_info (const MHD_gnutls_datum_t * der,
                         MHD_gnutls_x509_privkey_t pkey)
{
  int result, len;
  opaque oid[64];
  ASN1_TYPE pkcs8_asn = ASN1_TYPE_EMPTY;

  if ((result =
       MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                            "PKIX1.pkcs-8-PrivateKeyInfo",
                            &pkcs8_asn)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }

  result = MHD__asn1_der_decoding (&pkcs8_asn, der->data, der->size, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }

  /* Check the private key algorithm OID
   */
  len = sizeof (oid);
  result =
    MHD__asn1_read_value (pkcs8_asn, "privateKeyAlgorithm.algorithm", oid, &len);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }

  /* we only support RSA and DSA private keys.
   */
  if (strcmp ((const char*) oid, PK_PKIX1_RSA_OID) == 0)
    pkey->pk_algorithm = MHD_GNUTLS_PK_RSA;
  else
    {
      MHD_gnutls_assert ();
      MHD__gnutls_x509_log
        ("PKCS #8 private key OID '%s' is unsupported.\n", oid);
      result = GNUTLS_E_UNKNOWN_PK_ALGORITHM;
      goto error;
    }

  /* Get the DER encoding of the actual private key.
   */

  if (pkey->pk_algorithm == MHD_GNUTLS_PK_RSA)
    result = _decode_pkcs8_rsa_key (pkcs8_asn, pkey);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  result = 0;

error:
  MHD__asn1_delete_structure (&pkcs8_asn);

  return result;

}

/**
 * MHD_gnutls_x509_privkey_import_pkcs8 - This function will import a DER or PEM PKCS8 encoded key
 * @key: The structure to store the parsed key
 * @data: The DER or PEM encoded key.
 * @format: One of DER or PEM
 * @password: the password to decrypt the key (if it is encrypted).
 * @flags: 0 if encrypted or GNUTLS_PKCS_PLAIN if not encrypted.
 *
 * This function will convert the given DER or PEM encoded PKCS8 2.0 encrypted key
 * to the native MHD_gnutls_x509_privkey_t format. The output will be stored in @key.
 * Both RSA and DSA keys can be imported, and flags can only be used to indicate
 * an unencrypted key.
 *
 * The @password can be either ASCII or UTF-8 in the default PBES2
 * encryption schemas, or ASCII for the PKCS12 schemas.
 *
 * If the Certificate is PEM encoded it should have a header of "ENCRYPTED PRIVATE KEY",
 * or "PRIVATE KEY". You only need to specify the flags if the key is DER encoded, since
 * in that case the encryption status cannot be auto-detected.
 *
 * Returns 0 on success.
 *
 **/
int
MHD_gnutls_x509_privkey_import_pkcs8 (MHD_gnutls_x509_privkey_t key,
                                  const MHD_gnutls_datum_t * data,
                                  MHD_gnutls_x509_crt_fmt_t format,
                                  const char *password, unsigned int flags)
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

  /* If the Certificate is in PEM format then decode it
   */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      /* Try the first header
       */
      result =
        MHD__gnutls_fbase64_decode (PEM_UNENCRYPTED_PKCS8,
                                data->data, data->size, &out);

      if (result < 0)
        {                       /* Try the encrypted header
                                 */
          result =
            MHD__gnutls_fbase64_decode (PEM_PKCS8, data->data, data->size, &out);

          if (result <= 0)
            {
              if (result == 0)
                result = GNUTLS_E_INTERNAL_ERROR;
              MHD_gnutls_assert ();
              return result;
            }
        }
      else if (flags == 0)
        flags |= GNUTLS_PKCS_PLAIN;

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }

  if (flags & GNUTLS_PKCS_PLAIN)
    {
      result = decode_private_key_info (&_data, key);
    }
  else
    {                           /* encrypted. */
      result = decode_pkcs8_key (&_data, password, key);
    }

  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  if (need_free)
    MHD__gnutls_free_datum (&_data);

  /* The key has now been decoded.
   */

  return 0;

cleanup:
  key->pk_algorithm = MHD_GNUTLS_PK_UNKNOWN;
  if (need_free)
    MHD__gnutls_free_datum (&_data);
  return result;
}

/* Reads the PBKDF2 parameters.
 */
static int
read_pbkdf2_params (ASN1_TYPE pbes2_asn,
                    const MHD_gnutls_datum_t * der, struct pbkdf2_params *params)
{
  int params_start, params_end;
  int params_len, len, result;
  ASN1_TYPE pbkdf2_asn = ASN1_TYPE_EMPTY;
  char oid[64];

  memset (params, 0, sizeof (params));

  /* Check the key derivation algorithm
   */
  len = sizeof (oid);
  result =
    MHD__asn1_read_value (pbes2_asn, "keyDerivationFunc.algorithm", oid, &len);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }
  MHD__gnutls_hard_log ("keyDerivationFunc.algorithm: %s\n", oid);

  if (strcmp (oid, PBKDF2_OID) != 0)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_x509_log
        ("PKCS #8 key derivation OID '%s' is unsupported.\n", oid);
      return MHD_gtls_asn2err (result);
    }

  result =
    MHD__asn1_der_decoding_startEnd (pbes2_asn, der->data, der->size,
                                "keyDerivationFunc.parameters",
                                &params_start, &params_end);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }
  params_len = params_end - params_start + 1;

  /* Now check the key derivation and the encryption
   * functions.
   */
  if ((result =
       MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                            "PKIX1.pkcs-5-PBKDF2-params",
                            &pbkdf2_asn)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result =
    MHD__asn1_der_decoding (&pbkdf2_asn, &der->data[params_start],
                       params_len, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }

  /* read the salt */
  params->salt_size = sizeof (params->salt);
  result =
    MHD__asn1_read_value (pbkdf2_asn, "salt.specified", params->salt,
                     &params->salt_size);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }
  MHD__gnutls_hard_log ("salt.specified.size: %d\n", params->salt_size);

  /* read the iteration count
   */
  result =
    MHD__gnutls_x509_read_uint (pbkdf2_asn, "iterationCount",
                            &params->iter_count);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      goto error;
    }
  MHD__gnutls_hard_log ("iterationCount: %d\n", params->iter_count);

  /* read the keylength, if it is set.
   */
  result =
    MHD__gnutls_x509_read_uint (pbkdf2_asn, "keyLength", &params->key_size);
  if (result < 0)
    {
      params->key_size = 0;
    }
  MHD__gnutls_hard_log ("keyLength: %d\n", params->key_size);

  /* We don't read the PRF. We only use the default.
   */

  return 0;

error:
  MHD__asn1_delete_structure (&pbkdf2_asn);
  return result;

}

/* Reads the PBE parameters from PKCS-12 schemas (*&#%*&#% RSA).
 */
static int
readMHD_pkcs12_kdf_params (ASN1_TYPE pbes2_asn, struct pbkdf2_params *params)
{
  int result;

  memset (params, 0, sizeof (params));

  /* read the salt */
  params->salt_size = sizeof (params->salt);
  result =
    MHD__asn1_read_value (pbes2_asn, "salt", params->salt, &params->salt_size);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }
  MHD__gnutls_hard_log ("salt.size: %d\n", params->salt_size);

  /* read the iteration count
   */
  result =
    MHD__gnutls_x509_read_uint (pbes2_asn, "iterations", &params->iter_count);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      goto error;
    }
  MHD__gnutls_hard_log ("iterationCount: %d\n", params->iter_count);

  params->key_size = 0;

  return 0;

error:
  return result;

}

/* Converts an OID to a gnutls cipher type.
 */
static int
oid2cipher (const char *oid, enum MHD_GNUTLS_CipherAlgorithm *algo)
{

  *algo = 0;

  if (strcmp (oid, DES_EDE3_CBC_OID) == 0)
    {
      *algo = MHD_GNUTLS_CIPHER_3DES_CBC;
      return 0;
    }

  if (strcmp (oid, DES_CBC_OID) == 0)
    {
      *algo = MHD_GNUTLS_CIPHER_DES_CBC;
      return 0;
    }

  MHD__gnutls_x509_log ("PKCS #8 encryption OID '%s' is unsupported.\n", oid);
  return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
}

static int
read_pbe_enc_params (ASN1_TYPE pbes2_asn,
                     const MHD_gnutls_datum_t * der,
                     struct pbe_enc_params *params)
{
  int params_start, params_end;
  int params_len, len, result;
  ASN1_TYPE pbe_asn = ASN1_TYPE_EMPTY;
  char oid[64];

  memset (params, 0, sizeof (params));

  /* Check the encryption algorithm
   */
  len = sizeof (oid);
  result =
    MHD__asn1_read_value (pbes2_asn, "encryptionScheme.algorithm", oid, &len);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      goto error;
    }
  MHD__gnutls_hard_log ("encryptionScheme.algorithm: %s\n", oid);

  if ((result = oid2cipher (oid, &params->cipher)) < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  result =
    MHD__asn1_der_decoding_startEnd (pbes2_asn, der->data, der->size,
                                "encryptionScheme.parameters",
                                &params_start, &params_end);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }
  params_len = params_end - params_start + 1;

  /* Now check the encryption parameters.
   */
  if ((result =
       MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                            "PKIX1.pkcs-5-des-EDE3-CBC-params",
                            &pbe_asn)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result =
    MHD__asn1_der_decoding (&pbe_asn, &der->data[params_start], params_len, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }

  /* read the IV */
  params->iv_size = sizeof (params->iv);
  result = MHD__asn1_read_value (pbe_asn, "", params->iv, &params->iv_size);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }
  MHD__gnutls_hard_log ("IV.size: %d\n", params->iv_size);

  return 0;

error:
  MHD__asn1_delete_structure (&pbe_asn);
  return result;

}

static int
decrypt_data (schema_id schema, ASN1_TYPE pkcs8_asn,
              const char *root, const char *password,
              const struct pbkdf2_params *kdf_params,
              const struct pbe_enc_params *enc_params,
              MHD_gnutls_datum_t * decrypted_data)
{
  int result;
  int data_size;
  opaque *data = NULL, *key = NULL;
  MHD_gnutls_datum_t dkey, d_iv;
  cipher_hd_t ch = NULL;
  int key_size;

  data_size = 0;
  result = MHD__asn1_read_value (pkcs8_asn, root, NULL, &data_size);
  if (result != ASN1_MEM_ERROR)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  data = MHD_gnutls_malloc (data_size);
  if (data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = MHD__asn1_read_value (pkcs8_asn, root, data, &data_size);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto error;
    }

  if (kdf_params->key_size == 0)
    {
      key_size = MHD__gnutls_cipher_get_key_size (enc_params->cipher);
    }
  else
    key_size = kdf_params->key_size;

  key = MHD_gnutls_alloca (key_size);
  if (key == NULL)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto error;
    }

  /* generate the key
   */
  if (schema == PBES2)
    {
      result = MHD_gc_pbkdf2_sha1 (password, strlen (password),
				   (const char*) kdf_params->salt, kdf_params->salt_size,
				   kdf_params->iter_count,
				   (char*) key, key_size);

      if (result != GC_OK)
        {
          MHD_gnutls_assert ();
          result = GNUTLS_E_DECRYPTION_FAILED;
          goto error;
        }
    }
  else
    {
      result =
        MHD_pkcs12_string_to_key (1 /*KEY*/, kdf_params->salt,
                               kdf_params->salt_size,
                               kdf_params->iter_count, password,
                               key_size, key);

      if (result < 0)
        {
          MHD_gnutls_assert ();
          goto error;
        }
    }

  /* do the decryption.
   */
  dkey.data = key;
  dkey.size = key_size;

  d_iv.data = (opaque *) enc_params->iv;
  d_iv.size = enc_params->iv_size;
  ch = MHD_gtls_cipher_init (enc_params->cipher, &dkey, &d_iv);

  MHD_gnutls_afree (key);
  key = NULL;

  if (ch == NULL)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_DECRYPTION_FAILED;
      goto error;
    }

  result = MHD_gtls_cipher_decrypt (ch, data, data_size);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto error;
    }

  decrypted_data->data = data;

  if (MHD_gtls_cipher_get_block_size (enc_params->cipher) != 1)
    decrypted_data->size = data_size - data[data_size - 1];
  else
    decrypted_data->size = data_size;

  MHD_gnutls_cipher_deinit (ch);

  return 0;

error:
  MHD_gnutls_free (data);
  MHD_gnutls_afree (key);
  if (ch != NULL)
    MHD_gnutls_cipher_deinit (ch);
  return result;
}


#endif
