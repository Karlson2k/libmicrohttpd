/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
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
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include <gnutls_cert.h>
#include <auth_cert.h>
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "libtasn1.h"
#include "gnutls_datum.h"
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include <gnutls_record.h>
#include <gnutls_sig.h>
#include <gnutls_state.h>
#include <gnutls_pk.h>
#include <gnutls_str.h>
#include <debug.h>
#include <x509_b64.h>
#include <gnutls_x509.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


/* x509 */
#include "common.h"
#include "x509.h"
#include "verify.h"
#include "mpi.h"
#include "pkcs7.h"
#include "privkey.h"


/*
 * some x509 certificate parsing functions.
 */

/* Check if the number of bits of the key in the certificate
 * is unacceptable.
  */
inline static int
check_bits (MHD_gnutls_x509_crt_t crt, unsigned int max_bits)
{
  int ret;
  unsigned int bits;

  ret = MHD_gnutls_x509_crt_get_pk_algorithm (crt, &bits);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  if (bits > max_bits && max_bits > 0)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_CONSTRAINT_ERROR;
    }

  return 0;
}


#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) { \
	if (peer_certificate_list[x]) \
		MHD_gnutls_x509_crt_deinit(peer_certificate_list[x]); \
	} \
	MHD_gnutls_free( peer_certificate_list)

/*-
  * MHD__gnutls_x509_cert_verify_peers - This function returns the peer's certificate status
  * @session: is a gnutls session
  *
  * This function will try to verify the peer's certificate and return its status (TRUSTED, REVOKED etc.).
  * The return value (status) should be one of the MHD_gnutls_certificate_status_t enumerated elements.
  * However you must also check the peer's name in order to check if the verified certificate belongs to the
  * actual peer. Returns a negative error code in case of an error, or GNUTLS_E_NO_CERTIFICATE_FOUND if no certificate was sent.
  *
  -*/
int
MHD__gnutls_x509_cert_verify_peers (MHD_gtls_session_t session,
                                unsigned int *status)
{
  cert_auth_info_t info;
  MHD_gtls_cert_credentials_t cred;
  MHD_gnutls_x509_crt_t *peer_certificate_list;
  int peer_certificate_list_size, i, x, ret;

  CHECK_AUTH (MHD_GNUTLS_CRD_CERTIFICATE, GNUTLS_E_INVALID_REQUEST);

  info = MHD_gtls_get_auth_info (session);
  if (info == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  cred = (MHD_gtls_cert_credentials_t)
    MHD_gtls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  if (info->raw_certificate_list == NULL || info->ncerts == 0)
    return GNUTLS_E_NO_CERTIFICATE_FOUND;

  if (info->ncerts > cred->verify_depth && cred->verify_depth > 0)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_CONSTRAINT_ERROR;
    }

  /* generate a list of MHD_gnutls_certs based on the auth info
   * raw certs.
   */
  peer_certificate_list_size = info->ncerts;
  peer_certificate_list =
    MHD_gnutls_calloc (1,
                   peer_certificate_list_size * sizeof (MHD_gnutls_x509_crt_t));
  if (peer_certificate_list == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  for (i = 0; i < peer_certificate_list_size; i++)
    {
      ret = MHD_gnutls_x509_crt_init (&peer_certificate_list[i]);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          CLEAR_CERTS;
          return ret;
        }

      ret =
        MHD_gnutls_x509_crt_import (peer_certificate_list[i],
                                &info->raw_certificate_list[i],
                                GNUTLS_X509_FMT_DER);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          CLEAR_CERTS;
          return ret;
        }

      ret = check_bits (peer_certificate_list[i], cred->verify_bits);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          CLEAR_CERTS;
          return ret;
        }

    }

  /* Verify certificate
   */
  ret =
    MHD_gnutls_x509_crt_list_verify (peer_certificate_list,
                                 peer_certificate_list_size,
                                 cred->x509_ca_list, cred->x509_ncas,
                                 cred->x509_crl_list, cred->x509_ncrls,
                                 cred->verify_flags, status);

  CLEAR_CERTS;

  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  return 0;
}

/*
 * Read certificates and private keys, from memory etc.
 */

/* returns error if the certificate has different algorithm than
 * the given key parameters.
 */
static int
MHD__gnutls_check_key_cert_match (MHD_gtls_cert_credentials_t res)
{
  MHD_gnutls_datum_t cid;
  MHD_gnutls_datum_t kid;
  unsigned pk = res->cert_list[res->ncerts - 1][0].subject_pk_algorithm;

  if (res->pkey[res->ncerts - 1].pk_algorithm != pk)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
    }

  MHD__gnutls_x509_write_rsa_params (res->pkey[res->ncerts - 1].params,
                                 res->pkey[res->ncerts -
                                           1].params_size, &kid);


  MHD__gnutls_x509_write_rsa_params (res->cert_list[res->ncerts - 1][0].params,
                                 res->cert_list[res->ncerts -
                                                1][0].params_size, &cid);

  if (cid.size != kid.size)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (&kid);
      MHD__gnutls_free_datum (&cid);
      return GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
    }

  if (memcmp (kid.data, cid.data, kid.size) != 0)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (&kid);
      MHD__gnutls_free_datum (&cid);
      return GNUTLS_E_CERTIFICATE_KEY_MISMATCH;
    }

  MHD__gnutls_free_datum (&kid);
  MHD__gnutls_free_datum (&cid);
  return 0;
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a MHD_gnutls_cert structure.
 * Returns the number of certificates parsed.
 */
static int
parse_crt_mem (MHD_gnutls_cert ** cert_list, unsigned *ncerts,
               MHD_gnutls_x509_crt_t cert)
{
  int i;
  int ret;

  i = *ncerts + 1;

  *cert_list =
    (MHD_gnutls_cert *) MHD_gtls_realloc_fast (*cert_list,
                                           i * sizeof (MHD_gnutls_cert));

  if (*cert_list == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = MHD_gtls_x509_crt_to_gcert (&cert_list[0][i - 1], cert, 0);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  *ncerts = i;

  return 1;                     /* one certificate parsed */
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a MHD_gnutls_cert structure. 
 * Returns the number of certificates parsed.
 */
static int
parse_der_cert_mem (MHD_gnutls_cert ** cert_list, unsigned *ncerts,
                    const void *input_cert, int input_cert_size)
{
  MHD_gnutls_datum_t tmp;
  MHD_gnutls_x509_crt_t cert;
  int ret;

  ret = MHD_gnutls_x509_crt_init (&cert);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  tmp.data = (opaque *) input_cert;
  tmp.size = input_cert_size;

  ret = MHD_gnutls_x509_crt_import (cert, &tmp, GNUTLS_X509_FMT_DER);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      MHD_gnutls_x509_crt_deinit (cert);
      return ret;
    }

  ret = parse_crt_mem (cert_list, ncerts, cert);
  MHD_gnutls_x509_crt_deinit (cert);

  return ret;
}

/* Reads a base64 encoded certificate list from memory and stores it to
 * a MHD_gnutls_cert structure. Returns the number of certificate parsed.
 */
static int
parse_pem_cert_mem (MHD_gnutls_cert ** cert_list, unsigned *ncerts,
                    const char *input_cert, int input_cert_size)
{
  int size, siz2, i;
  const char *ptr;
  opaque *ptr2;
  MHD_gnutls_datum_t tmp;
  int ret, count;

  /* move to the certificate
   */
  ptr = MHD_memmem (input_cert, input_cert_size,
                PEM_CERT_SEP, sizeof (PEM_CERT_SEP) - 1);
  if (ptr == NULL)
    ptr = MHD_memmem (input_cert, input_cert_size,
                  PEM_CERT_SEP2, sizeof (PEM_CERT_SEP2) - 1);

  if (ptr == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_BASE64_DECODING_ERROR;
    }
  size = input_cert_size - (ptr - input_cert);

  i = *ncerts + 1;
  count = 0;

  do
    {

      siz2 = MHD__gnutls_fbase64_decode (NULL, (const unsigned char*) ptr, size, &ptr2);

      if (siz2 < 0)
        {
          MHD_gnutls_assert ();
          return GNUTLS_E_BASE64_DECODING_ERROR;
        }

      *cert_list =
        (MHD_gnutls_cert *) MHD_gtls_realloc_fast (*cert_list,
                                               i * sizeof (MHD_gnutls_cert));

      if (*cert_list == NULL)
        {
          MHD_gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }

      tmp.data = ptr2;
      tmp.size = siz2;

      ret = MHD_gtls_x509_raw_cert_to_gcert (&cert_list[0][i - 1], &tmp, 0);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }
      MHD__gnutls_free_datum (&tmp);        /* free ptr2 */

      /* now we move ptr after the pem header
       */
      ptr++;
      /* find the next certificate (if any)
       */
      size = input_cert_size - (ptr - input_cert);

      if (size > 0)
        {
          char *ptr3;

          ptr3 = MHD_memmem (ptr, size, PEM_CERT_SEP, sizeof (PEM_CERT_SEP) - 1);
          if (ptr3 == NULL)
            ptr3 = MHD_memmem (ptr, size, PEM_CERT_SEP2,
                           sizeof (PEM_CERT_SEP2) - 1);

          ptr = ptr3;
        }
      else
        ptr = NULL;

      i++;
      count++;

    }
  while (ptr != NULL);

  *ncerts = i - 1;

  return count;
}



/* Reads a DER or PEM certificate from memory
 */
static int
read_cert_mem (MHD_gtls_cert_credentials_t res, const void *cert,
               int cert_size, MHD_gnutls_x509_crt_fmt_t type)
{
  int ret;

  /* allocate space for the certificate to add
   */
  res->cert_list = MHD_gtls_realloc_fast (res->cert_list,
                                          (1 +
                                           res->ncerts) *
                                          sizeof (MHD_gnutls_cert *));
  if (res->cert_list == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list_length = MHD_gtls_realloc_fast (res->cert_list_length,
                                                 (1 +
                                                  res->ncerts) *
                                                 sizeof (int));
  if (res->cert_list_length == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list[res->ncerts] = NULL;   /* for realloc */
  res->cert_list_length[res->ncerts] = 0;

  if (type == GNUTLS_X509_FMT_DER)
    ret = parse_der_cert_mem (&res->cert_list[res->ncerts],
                                &res->cert_list_length[res->ncerts],
			      cert, cert_size);
  else
    ret =
      parse_pem_cert_mem (&res->cert_list[res->ncerts],
                          &res->cert_list_length[res->ncerts], cert,
                          cert_size);

  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  return ret;
}


int
MHD__gnutls_x509_privkey_to_gkey (MHD_gnutls_privkey * dest,
                              MHD_gnutls_x509_privkey_t src)
{
  int i, ret;

  memset (dest, 0, sizeof (MHD_gnutls_privkey));

  for (i = 0; i < src->params_size; i++)
    {
      dest->params[i] = MHD__gnutls_mpi_copy (src->params[i]);
      if (dest->params[i] == NULL)
        {
          MHD_gnutls_assert ();
          ret = GNUTLS_E_MEMORY_ERROR;
          goto cleanup;
        }
    }

  dest->pk_algorithm = src->pk_algorithm;
  dest->params_size = src->params_size;

  return 0;

cleanup:

  for (i = 0; i < src->params_size; i++)
    {
      MHD_gtls_mpi_release (&dest->params[i]);
    }
  return ret;
}

void
MHD_gtls_gkey_deinit (MHD_gnutls_privkey * key)
{
  int i;
  if (key == NULL)
    return;

  for (i = 0; i < key->params_size; i++)
    {
      MHD_gtls_mpi_release (&key->params[i]);
    }
}

int
MHD__gnutls_x509_raw_privkey_to_gkey (MHD_gnutls_privkey * privkey,
                                  const MHD_gnutls_datum_t * raw_key,
                                  MHD_gnutls_x509_crt_fmt_t type)
{
  MHD_gnutls_x509_privkey_t tmpkey;
  int ret;

  ret = MHD_gnutls_x509_privkey_init (&tmpkey);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  ret = MHD_gnutls_x509_privkey_import (tmpkey, raw_key, type);

#ifdef ENABLE_PKI
  /* If normal key decoding doesn't work try decoding a plain PKCS #8 key */
  if (ret < 0)
    ret =
      MHD_gnutls_x509_privkey_import_pkcs8 (tmpkey, raw_key, type, NULL,
                                        GNUTLS_PKCS_PLAIN);
#endif

  if (ret < 0)
    {
      MHD_gnutls_assert ();
      MHD_gnutls_x509_privkey_deinit (tmpkey);
      return ret;
    }

  ret = MHD__gnutls_x509_privkey_to_gkey (privkey, tmpkey);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      MHD_gnutls_x509_privkey_deinit (tmpkey);
      return ret;
    }

  MHD_gnutls_x509_privkey_deinit (tmpkey);

  return 0;
}

/* Reads a PEM encoded PKCS-1 RSA/DSA private key from memory.  Type
 * indicates the certificate format.  KEY can be NULL, to indicate
 * that GnuTLS doesn't know the private key.
 */
static int
read_key_mem (MHD_gtls_cert_credentials_t res,
              const void *key, int key_size, MHD_gnutls_x509_crt_fmt_t type)
{
  int ret;
  MHD_gnutls_datum_t tmp;

  /* allocate space for the pkey list
   */
  res->pkey =
    MHD_gtls_realloc_fast (res->pkey,
                           (res->ncerts + 1) * sizeof (MHD_gnutls_privkey));
  if (res->pkey == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  if (key)
    {
      tmp.data = (opaque *) key;
      tmp.size = key_size;

      ret =
        MHD__gnutls_x509_raw_privkey_to_gkey (&res->pkey[res->ncerts], &tmp,
                                          type);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }
    }
  else
    memset (&res->pkey[res->ncerts], 0, sizeof (MHD_gnutls_privkey));

  return 0;
}

/**
  * MHD__gnutls_certificate_set_x509_key_mem - Used to set keys in a MHD_gtls_cert_credentials_t structure
  * @res: is an #MHD_gtls_cert_credentials_t structure.
  * @cert: contains a certificate list (path) for the specified private key
  * @key: is the private key, or %NULL
  * @type: is PEM or DER
  *
  * This function sets a certificate/private key pair in the
  * MHD_gtls_cert_credentials_t structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  * Currently are supported: RSA PKCS-1 encoded private keys,
  * DSA private keys.
  *
  * DSA private keys are encoded the OpenSSL way, which is an ASN.1
  * DER sequence of 6 INTEGERs - version, p, q, g, pub, priv.
  *
  * Note that the keyUsage (2.5.29.15) PKIX extension in X.509 certificates
  * is supported. This means that certificates intended for signing cannot
  * be used for ciphersuites that require encryption.
  *
  * If the certificate and the private key are given in PEM encoding
  * then the strings that hold their values must be null terminated.
  *
  * The @key may be %NULL if you are using a sign callback, see
  * MHD_gtls_sign_callback_set().
  *
  * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
  **/
int
MHD__gnutls_certificate_set_x509_key_mem (MHD_gtls_cert_credentials_t
                                         res, const MHD_gnutls_datum_t * cert,
                                         const MHD_gnutls_datum_t * key,
                                         MHD_gnutls_x509_crt_fmt_t type)
{
  int ret;

  /* this should be first
   */
  if ((ret = read_key_mem (res, key ? key->data : NULL,
                           key ? key->size : 0, type)) < 0)
    return ret;

  if ((ret = read_cert_mem (res, cert->data, cert->size, type)) < 0)
    return ret;

  res->ncerts++;

  if (key && (ret = MHD__gnutls_check_key_cert_match (res)) < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  return 0;
}

static int
generate_rdn_seq (MHD_gtls_cert_credentials_t res)
{
  MHD_gnutls_datum_t tmp;
  int ret;
  unsigned size, i;
  opaque *pdata;

  /* Generate the RDN sequence
   * This will be sent to clients when a certificate
   * request message is sent.
   */

  /* FIXME: in case of a client it is not needed
   * to do that. This would save time and memory.
   * However we don't have that information available
   * here.
   */

  size = 0;
  for (i = 0; i < res->x509_ncas; i++)
    {
      if ((ret = MHD_gnutls_x509_crt_get_raw_dn (res->x509_ca_list[i], &tmp)) < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }
      size += (2 + tmp.size);
      MHD__gnutls_free_datum (&tmp);
    }

  if (res->x509_rdn_sequence.data != NULL)
    MHD_gnutls_free (res->x509_rdn_sequence.data);

  res->x509_rdn_sequence.data = MHD_gnutls_malloc (size);
  if (res->x509_rdn_sequence.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  res->x509_rdn_sequence.size = size;

  pdata = res->x509_rdn_sequence.data;

  for (i = 0; i < res->x509_ncas; i++)
    {
      if ((ret = MHD_gnutls_x509_crt_get_raw_dn (res->x509_ca_list[i], &tmp)) < 0)
        {
          MHD__gnutls_free_datum (&res->x509_rdn_sequence);
          MHD_gnutls_assert ();
          return ret;
        }

      MHD_gtls_write_datum16 (pdata, tmp);
      pdata += (2 + tmp.size);
      MHD__gnutls_free_datum (&tmp);
    }

  return 0;
}

/* Returns 0 if it's ok to use the enum MHD_GNUTLS_KeyExchangeAlgorithm with this
 * certificate (uses the KeyUsage field).
 */
int
MHD__gnutls_check_key_usage (const MHD_gnutls_cert * cert,
                         enum MHD_GNUTLS_KeyExchangeAlgorithm alg)
{
  unsigned int key_usage = 0;
  int encipher_type;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (MHD_gtls_map_kx_get_cred (alg, 1) == MHD_GNUTLS_CRD_CERTIFICATE ||
      MHD_gtls_map_kx_get_cred (alg, 0) == MHD_GNUTLS_CRD_CERTIFICATE)
    {

      key_usage = cert->key_usage;

      encipher_type = MHD_gtls_kx_encipher_type (alg);

      if (key_usage != 0 && encipher_type != CIPHER_IGN)
        {
          /* If key_usage has been set in the certificate
           */

          if (encipher_type == CIPHER_ENCRYPT)
            {
              /* If the key exchange method requires an encipher
               * type algorithm, and key's usage does not permit
               * encipherment, then fail.
               */
              if (!(key_usage & KEY_KEY_ENCIPHERMENT))
                {
                  MHD_gnutls_assert ();
                  return GNUTLS_E_KEY_USAGE_VIOLATION;
                }
            }

          if (encipher_type == CIPHER_SIGN)
            {
              /* The same as above, but for sign only keys
               */
              if (!(key_usage & KEY_DIGITAL_SIGNATURE))
                {
                  MHD_gnutls_assert ();
                  return GNUTLS_E_KEY_USAGE_VIOLATION;
                }
            }
        }
    }
  return 0;
}



static int
parse_pem_ca_mem (MHD_gnutls_x509_crt_t ** cert_list, unsigned *ncerts,
                  const opaque * input_cert, int input_cert_size)
{
  int i, size;
  const opaque *ptr;
  MHD_gnutls_datum_t tmp;
  int ret, count;

  /* move to the certificate
   */
  ptr = MHD_memmem (input_cert, input_cert_size,
                PEM_CERT_SEP, sizeof (PEM_CERT_SEP) - 1);
  if (ptr == NULL)
    ptr = MHD_memmem (input_cert, input_cert_size,
                  PEM_CERT_SEP2, sizeof (PEM_CERT_SEP2) - 1);

  if (ptr == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_BASE64_DECODING_ERROR;
    }
  size = input_cert_size - (ptr - input_cert);

  i = *ncerts + 1;
  count = 0;

  do
    {

      *cert_list =
        (MHD_gnutls_x509_crt_t *) MHD_gtls_realloc_fast (*cert_list,
                                                     i *
                                                     sizeof
                                                     (MHD_gnutls_x509_crt_t));

      if (*cert_list == NULL)
        {
          MHD_gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }

      ret = MHD_gnutls_x509_crt_init (&cert_list[0][i - 1]);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }

      tmp.data = (opaque *) ptr;
      tmp.size = size;

      ret =
        MHD_gnutls_x509_crt_import (cert_list[0][i - 1],
                                &tmp, GNUTLS_X509_FMT_PEM);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }

      /* now we move ptr after the pem header
       */
      ptr++;
      size--;
      /* find the next certificate (if any)
       */

      if (size > 0)
        {
          char *ptr3;

          ptr3 = MHD_memmem (ptr, size, PEM_CERT_SEP, sizeof (PEM_CERT_SEP) - 1);
          if (ptr3 == NULL)
            ptr3 = MHD_memmem (ptr, size,
                           PEM_CERT_SEP2, sizeof (PEM_CERT_SEP2) - 1);

          ptr = (const opaque *) ptr3;
          size = input_cert_size - (ptr - input_cert);
        }
      else
        ptr = NULL;

      i++;
      count++;

    }
  while (ptr != NULL);

  *ncerts = i - 1;

  return count;
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a MHD_gnutls_cert structure.
 * returns the number of certificates parsed.
 */
static int
parse_der_ca_mem (MHD_gnutls_x509_crt_t ** cert_list, unsigned *ncerts,
                  const void *input_cert, int input_cert_size)
{
  int i;
  MHD_gnutls_datum_t tmp;
  int ret;

  i = *ncerts + 1;

  *cert_list =
    (MHD_gnutls_x509_crt_t *) MHD_gtls_realloc_fast (*cert_list,
                                                 i *
                                                 sizeof (MHD_gnutls_x509_crt_t));

  if (*cert_list == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  tmp.data = (opaque *) input_cert;
  tmp.size = input_cert_size;

  ret = MHD_gnutls_x509_crt_init (&cert_list[0][i - 1]);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  ret =
    MHD_gnutls_x509_crt_import (cert_list[0][i - 1], &tmp, GNUTLS_X509_FMT_DER);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  *ncerts = i;

  return 1;                     /* one certificate parsed */
}

/**
  * MHD__gnutls_certificate_set_x509_trust_mem - Used to add trusted CAs in a MHD_gtls_cert_credentials_t structure
  * @res: is an #MHD_gtls_cert_credentials_t structure.
  * @ca: is a list of trusted CAs or a DER certificate
  * @type: is DER or PEM
  *
  * This function adds the trusted CAs in order to verify client or
  * server certificates. In case of a client this is not required to
  * be called if the certificates are not verified using
  * MHD_gtls_certificate_verify_peers2().  This function may be called
  * multiple times.
  *
  * In case of a server the CAs set here will be sent to the client if
  * a certificate request is sent. This can be disabled using
  * MHD__gnutls_certificate_send_x509_rdn_sequence().
  *
  * Returns: the number of certificates processed or a negative value
  * on error.
  **/
int
MHD__gnutls_certificate_set_x509_trust_mem (MHD_gtls_cert_credentials_t
                                           res, const MHD_gnutls_datum_t * ca,
                                           MHD_gnutls_x509_crt_fmt_t type)
{
  int ret, ret2;

  if (type == GNUTLS_X509_FMT_DER)
    ret = parse_der_ca_mem (&res->x509_ca_list, &res->x509_ncas,
                            ca->data, ca->size);
  else
    ret = parse_pem_ca_mem (&res->x509_ca_list, &res->x509_ncas,
                            ca->data, ca->size);

  if ((ret2 = generate_rdn_seq (res)) < 0)
    return ret2;

  return ret;
}

#ifdef ENABLE_PKI

static int
parse_pem_crl_mem (MHD_gnutls_x509_crl_t ** crl_list, unsigned *ncrls,
                   const opaque * input_crl, int input_crl_size)
{
  int size, i;
  const opaque *ptr;
  MHD_gnutls_datum_t tmp;
  int ret, count;

  /* move to the certificate
   */
  ptr = MHD_memmem (input_crl, input_crl_size,
                PEM_CRL_SEP, sizeof (PEM_CRL_SEP) - 1);
  if (ptr == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_BASE64_DECODING_ERROR;
    }

  size = input_crl_size - (ptr - input_crl);

  i = *ncrls + 1;
  count = 0;

  do
    {

      *crl_list =
        (MHD_gnutls_x509_crl_t *) MHD_gtls_realloc_fast (*crl_list,
                                                     i *
                                                     sizeof
                                                     (MHD_gnutls_x509_crl_t));

      if (*crl_list == NULL)
        {
          MHD_gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }

      ret = MHD_gnutls_x509_crl_init (&crl_list[0][i - 1]);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }
      
      tmp.data = (unsigned char *) ptr;
      tmp.size = size;

      ret =
        MHD_gnutls_x509_crl_import (crl_list[0][i - 1],
                                &tmp, GNUTLS_X509_FMT_PEM);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }

      /* now we move ptr after the pem header
       */
      ptr++;
      /* find the next certificate (if any)
       */

      size = input_crl_size - (ptr - input_crl);

      if (size > 0)
        ptr = MHD_memmem (ptr, size, PEM_CRL_SEP, sizeof (PEM_CRL_SEP) - 1);
      else
        ptr = NULL;
      i++;
      count++;

    }
  while (ptr != NULL);

  *ncrls = i - 1;

  return count;
}

/* Reads a DER encoded certificate list from memory and stores it to
 * a MHD_gnutls_cert structure.
 * returns the number of certificates parsed.
 */
static int
parse_der_crl_mem (MHD_gnutls_x509_crl_t ** crl_list, unsigned *ncrls,
                   const void *input_crl, int input_crl_size)
{
  int i;
  MHD_gnutls_datum_t tmp;
  int ret;

  i = *ncrls + 1;

  *crl_list =
    (MHD_gnutls_x509_crl_t *) MHD_gtls_realloc_fast (*crl_list,
                                                 i *
                                                 sizeof (MHD_gnutls_x509_crl_t));

  if (*crl_list == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  tmp.data = (opaque *) input_crl;
  tmp.size = input_crl_size;

  ret = MHD_gnutls_x509_crl_init (&crl_list[0][i - 1]);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  ret =
    MHD_gnutls_x509_crl_import (crl_list[0][i - 1], &tmp, GNUTLS_X509_FMT_DER);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  *ncrls = i;

  return 1;                     /* one certificate parsed */
}


/* Reads a DER or PEM CRL from memory
 */
static int
read_crl_mem (MHD_gtls_cert_credentials_t res, const void *crl,
              int crl_size, MHD_gnutls_x509_crt_fmt_t type)
{
  int ret;

  /* allocate space for the certificate to add
   */
  res->x509_crl_list = MHD_gtls_realloc_fast (res->x509_crl_list,
                                              (1 +
                                               res->x509_ncrls) *
                                              sizeof (MHD_gnutls_x509_crl_t));
  if (res->x509_crl_list == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  if (type == GNUTLS_X509_FMT_DER)
    ret = parse_der_crl_mem (&res->x509_crl_list,
                             &res->x509_ncrls, crl, crl_size);
  else
    ret = parse_pem_crl_mem (&res->x509_crl_list,
                             &res->x509_ncrls, crl, crl_size);

  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  return ret;
}

/**
  * MHD__gnutls_certificate_set_x509_crl_mem - Used to add CRLs in a MHD_gtls_cert_credentials_t structure
  * @res: is an #MHD_gtls_cert_credentials_t structure.
  * @CRL: is a list of trusted CRLs. They should have been verified before.
  * @type: is DER or PEM
  *
  * This function adds the trusted CRLs in order to verify client or
  * server certificates.  In case of a client this is not required to
  * be called if the certificates are not verified using
  * MHD_gtls_certificate_verify_peers2().  This function may be called
  * multiple times.
  *
  * Returns: number of CRLs processed, or a negative value on error.
  **/
int
MHD__gnutls_certificate_set_x509_crl_mem (MHD_gtls_cert_credentials_t
                                         res, const MHD_gnutls_datum_t * CRL,
                                         MHD_gnutls_x509_crt_fmt_t type)
{
  int ret;

  if ((ret = read_crl_mem (res, CRL->data, CRL->size, type)) < 0)
    return ret;

  return ret;
}

/**
  * MHD__gnutls_certificate_free_crls - Used to free all the CRLs from a MHD_gtls_cert_credentials_t structure
  * @sc: is an #MHD_gtls_cert_credentials_t structure.
  *
  * This function will delete all the CRLs associated
  * with the given credentials.
  *
  **/
void
MHD__gnutls_certificate_free_crls (MHD_gtls_cert_credentials_t sc)
{
  unsigned j;

  for (j = 0; j < sc->x509_ncrls; j++)
    {
      MHD_gnutls_x509_crl_deinit (sc->x509_crl_list[j]);
    }

  sc->x509_ncrls = 0;

  MHD_gnutls_free (sc->x509_crl_list);
  sc->x509_crl_list = NULL;
}

#endif
