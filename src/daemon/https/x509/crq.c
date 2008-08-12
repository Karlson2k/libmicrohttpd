/*
 * Copyright (C) 2003, 2004, 2005 Free Software Foundation
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

/* This file contains functions to handle PKCS #10 certificate requests.
 */

#include <gnutls_int.h>

#ifdef ENABLE_PKI

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <crq.h>
#include <dn.h>
#include <mpi.h>
#include <sign.h>
#include <extensions.h>
#include <libtasn1.h>

/**
  * gnutls_x509_crq_init - This function initializes a gnutls_x509_crq_t structure
  * @crq: The structure to be initialized
  *
  * This function will initialize a PKCS10 certificate request structure. 
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_init (gnutls_x509_crq_t * crq)
{
  *crq = gnutls_calloc (1, sizeof (gnutls_x509_crq_int));

  if (*crq)
    {
      int result = asn1_create_element (_gnutls_get_pkix (),
                                        "PKIX1.pkcs-10-CertificationRequest",
                                        &((*crq)->crq));
      if (result != ASN1_SUCCESS)
        {
          gnutls_assert ();
          gnutls_free (*crq);
          return mhd_gtls_asn2err (result);
        }
      return 0;                 /* success */
    }
  return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_x509_crq_deinit - This function deinitializes memory used by a gnutls_x509_crq_t structure
  * @crq: The structure to be initialized
  *
  * This function will deinitialize a CRL structure. 
  *
  **/
void
gnutls_x509_crq_deinit (gnutls_x509_crq_t crq)
{
  if (!crq)
    return;

  if (crq->crq)
    asn1_delete_structure (&crq->crq);

  gnutls_free (crq);
}

#define PEM_CRQ "NEW CERTIFICATE REQUEST"
#define PEM_CRQ2 "CERTIFICATE REQUEST"

/**
  * gnutls_x509_crq_import - This function will import a DER or PEM encoded Certificate request
  * @crq: The structure to store the parsed certificate request.
  * @data: The DER or PEM encoded certificate.
  * @format: One of DER or PEM
  *
  * This function will convert the given DER or PEM encoded Certificate
  * to the native gnutls_x509_crq_t format. The output will be stored in @cert.
  *
  * If the Certificate is PEM encoded it should have a header of "NEW CERTIFICATE REQUEST".
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_import (gnutls_x509_crq_t crq,
                        const gnutls_datum_t * data,
                        gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  gnutls_datum_t _data;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  _data.data = data->data;
  _data.size = data->size;

  /* If the Certificate is in PEM format then decode it
   */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      /* Try the first header */
      result = _gnutls_fbase64_decode (PEM_CRQ, data->data, data->size, &out);

      if (result <= 0)          /* Go for the second header */
        result =
          _gnutls_fbase64_decode (PEM_CRQ2, data->data, data->size, &out);

      if (result <= 0)
        {
          if (result == 0)
            result = GNUTLS_E_INTERNAL_ERROR;
          gnutls_assert ();
          return result;
        }

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }

  result = asn1_der_decoding (&crq->crq, _data.data, _data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      result = mhd_gtls_asn2err (result);
      gnutls_assert ();
      goto cleanup;
    }

  result = 0;

cleanup:
  if (need_free)
    _gnutls_free_datum (&_data);
  return result;
}



/**
  * gnutls_x509_crq_get_dn - This function returns the Certificate request subject's distinguished name
  * @crq: should contain a gnutls_x509_crq_t structure
  * @buf: a pointer to a structure to hold the name (may be null)
  * @sizeof_buf: initially holds the size of @buf
  *
  * This function will copy the name of the Certificate request
  * subject in the provided buffer. The name will be in the form
  * "C=xxxx,O=yyyy,CN=zzzz" as described in RFC2253. The output string
  * will be ASCII or UTF-8 encoded, depending on the certificate data.
  *
  * If @buf is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
  * long enough, and in that case the *sizeof_buf will be updated with
  * the required size.  On success 0 is returned.
  *
  **/
int
gnutls_x509_crq_get_dn (gnutls_x509_crq_t crq, char *buf, size_t * sizeof_buf)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn (crq->crq,
                                "certificationRequestInfo.subject.rdnSequence",
                                buf, sizeof_buf);
}

/**
  * gnutls_x509_crq_get_dn_by_oid - This function returns the Certificate request subject's distinguished name
  * @crq: should contain a gnutls_x509_crq_t structure
  * @oid: holds an Object Identified in null terminated string
  * @indx: In case multiple same OIDs exist in the RDN, this specifies
  *   which to send. Use zero to get the first one.
  * @raw_flag: If non zero returns the raw DER data of the DN part.
  * @buf: a pointer to a structure to hold the name (may be null)
  * @sizeof_buf: initially holds the size of @buf
  *
  * This function will extract the part of the name of the Certificate
  * request subject, specified by the given OID. The output will be
  * encoded as described in RFC2253. The output string will be ASCII
  * or UTF-8 encoded, depending on the certificate data.
  *
  * Some helper macros with popular OIDs can be found in gnutls/x509.h
  * If raw flag is zero, this function will only return known OIDs as
  * text. Other OIDs will be DER encoded, as described in RFC2253 --
  * in hex format with a '\#' prefix.  You can check about known OIDs
  * using gnutls_x509_dn_oid_known().
  *
  * If @buf is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
  * long enough, and in that case the *sizeof_buf will be updated with
  * the required size.  On success 0 is returned.
  *
  **/
int
gnutls_x509_crq_get_dn_by_oid (gnutls_x509_crq_t crq, const char *oid,
                               int indx, unsigned int raw_flag,
                               void *buf, size_t * sizeof_buf)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn_oid (crq->crq,
                                    "certificationRequestInfo.subject.rdnSequence",
                                    oid, indx, raw_flag, buf, sizeof_buf);
}

/**
  * gnutls_x509_crq_get_dn_oid - This function returns the Certificate request subject's distinguished name OIDs
  * @crq: should contain a gnutls_x509_crq_t structure
  * @indx: Specifies which DN OID to send. Use zero to get the first one.
  * @oid: a pointer to a structure to hold the name (may be null)
  * @sizeof_oid: initially holds the size of @oid
  *
  * This function will extract the requested OID of the name of the
  * Certificate request subject, specified by the given index.
  *
  * If oid is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
  * long enough, and in that case the *sizeof_oid will be updated with
  * the required size.  On success 0 is returned.
  *
  **/
int
gnutls_x509_crq_get_dn_oid (gnutls_x509_crq_t crq,
                            int indx, void *oid, size_t * sizeof_oid)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_get_dn_oid (crq->crq,
                                  "certificationRequestInfo.subject.rdnSequence",
                                  indx, oid, sizeof_oid);
}

/* Parses an Attribute list in the asn1_struct, and searches for the
 * given OID. The index indicates the attribute value to be returned.
 *
 * If raw==0 only printable data are returned, or GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE.
 *
 * asn1_attr_name must be a string in the form "certificationRequestInfo.attributes"
 *
 */
static int
parse_attribute (ASN1_TYPE asn1_struct,
                 const char *attr_name, const char *given_oid, int indx,
                 int raw, char *buf, size_t * sizeof_buf)
{
  int k1, result;
  char tmpbuffer1[MAX_NAME_SIZE];
  char tmpbuffer3[MAX_NAME_SIZE];
  char value[200];
  char oid[128];
  int len, printable;

  if (*sizeof_buf == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  buf[0] = 0;

  k1 = 0;
  do
    {

      k1++;
      /* create a string like "attribute.?1"
       */
      if (attr_name[0] != 0)
        snprintf (tmpbuffer1, sizeof (tmpbuffer1), "%s.?%u", attr_name, k1);
      else
        snprintf (tmpbuffer1, sizeof (tmpbuffer1), "?%u", k1);

      len = sizeof (value) - 1;
      result = asn1_read_value (asn1_struct, tmpbuffer1, value, &len);

      if (result == ASN1_ELEMENT_NOT_FOUND)
        {
          gnutls_assert ();
          break;
        }

      if (result != ASN1_VALUE_NOT_FOUND)
        {
          gnutls_assert ();
          result = mhd_gtls_asn2err (result);
          goto cleanup;
        }

      /* Move to the attibute type and values
       */
      /* Read the OID 
       */
      mhd_gtls_str_cpy (tmpbuffer3, sizeof (tmpbuffer3), tmpbuffer1);
      mhd_gtls_str_cat (tmpbuffer3, sizeof (tmpbuffer3), ".type");

      len = sizeof (oid) - 1;
      result = asn1_read_value (asn1_struct, tmpbuffer3, oid, &len);

      if (result == ASN1_ELEMENT_NOT_FOUND)
        break;
      else if (result != ASN1_SUCCESS)
        {
          gnutls_assert ();
          result = mhd_gtls_asn2err (result);
          goto cleanup;
        }

      if (strcmp (oid, given_oid) == 0)
        {                       /* Found the OID */

          /* Read the Value 
           */
          snprintf (tmpbuffer3, sizeof (tmpbuffer3), "%s.values.?%u",
                    tmpbuffer1, indx + 1);

          len = sizeof (value) - 1;
          result = asn1_read_value (asn1_struct, tmpbuffer3, value, &len);

          if (result != ASN1_SUCCESS)
            {
              gnutls_assert ();
              result = mhd_gtls_asn2err (result);
              goto cleanup;
            }

          if (raw == 0)
            {
              printable = _gnutls_x509_oid_data_printable (oid);
              if (printable == 1)
                {
                  if ((result =
                       _gnutls_x509_oid_data2string
                       (oid, value, len, buf, sizeof_buf)) < 0)
                    {
                      gnutls_assert ();
                      goto cleanup;
                    }
                  return 0;
                }
              else
                {
                  gnutls_assert ();
                  return GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE;
                }
            }
          else
            {                   /* raw!=0 */
              if (*sizeof_buf > (size_t) len && buf != NULL)
                {
                  *sizeof_buf = len;
                  memcpy (buf, value, len);

                  return 0;
                }
              else
                {
                  *sizeof_buf = len;
                  gnutls_assert ();
                  return GNUTLS_E_SHORT_MEMORY_BUFFER;
                }
            }
        }

    }
  while (1);

  gnutls_assert ();

  result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

cleanup:
  return result;
}

/**
  * gnutls_x509_crq_get_challenge_password - This function will get the challenge password 
  * @crq: should contain a gnutls_x509_crq_t structure
  * @pass: will hold a null terminated password
  * @sizeof_pass: Initially holds the size of @pass.
  *
  * This function will return the challenge password in the
  * request.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_get_challenge_password (gnutls_x509_crq_t crq,
                                        char *pass, size_t * sizeof_pass)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return parse_attribute (crq->crq, "certificationRequestInfo.attributes",
                          "1.2.840.113549.1.9.7", 0, 0, pass, sizeof_pass);
}

/**
  * gnutls_x509_crq_set_attribute_by_oid - This function will set an attribute in the request
  * @crq: should contain a gnutls_x509_crq_t structure
  * @oid: holds an Object Identified in null terminated string
  * @buf: a pointer to a structure that holds the attribute data
  * @sizeof_buf: holds the size of @buf
  *
  * This function will set the attribute in the certificate request specified
  * by the given Object ID. The attribute must be be DER encoded.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_set_attribute_by_oid (gnutls_x509_crq_t crq,
                                      const char *oid, void *buf,
                                      size_t sizeof_buf)
{
  int result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Add the attribute.
   */
  result =
    asn1_write_value (crq->crq, "certificationRequestInfo.attributes",
                      "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  result =
    _gnutls_x509_encode_and_write_attribute (oid,
                                             crq->crq,
                                             "certificationRequestInfo.attributes.?LAST",
                                             buf, sizeof_buf, 1);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
  * gnutls_x509_crq_get_attribute_by_oid - This function will get an attribute of the request 
  * @crq: should contain a gnutls_x509_crq_t structure
  * @oid: holds an Object Identified in null terminated string
  * @indx: In case multiple same OIDs exist in the attribute list, this specifies
  *   which to send. Use zero to get the first one.
  * @buf: a pointer to a structure to hold the attribute data (may be null)
  * @sizeof_buf: initially holds the size of @buf
  *
  * This function will return the attribute in the certificate request specified
  * by the given Object ID. The attribute will be DER encoded.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_get_attribute_by_oid (gnutls_x509_crq_t crq,
                                      const char *oid, int indx, void *buf,
                                      size_t * sizeof_buf)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return parse_attribute (crq->crq, "certificationRequestInfo.attributes",
                          oid, indx, 1, buf, sizeof_buf);
}

/**
  * gnutls_x509_crq_set_dn_by_oid - This function will set the Certificate request subject's distinguished name
  * @crq: should contain a gnutls_x509_crq_t structure
  * @oid: holds an Object Identifier in a null terminated string
  * @raw_flag: must be 0, or 1 if the data are DER encoded
  * @data: a pointer to the input data
  * @sizeof_data: holds the size of @data
  *
  * This function will set the part of the name of the Certificate request subject, specified
  * by the given OID. The input string should be ASCII or UTF-8 encoded.
  *
  * Some helper macros with popular OIDs can be found in gnutls/x509.h
  * With this function you can only set the known OIDs. You can test
  * for known OIDs using gnutls_x509_dn_oid_known(). For OIDs that are
  * not known (by gnutls) you should properly DER encode your data, and
  * call this function with raw_flag set.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_set_dn_by_oid (gnutls_x509_crq_t crq, const char *oid,
                               unsigned int raw_flag, const void *data,
                               unsigned int sizeof_data)
{
  if (sizeof_data == 0 || data == NULL || crq == NULL)
    {
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_set_dn_oid (crq->crq,
                                  "certificationRequestInfo.subject", oid,
                                  raw_flag, data, sizeof_data);
}

/**
  * gnutls_x509_crq_set_version - This function will set the Certificate request version
  * @crq: should contain a gnutls_x509_crq_t structure
  * @version: holds the version number. For v1 Requests must be 1.
  *
  * This function will set the version of the certificate request. For
  * version 1 requests this must be one.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_set_version (gnutls_x509_crq_t crq, unsigned int version)
{
  int result;
  unsigned char null = version;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (null > 0)
    null--;

  result =
    asn1_write_value (crq->crq, "certificationRequestInfo.version", &null, 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  return 0;
}

/**
  * gnutls_x509_crq_get_version - This function returns the Certificate request's version number
  * @crq: should contain a gnutls_x509_crq_t structure
  *
  * This function will return the version of the specified Certificate request.
  *
  * Returns a negative value on error.
  *
  **/
int
gnutls_x509_crq_get_version (gnutls_x509_crq_t crq)
{
  opaque version[5];
  int len, result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  len = sizeof (version);
  if ((result =
       asn1_read_value (crq->crq, "certificationRequestInfo.version",
                        version, &len)) != ASN1_SUCCESS)
    {

      if (result == ASN1_ELEMENT_NOT_FOUND)
        return 1;               /* the DEFAULT version */
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  return (int) version[0] + 1;
}

/**
  * gnutls_x509_crq_set_key - This function will associate the Certificate request with a key
  * @crq: should contain a gnutls_x509_crq_t structure
  * @key: holds a private key
  *
  * This function will set the public parameters from the given private key to the
  * request. Only RSA keys are currently supported.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_set_key (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key)
{
  int result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_x509_encode_and_copy_PKI_params (crq->crq,
                                                    "certificationRequestInfo.subjectPKInfo",
                                                    key->pk_algorithm,
                                                    key->params,
                                                    key->params_size);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
  * gnutls_x509_crq_set_challenge_password - This function will set a challenge password 
  * @crq: should contain a gnutls_x509_crq_t structure
  * @pass: holds a null terminated password
  *
  * This function will set a challenge password to be used when revoking the request.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_set_challenge_password (gnutls_x509_crq_t crq,
                                        const char *pass)
{
  int result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Add the attribute.
   */
  result =
    asn1_write_value (crq->crq, "certificationRequestInfo.attributes",
                      "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  result =
    _gnutls_x509_encode_and_write_attribute ("1.2.840.113549.1.9.7",
                                             crq->crq,
                                             "certificationRequestInfo.attributes.?LAST",
                                             pass, strlen (pass), 1);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
  * gnutls_x509_crq_sign2 - This function will sign a Certificate request with a key
  * @crq: should contain a gnutls_x509_crq_t structure
  * @key: holds a private key
  * @dig: The message digest to use. GNUTLS_DIG_SHA1 is the safe choice unless you know what you're doing.
  * @flags: must be 0
  *
  * This function will sign the certificate request with a private key.
  * This must be the same key as the one used in gnutls_x509_crt_set_key() since a
  * certificate request is self signed.
  *
  * This must be the last step in a certificate request generation since all
  * the previously set parameters are now signed.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_sign2 (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key,
                       gnutls_digest_algorithm_t dig, unsigned int flags)
{
  int result;
  gnutls_datum_t signature;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Step 1. Self sign the request.
   */
  result =
    _gnutls_x509_sign_tbs (crq->crq, "certificationRequestInfo",
                           dig, key, &signature);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  /* Step 2. write the signature (bits)
   */
  result =
    asn1_write_value (crq->crq, "signature", signature.data,
                      signature.size * 8);

  _gnutls_free_datum (&signature);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  /* Step 3. Write the signatureAlgorithm field.
   */
  result = _gnutls_x509_write_sig_params (crq->crq, "signatureAlgorithm",
                                          key->pk_algorithm, dig, key->params,
                                          key->params_size);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
  * gnutls_x509_crq_sign - This function will sign a Certificate request with a key
  * @crq: should contain a gnutls_x509_crq_t structure
  * @key: holds a private key
  *
  * This function is the same a gnutls_x509_crq_sign2() with no flags, and
  * SHA1 as the hash algorithm.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crq_sign (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key)
{
  return gnutls_x509_crq_sign2 (crq, key, MHD_GNUTLS_DIG_SHA1, 0);
}

/**
  * gnutls_x509_crq_export - Export the generated certificate request
  * @crq: Holds the request
  * @format: the format of output params. One of PEM or DER.
  * @output_data: will contain a certificate request PEM or DER encoded
  * @output_data_size: holds the size of output_data (and will be
  *   replaced by the actual size of parameters)
  *
  * This function will export the certificate request to a PKCS10
  *
  * If the buffer provided is not long enough to hold the output, then
  * GNUTLS_E_SHORT_MEMORY_BUFFER will be returned and
  * *output_data_size will be updated.
  *
  * If the structure is PEM encoded, it will have a header of "BEGIN
  * NEW CERTIFICATE REQUEST".
  *
  * Return value: In case of failure a negative value will be
  *   returned, and 0 on success.
  *
  **/
int
gnutls_x509_crq_export (gnutls_x509_crq_t crq,
                        gnutls_x509_crt_fmt_t format, void *output_data,
                        size_t * output_data_size)
{
  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_export_int (crq->crq, format, PEM_CRQ,
                                  output_data, output_data_size);
}

/**
  * gnutls_x509_crq_get_pk_algorithm - This function returns the certificate request's PublicKey algorithm
  * @crq: should contain a gnutls_x509_crq_t structure
  * @bits: if bits is non null it will hold the size of the parameters' in bits
  *
  * This function will return the public key algorithm of a PKCS \#10 
  * certificate request.
  *
  * If bits is non null, it should have enough size to hold the parameters
  * size in bits. For RSA the bits returned is the modulus. 
  * For DSA the bits returned are of the public
  * exponent.
  *
  * Returns a member of the gnutls_pk_algorithm_t enumeration on success,
  * or a negative value on error.
  *
  **/
int
gnutls_x509_crq_get_pk_algorithm (gnutls_x509_crq_t crq, unsigned int *bits)
{
  int result;

  if (crq == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result =
    _gnutls_x509_get_pk_algorithm (crq->crq,
                                   "certificationRequestInfo.subjectPKInfo",
                                   bits);
  if (result < 0)
    {
      gnutls_assert ();
    }

  return result;
}

#endif /* ENABLE_PKI */
