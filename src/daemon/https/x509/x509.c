/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007 Free Software Foundation
 * Author: Nikos Mavrogiannopoulos, Simon Josefsson, Howard Chu
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

/* Functions on X.509 Certificate parsing
 */

#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <x509.h>
#include <dn.h>
#include <extensions.h>
#include <libtasn1.h>
#include <mpi.h>
#include <privkey.h>
#include <verify.h>

/**
 * MHD_gnutls_x509_crt_init - This function initializes a MHD_gnutls_x509_crt_t structure
 * @cert: The structure to be initialized
 *
 * This function will initialize an X.509 certificate structure.
 *
 * Returns 0 on success.
 *
 **/
int
MHD_gnutls_x509_crt_init (MHD_gnutls_x509_crt_t * cert)
{
  MHD_gnutls_x509_crt_t tmp = MHD_gnutls_calloc (1, sizeof (MHD_gnutls_x509_crt_int));
  int result;

  if (!tmp)
    return GNUTLS_E_MEMORY_ERROR;

  result = MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                                "PKIX1.Certificate", &tmp->cert);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD_gnutls_free (tmp);
      return MHD_gtls_asn2err (result);
    }

  *cert = tmp;

  return 0;                     /* success */
}

/*-
 * MHD__gnutls_x509_crt_cpy - This function copies a MHD_gnutls_x509_crt_t structure
 * @dest: The structure where to copy
 * @src: The structure to be copied
 *
 * This function will copy an X.509 certificate structure.
 *
 * Returns 0 on success.
 *
 -*/
int
MHD__gnutls_x509_crt_cpy (MHD_gnutls_x509_crt_t dest, MHD_gnutls_x509_crt_t src)
{
  int ret;
  size_t der_size;
  opaque *der;
  MHD_gnutls_datum_t tmp;

  ret = MHD_gnutls_x509_crt_export (src, GNUTLS_X509_FMT_DER, NULL, &der_size);
  if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  der = MHD_gnutls_alloca (der_size);
  if (der == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = MHD_gnutls_x509_crt_export (src, GNUTLS_X509_FMT_DER, der, &der_size);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      MHD_gnutls_afree (der);
      return ret;
    }

  tmp.data = der;
  tmp.size = der_size;
  ret = MHD_gnutls_x509_crt_import (dest, &tmp, GNUTLS_X509_FMT_DER);

  MHD_gnutls_afree (der);

  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  return 0;

}

/**
 * MHD_gnutls_x509_crt_deinit - This function deinitializes memory used by a MHD_gnutls_x509_crt_t structure
 * @cert: The structure to be initialized
 *
 * This function will deinitialize a CRL structure.
 *
 **/
void
MHD_gnutls_x509_crt_deinit (MHD_gnutls_x509_crt_t cert)
{
  if (!cert)
    return;

  if (cert->cert)
    MHD__asn1_delete_structure (&cert->cert);

  MHD_gnutls_free (cert);
}

/**
 * MHD_gnutls_x509_crt_import - This function will import a DER or PEM encoded Certificate
 * @cert: The structure to store the parsed certificate.
 * @data: The DER or PEM encoded certificate.
 * @format: One of DER or PEM
 *
 * This function will convert the given DER or PEM encoded Certificate
 * to the native MHD_gnutls_x509_crt_t format. The output will be stored in @cert.
 *
 * If the Certificate is PEM encoded it should have a header of "X509 CERTIFICATE", or
 * "CERTIFICATE".
 *
 * Returns 0 on success.
 *
 **/
int
MHD_gnutls_x509_crt_import (MHD_gnutls_x509_crt_t cert,
                        const MHD_gnutls_datum_t * data,
                        MHD_gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  MHD_gnutls_datum_t _data;
  opaque *signature = NULL;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
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
      result = MHD__gnutls_fbase64_decode (PEM_X509_CERT2, data->data, data->size,
                                       &out);

      if (result <= 0)
        {
          /* try for the second header */
          result = MHD__gnutls_fbase64_decode (PEM_X509_CERT, data->data,
                                           data->size, &out);

          if (result <= 0)
            {
              if (result == 0)
                result = GNUTLS_E_INTERNAL_ERROR;
              MHD_gnutls_assert ();
              return result;
            }
        }

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }

  result = MHD__asn1_der_decoding (&cert->cert, _data.data, _data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      result = MHD_gtls_asn2err (result);
      MHD_gnutls_assert ();
      goto cleanup;
    }

  /* Since we do not want to disable any extension
   */
  cert->use_extensions = 1;
  if (need_free)
    MHD__gnutls_free_datum (&_data);

  return 0;

cleanup:MHD_gnutls_free (signature);
  if (need_free)
    MHD__gnutls_free_datum (&_data);
  return result;
}

/**
 * MHD_gnutls_x509_crt_get_issuer_dn - This function returns the Certificate's issuer distinguished name
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @buf: a pointer to a structure to hold the name (may be null)
 * @sizeof_buf: initially holds the size of @buf
 *
 * This function will copy the name of the Certificate issuer in the
 * provided buffer. The name will be in the form
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
MHD_gnutls_x509_crt_get_issuer_dn (MHD_gnutls_x509_crt_t cert,
                               char *buf, size_t * sizeof_buf)
{
  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return MHD__gnutls_x509_parse_dn (cert->cert,
                                "tbsCertificate.issuer.rdnSequence", buf,
                                sizeof_buf);
}

/**
 * MHD_gnutls_x509_crt_get_issuer_dn_by_oid - This function returns the Certificate's issuer distinguished name
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @oid: holds an Object Identified in null terminated string
 * @indx: In case multiple same OIDs exist in the RDN, this specifies which to send. Use zero to get the first one.
 * @raw_flag: If non zero returns the raw DER data of the DN part.
 * @buf: a pointer to a structure to hold the name (may be null)
 * @sizeof_buf: initially holds the size of @buf
 *
 * This function will extract the part of the name of the Certificate
 * issuer specified by the given OID. The output, if the raw flag is not
 * used, will be encoded as described in RFC2253. Thus a string that is
 * ASCII or UTF-8 encoded, depending on the certificate data.
 *
 * Some helper macros with popular OIDs can be found in gnutls/x509.h
 * If raw flag is zero, this function will only return known OIDs as
 * text. Other OIDs will be DER encoded, as described in RFC2253 --
 * in hex format with a '\#' prefix.  You can check about known OIDs
 * using MHD_gnutls_x509_dn_oid_known().
 *
 * If @buf is null then only the size will be filled.
 *
 * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
 * long enough, and in that case the *sizeof_buf will be updated with
 * the required size.  On success 0 is returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_issuer_dn_by_oid (MHD_gnutls_x509_crt_t cert,
                                      const char *oid,
                                      int indx,
                                      unsigned int raw_flag,
                                      void *buf, size_t * sizeof_buf)
{
  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return MHD__gnutls_x509_parse_dn_oid (cert->cert,
                                    "tbsCertificate.issuer.rdnSequence", oid,
                                    indx, raw_flag, buf, sizeof_buf);
}

/**
 * MHD_gnutls_x509_crt_get_issuer_dn_oid - This function returns the Certificate's issuer distinguished name OIDs
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @indx: This specifies which OID to return. Use zero to get the first one.
 * @oid: a pointer to a buffer to hold the OID (may be null)
 * @sizeof_oid: initially holds the size of @oid
 *
 * This function will extract the OIDs of the name of the Certificate
 * issuer specified by the given index.
 *
 * If @oid is null then only the size will be filled.
 *
 * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
 * long enough, and in that case the *sizeof_oid will be updated with
 * the required size.  On success 0 is returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_issuer_dn_oid (MHD_gnutls_x509_crt_t cert,
                                   int indx, void *oid, size_t * sizeof_oid)
{
  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return MHD__gnutls_x509_get_dn_oid (cert->cert,
                                  "tbsCertificate.issuer.rdnSequence", indx,
                                  oid, sizeof_oid);
}

/**
 * MHD_gnutls_x509_crt_get_dn - This function returns the Certificate's distinguished name
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @buf: a pointer to a structure to hold the name (may be null)
 * @sizeof_buf: initially holds the size of @buf
 *
 * This function will copy the name of the Certificate in the
 * provided buffer. The name will be in the form
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
MHD_gnutls_x509_crt_get_dn (MHD_gnutls_x509_crt_t cert,
                        char *buf, size_t * sizeof_buf)
{
  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return MHD__gnutls_x509_parse_dn (cert->cert,
                                "tbsCertificate.subject.rdnSequence", buf,
                                sizeof_buf);
}

/**
 * MHD_gnutls_x509_crt_get_dn_by_oid - This function returns the Certificate's distinguished name
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @oid: holds an Object Identified in null terminated string
 * @indx: In case multiple same OIDs exist in the RDN, this specifies which to send. Use zero to get the first one.
 * @raw_flag: If non zero returns the raw DER data of the DN part.
 * @buf: a pointer where the DN part will be copied (may be null).
 * @sizeof_buf: initially holds the size of @buf
 *
 * This function will extract the part of the name of the Certificate
 * subject specified by the given OID. The output, if the raw flag is not
 * used, will be encoded as described in RFC2253. Thus a string that is
 * ASCII or UTF-8 encoded, depending on the certificate data.
 *
 * Some helper macros with popular OIDs can be found in gnutls/x509.h
 * If raw flag is zero, this function will only return known OIDs as
 * text. Other OIDs will be DER encoded, as described in RFC2253 --
 * in hex format with a '\#' prefix.  You can check about known OIDs
 * using MHD_gnutls_x509_dn_oid_known().
 *
 * If @buf is null then only the size will be filled.
 *
 * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
 * long enough, and in that case the *sizeof_buf will be updated with
 * the required size.  On success 0 is returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_dn_by_oid (MHD_gnutls_x509_crt_t cert,
                               const char *oid,
                               int indx,
                               unsigned int raw_flag,
                               void *buf, size_t * sizeof_buf)
{
  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return MHD__gnutls_x509_parse_dn_oid (cert->cert,
                                    "tbsCertificate.subject.rdnSequence", oid,
                                    indx, raw_flag, buf, sizeof_buf);
}

/**
 * MHD_gnutls_x509_crt_get_dn_oid - This function returns the Certificate's subject distinguished name OIDs
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @indx: This specifies which OID to return. Use zero to get the first one.
 * @oid: a pointer to a buffer to hold the OID (may be null)
 * @sizeof_oid: initially holds the size of @oid
 *
 * This function will extract the OIDs of the name of the Certificate
 * subject specified by the given index.
 *
 * If oid is null then only the size will be filled.
 *
 * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not
 * long enough, and in that case the *sizeof_oid will be updated with
 * the required size.  On success 0 is returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_dn_oid (MHD_gnutls_x509_crt_t cert,
                            int indx, void *oid, size_t * sizeof_oid)
{
  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return MHD__gnutls_x509_get_dn_oid (cert->cert,
                                  "tbsCertificate.subject.rdnSequence", indx,
                                  oid, sizeof_oid);
}

/**
 * MHD_gnutls_x509_crt_get_signature_algorithm - This function returns the Certificate's signature algorithm
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 *
 * This function will return a value of the MHD_gnutls_sign_algorithm_t enumeration that
 * is the signature algorithm.
 *
 * Returns a negative value on error.
 *
 **/
int
MHD_gnutls_x509_crt_get_signature_algorithm (MHD_gnutls_x509_crt_t cert)
{
  int result;
  MHD_gnutls_datum_t sa;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Read the signature algorithm. Note that parameters are not
   * read. They will be read from the issuer's certificate if needed.
   */
  result =
    MHD__gnutls_x509_read_value (cert->cert, "signatureAlgorithm.algorithm", &sa,
                             0);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  result = MHD_gtls_x509_oid2sign_algorithm (sa.data);

  MHD__gnutls_free_datum (&sa);

  return result;
}

/**
 * MHD_gnutls_x509_crt_get_signature - Returns the Certificate's signature
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @sig: a pointer where the signature part will be copied (may be null).
 * @sizeof_sig: initially holds the size of @sig
 *
 * This function will extract the signature field of a certificate.
 *
 * Returns 0 on success, and a negative value on error.
 **/
int
MHD_gnutls_x509_crt_get_signature (MHD_gnutls_x509_crt_t cert,
                               char *sig, size_t * sizeof_sig)
{
  int result;
  int bits, len;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  bits = 0;
  result = MHD__asn1_read_value (cert->cert, "signature", NULL, &bits);
  if (result != ASN1_MEM_ERROR)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  if (bits % 8 != 0)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  len = bits / 8;

  if (*sizeof_sig < len)
    {
      *sizeof_sig = bits / 8;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  result = MHD__asn1_read_value (cert->cert, "signature", sig, &len);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  return 0;
}

/**
 * MHD_gnutls_x509_crt_get_version - This function returns the Certificate's version number
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 *
 * This function will return the version of the specified Certificate.
 *
 * Returns a negative value on error.
 *
 **/
int
MHD_gnutls_x509_crt_get_version (MHD_gnutls_x509_crt_t cert)
{
  opaque version[5];
  int len, result;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  len = sizeof (version);
  if ((result =
       MHD__asn1_read_value (cert->cert, "tbsCertificate.version", version,
                        &len)) != ASN1_SUCCESS)
    {

      if (result == ASN1_ELEMENT_NOT_FOUND)
        return 1;               /* the DEFAULT version */
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  return (int) version[0] + 1;
}

/**
 * MHD_gnutls_x509_crt_get_activation_time - This function returns the Certificate's activation time
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 *
 * This function will return the time this Certificate was or will be activated.
 *
 * Returns (time_t)-1 on error.
 *
 **/
time_t
MHD_gnutls_x509_crt_get_activation_time (MHD_gnutls_x509_crt_t cert)
{
  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return (time_t) - 1;
    }

  return MHD__gnutls_x509_get_time (cert->cert,
                                "tbsCertificate.validity.notBefore");
}

/**
 * MHD_gnutls_x509_crt_get_expiration_time - This function returns the Certificate's expiration time
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 *
 * This function will return the time this Certificate was or will be expired.
 *
 * Returns (time_t)-1 on error.
 *
 **/
time_t
MHD_gnutls_x509_crt_get_expiration_time (MHD_gnutls_x509_crt_t cert)
{
  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return (time_t) - 1;
    }

  return MHD__gnutls_x509_get_time (cert->cert,
                                "tbsCertificate.validity.notAfter");
}

/**
 * MHD_gnutls_x509_crt_get_serial - This function returns the certificate's serial number
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @result: The place where the serial number will be copied
 * @result_size: Holds the size of the result field.
 *
 * This function will return the X.509 certificate's serial number.
 * This is obtained by the X509 Certificate serialNumber
 * field. Serial is not always a 32 or 64bit number. Some CAs use
 * large serial numbers, thus it may be wise to handle it as something
 * opaque.
 *
 * Returns 0 on success and a negative value in case of an error.
 *
 **/
int
MHD_gnutls_x509_crt_get_serial (MHD_gnutls_x509_crt_t cert,
                            void *result, size_t * result_size)
{
  int ret, len;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  len = *result_size;
  ret
    =
    MHD__asn1_read_value (cert->cert, "tbsCertificate.serialNumber", result, &len);
  *result_size = len;

  if (ret != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (ret);
    }

  return 0;
}

/**
 * MHD_gnutls_x509_crt_get_subject_key_id - This function returns the certificate's key identifier
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @ret: The place where the identifier will be copied
 * @ret_size: Holds the size of the result field.
 * @critical: will be non zero if the extension is marked as critical (may be null)
 *
 * This function will return the X.509v3 certificate's subject key identifier.
 * This is obtained by the X.509 Subject Key identifier extension
 * field (2.5.29.14).
 *
 * Returns 0 on success and a negative value in case of an error.
 *
 **/
int
MHD_gnutls_x509_crt_get_subject_key_id (MHD_gnutls_x509_crt_t cert,
                                    void *ret,
                                    size_t * ret_size, unsigned int *critical)
{
  int result, len;
  MHD_gnutls_datum_t id;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (ret)
    memset (ret, 0, *ret_size);
  else
    *ret_size = 0;

  if ((result = MHD__gnutls_x509_crt_get_extension (cert, "2.5.29.14", 0, &id,
                                                critical)) < 0)
    {
      return result;
    }

  if (id.size == 0 || id.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.SubjectKeyIdentifier",
                         &c2);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (&id);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_der_decoding (&c2, id.data, id.size, NULL);
  MHD__gnutls_free_datum (&id);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&c2);
      return MHD_gtls_asn2err (result);
    }

  len = *ret_size;
  result = MHD__asn1_read_value (c2, "", ret, &len);

  *ret_size = len;
  MHD__asn1_delete_structure (&c2);

  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  return 0;
}

/**
 * MHD_gnutls_x509_crt_get_authority_key_id - This function returns the certificate authority's identifier
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @result: The place where the identifier will be copied
 * @result_size: Holds the size of the result field.
 * @critical: will be non zero if the extension is marked as critical (may be null)
 *
 * This function will return the X.509v3 certificate authority's key identifier.
 * This is obtained by the X.509 Authority Key identifier extension
 * field (2.5.29.35). Note that this function only returns the keyIdentifier
 * field of the extension.
 *
 * Returns 0 on success and a negative value in case of an error.
 *
 **/
int
MHD_gnutls_x509_crt_get_authority_key_id (MHD_gnutls_x509_crt_t cert,
                                      void *ret,
                                      size_t * ret_size,
                                      unsigned int *critical)
{
  int result, len;
  MHD_gnutls_datum_t id;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (ret)
    memset (ret, 0, *ret_size);
  else
    *ret_size = 0;

  if ((result = MHD__gnutls_x509_crt_get_extension (cert, "2.5.29.35", 0, &id,
                                                critical)) < 0)
    {
      return result;
    }

  if (id.size == 0 || id.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.AuthorityKeyIdentifier",
                         &c2);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (&id);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_der_decoding (&c2, id.data, id.size, NULL);
  MHD__gnutls_free_datum (&id);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&c2);
      return MHD_gtls_asn2err (result);
    }

  len = *ret_size;
  result = MHD__asn1_read_value (c2, "keyIdentifier", ret, &len);

  *ret_size = len;
  MHD__asn1_delete_structure (&c2);

  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  return 0;
}

/**
 * MHD_gnutls_x509_crt_get_pk_algorithm - This function returns the certificate's PublicKey algorithm
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @bits: if bits is non null it will hold the size of the parameters' in bits
 *
 * This function will return the public key algorithm of an X.509
 * certificate.
 *
 * If bits is non null, it should have enough size to hold the parameters
 * size in bits. For RSA the bits returned is the modulus.
 * For DSA the bits returned are of the public
 * exponent.
 *
 * Returns a member of the enum MHD_GNUTLS_PublicKeyAlgorithm enumeration on success,
 * or a negative value on error.
 *
 **/
int
MHD_gnutls_x509_crt_get_pk_algorithm (MHD_gnutls_x509_crt_t cert, unsigned int *bits)
{
  int result;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = MHD__gnutls_x509_get_pk_algorithm (cert->cert,
                                          "tbsCertificate.subjectPublicKeyInfo",
                                          bits);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return result;

}

inline static int
is_type_printable (int type)
{
  if (type == GNUTLS_SAN_DNSNAME || type == GNUTLS_SAN_RFC822NAME || type
      == GNUTLS_SAN_URI)
    return 1;
  else
    return 0;
}

#define XMPP_OID "1.3.6.1.5.5.7.8.5"

/* returns the type and the name on success.
 * Type is also returned as a parameter in case of an error.
 */
static int
parse_general_name (ASN1_TYPE src,
                    const char *src_name,
                    int seq,
                    void *name,
                    size_t * name_size,
                    unsigned int *ret_type, int othername_oid)
{
  int len;
  char nptr[MAX_NAME_SIZE];
  int result;
  opaque choice_type[128];
  MHD_gnutls_x509_subject_alt_name_t type;

  seq++;                        /* 0->1, 1->2 etc */

  if (src_name[0] != 0)
    snprintf (nptr, sizeof (nptr), "%s.?%u", src_name, seq);
  else
    snprintf (nptr, sizeof (nptr), "?%u", seq);

  len = sizeof (choice_type);
  result = MHD__asn1_read_value (src, nptr, choice_type, &len);

  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  type = MHD__gnutls_x509_san_find_type (choice_type);
  if (type == (MHD_gnutls_x509_subject_alt_name_t) - 1)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_X509_UNKNOWN_SAN;
    }

  if (ret_type)
    *ret_type = type;

  if (type == GNUTLS_SAN_OTHERNAME)
    {
      if (othername_oid)
        MHD_gtls_str_cat (nptr, sizeof (nptr), ".otherName.type-id");
      else
        MHD_gtls_str_cat (nptr, sizeof (nptr), ".otherName.value");

      len = *name_size;
      result = MHD__asn1_read_value (src, nptr, name, &len);
      *name_size = len;

      if (result == ASN1_MEM_ERROR)
        return GNUTLS_E_SHORT_MEMORY_BUFFER;

      if (result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          return MHD_gtls_asn2err (result);
        }

      if (othername_oid)
        {
          if (len > strlen (XMPP_OID) && strcmp (name, XMPP_OID) == 0)
            type = GNUTLS_SAN_OTHERNAME_XMPP;
        }
      else
        {
          char oid[42];

          if (src_name[0] != 0)
            snprintf (nptr, sizeof (nptr), "%s.?%u.otherName.type-id",
                      src_name, seq);
          else
            snprintf (nptr, sizeof (nptr), "?%u.otherName.type-id", seq);

          len = sizeof (oid);
          result = MHD__asn1_read_value (src, nptr, oid, &len);
          if (result != ASN1_SUCCESS)
            {
              MHD_gnutls_assert ();
              return MHD_gtls_asn2err (result);
            }

          if (len > strlen (XMPP_OID) && strcmp (oid, XMPP_OID) == 0)
            {
              ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

              result =
                MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.XmppAddr",
                                     &c2);
              if (result != ASN1_SUCCESS)
                {
                  MHD_gnutls_assert ();
                  return MHD_gtls_asn2err (result);
                }

              result = MHD__asn1_der_decoding (&c2, name, *name_size, NULL);
              if (result != ASN1_SUCCESS)
                {
                  MHD_gnutls_assert ();
                  MHD__asn1_delete_structure (&c2);
                  return MHD_gtls_asn2err (result);
                }

              result = MHD__asn1_read_value (c2, "", name, &len);
              *name_size = len;
              if (result != ASN1_SUCCESS)
                {
                  MHD_gnutls_assert ();
                  MHD__asn1_delete_structure (&c2);
                  return MHD_gtls_asn2err (result);
                }
              MHD__asn1_delete_structure (&c2);
            }
        }
    }
  else if (type == GNUTLS_SAN_DN)
    {
      MHD_gtls_str_cat (nptr, sizeof (nptr), ".directoryName");
      result = MHD__gnutls_x509_parse_dn (src, nptr, name, name_size);
      if (result < 0)
        {
          MHD_gnutls_assert ();
          return result;
        }
    }
  else if (othername_oid)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  else
    {
      size_t orig_name_size = *name_size;

      MHD_gtls_str_cat (nptr, sizeof (nptr), ".");
      MHD_gtls_str_cat (nptr, sizeof (nptr), choice_type);

      len = *name_size;
      result = MHD__asn1_read_value (src, nptr, name, &len);
      *name_size = len;

      if (result == ASN1_MEM_ERROR)
        {
          if (is_type_printable (type))
            (*name_size)++;
          return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }

      if (result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          return MHD_gtls_asn2err (result);
        }

      if (is_type_printable (type))
        {

          if (len + 1 > orig_name_size)
            {
              MHD_gnutls_assert ();
              (*name_size)++;
              return GNUTLS_E_SHORT_MEMORY_BUFFER;
            }

          /* null terminate it */
          ((char *) name)[*name_size] = 0;
        }

    }

  return type;
}

static int
get_subject_alt_name (MHD_gnutls_x509_crt_t cert,
                      unsigned int seq,
                      void *ret,
                      size_t * ret_size,
                      unsigned int *ret_type,
                      unsigned int *critical, int othername_oid)
{
  int result;
  MHD_gnutls_datum_t dnsname;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  MHD_gnutls_x509_subject_alt_name_t type;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (ret)
    memset (ret, 0, *ret_size);
  else
    *ret_size = 0;

  if ((result =
       MHD__gnutls_x509_crt_get_extension (cert, "2.5.29.17", 0, &dnsname,
                                       critical)) < 0)
    {
      return result;
    }

  if (dnsname.size == 0 || dnsname.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.SubjectAltName", &c2);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (&dnsname);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_der_decoding (&c2, dnsname.data, dnsname.size, NULL);
  MHD__gnutls_free_datum (&dnsname);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&c2);
      return MHD_gtls_asn2err (result);
    }

  result = parse_general_name (c2, "", seq, ret, ret_size, ret_type,
                               othername_oid);

  MHD__asn1_delete_structure (&c2);

  if (result < 0)
    {
      return result;
    }

  type = result;

  return type;
}

/**
 * MHD_gnutls_x509_crt_get_subject_alt_name - Get certificate's alternative name, if any
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the alternative name will be copied to
 * @ret_size: holds the size of ret.
 * @critical: will be non zero if the extension is marked as critical (may be null)
 *
 * This function will return the alternative names, contained in the
 * given certificate.
 *
 * This is specified in X509v3 Certificate Extensions.  GNUTLS will
 * return the Alternative name (2.5.29.17), or a negative error code.
 *
 * When the SAN type is otherName, it will extract the data in the
 * otherName's value field, and %GNUTLS_SAN_OTHERNAME is returned.
 * You may use MHD_gnutls_x509_crt_get_subject_alt_othername_oid() to get
 * the corresponding OID and the "virtual" SAN types (e.g.,
 * %GNUTLS_SAN_OTHERNAME_XMPP).
 *
 * If an otherName OID is known, the data will be decoded.  Otherwise
 * the returned data will be DER encoded, and you will have to decode
 * it yourself.  Currently, only the RFC 3920 id-on-xmppAddr SAN is
 * recognized.
 *
 * Returns the alternative subject name type on success.  The type is
 * one of the enumerated MHD_gnutls_x509_subject_alt_name_t.  It will
 * return %GNUTLS_E_SHORT_MEMORY_BUFFER if @ret_size is not large
 * enough to hold the value.  In that case @ret_size will be updated
 * with the required size.  If the certificate does not have an
 * Alternative name with the specified sequence number then
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_subject_alt_name (MHD_gnutls_x509_crt_t cert,
                                      unsigned int seq,
                                      void *ret,
                                      size_t * ret_size,
                                      unsigned int *critical)
{
  return get_subject_alt_name (cert, seq, ret, ret_size, NULL, critical, 0);
}

/**
 * MHD_gnutls_x509_crt_get_subject_alt_name2 - Get certificate's alternative name, if any
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the alternative name will be copied to
 * @ret_size: holds the size of ret.
 * @ret_type: holds the type of the alternative name (one of MHD_gnutls_x509_subject_alt_name_t).
 * @critical: will be non zero if the extension is marked as critical (may be null)
 *
 * This function will return the alternative names, contained in the
 * given certificate. It is the same as MHD_gnutls_x509_crt_get_subject_alt_name()
 * except for the fact that it will return the type of the alternative
 * name in @ret_type even if the function fails for some reason (i.e.
 * the buffer provided is not enough).
 *
 * The return values are the same as with MHD_gnutls_x509_crt_get_subject_alt_name().
 *
 **/
int
MHD_gnutls_x509_crt_get_subject_alt_name2 (MHD_gnutls_x509_crt_t cert,
                                       unsigned int seq,
                                       void *ret,
                                       size_t * ret_size,
                                       unsigned int *ret_type,
                                       unsigned int *critical)
{
  return get_subject_alt_name (cert, seq, ret, ret_size, ret_type, critical,
                               0);
}

/**
 * MHD_gnutls_x509_crt_get_subject_alt_othername_oid - Get SAN otherName OID
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the otherName OID will be copied to
 * @ret_size: holds the size of ret.
 *
 * This function will extract the type OID of an otherName Subject
 * Alternative Name, contained in the given certificate, and return
 * the type as an enumerated element.
 *
 * This function is only useful if
 * MHD_gnutls_x509_crt_get_subject_alt_name() returned
 * %GNUTLS_SAN_OTHERNAME.
 *
 * Returns the alternative subject name type on success.  The type is
 * one of the enumerated MHD_gnutls_x509_subject_alt_name_t.  For
 * supported OIDs, it will return one of the virtual
 * (GNUTLS_SAN_OTHERNAME_*) types, e.g. %GNUTLS_SAN_OTHERNAME_XMPP,
 * and %GNUTLS_SAN_OTHERNAME for unknown OIDs.  It will return
 * %GNUTLS_E_SHORT_MEMORY_BUFFER if @ret_size is not large enough to
 * hold the value.  In that case @ret_size will be updated with the
 * required size.  If the certificate does not have an Alternative
 * name with the specified sequence number and with the otherName type
 * then %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 **/
int
MHD_gnutls_x509_crt_get_subject_alt_othername_oid (MHD_gnutls_x509_crt_t cert,
                                               unsigned int seq,
                                               void *ret, size_t * ret_size)
{
  return get_subject_alt_name (cert, seq, ret, ret_size, NULL, NULL, 1);
}

/**
 * MHD_gnutls_x509_crt_get_basic_constraints - This function returns the certificate basic constraints
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @critical: will be non zero if the extension is marked as critical
 * @ca: pointer to output integer indicating CA status, may be NULL,
 *   value is 1 if the certificate CA flag is set, 0 otherwise.
 * @pathlen: pointer to output integer indicating path length (may be
 *   NULL), non-negative values indicate a present pathLenConstraint
 *   field and the actual value, -1 indicate that the field is absent.
 *
 * This function will read the certificate's basic constraints, and
 * return the certificates CA status.  It reads the basicConstraints
 * X.509 extension (2.5.29.19).
 *
 * Return value: If the certificate is a CA a positive value will be
 * returned, or zero if the certificate does not have CA flag set.  A
 * negative value may be returned in case of errors.  If the
 * certificate does not contain the basicConstraints extension
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 **/
int
MHD_gnutls_x509_crt_get_basic_constraints (MHD_gnutls_x509_crt_t cert,
                                       unsigned int *critical,
                                       int *ca, int *pathlen)
{
  int result;
  MHD_gnutls_datum_t basicConstraints;
  int tmp_ca;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((result = MHD__gnutls_x509_crt_get_extension (cert, "2.5.29.19", 0,
                                                &basicConstraints, critical))
      < 0)
    {
      return result;
    }

  if (basicConstraints.size == 0 || basicConstraints.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result = MHD__gnutls_x509_ext_extract_basicConstraints (&tmp_ca, pathlen,
                                                      basicConstraints.data,
                                                      basicConstraints.size);
  if (ca)
    *ca = tmp_ca;
  MHD__gnutls_free_datum (&basicConstraints);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return tmp_ca;
}

/**
 * MHD_gnutls_x509_crt_get_ca_status - This function returns the certificate CA status
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @critical: will be non zero if the extension is marked as critical
 *
 * This function will return certificates CA status, by reading the
 * basicConstraints X.509 extension (2.5.29.19). If the certificate is
 * a CA a positive value will be returned, or zero if the certificate
 * does not have CA flag set.
 *
 * Use MHD_gnutls_x509_crt_get_basic_constraints() if you want to read the
 * pathLenConstraint field too.
 *
 * A negative value may be returned in case of parsing error.
 * If the certificate does not contain the basicConstraints extension
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_ca_status (MHD_gnutls_x509_crt_t cert, unsigned int *critical)
{
  int ca, pathlen;
  return MHD_gnutls_x509_crt_get_basic_constraints (cert, critical, &ca,
                                                &pathlen);
}

/**
 * MHD_gnutls_x509_crt_get_key_usage - This function returns the certificate's key usage
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @key_usage: where the key usage bits will be stored
 * @critical: will be non zero if the extension is marked as critical
 *
 * This function will return certificate's key usage, by reading the
 * keyUsage X.509 extension (2.5.29.15). The key usage value will ORed values of the:
 * GNUTLS_KEY_DIGITAL_SIGNATURE, GNUTLS_KEY_NON_REPUDIATION,
 * GNUTLS_KEY_KEY_ENCIPHERMENT, GNUTLS_KEY_DATA_ENCIPHERMENT,
 * GNUTLS_KEY_KEY_AGREEMENT, GNUTLS_KEY_KEY_CERT_SIGN,
 * GNUTLS_KEY_CRL_SIGN, GNUTLS_KEY_ENCIPHER_ONLY,
 * GNUTLS_KEY_DECIPHER_ONLY.
 *
 * A negative value may be returned in case of parsing error.
 * If the certificate does not contain the keyUsage extension
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_key_usage (MHD_gnutls_x509_crt_t cert,
                               unsigned int *key_usage,
                               unsigned int *critical)
{
  int result;
  MHD_gnutls_datum_t keyUsage;
  uint16_t _usage;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((result =
       MHD__gnutls_x509_crt_get_extension (cert, "2.5.29.15", 0, &keyUsage,
                                       critical)) < 0)
    {
      return result;
    }

  if (keyUsage.size == 0 || keyUsage.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result = MHD__gnutls_x509_ext_extract_keyUsage (&_usage, keyUsage.data,
                                              keyUsage.size);
  MHD__gnutls_free_datum (&keyUsage);

  *key_usage = _usage;

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * MHD_gnutls_x509_crt_get_proxy - This function returns the proxy certificate info
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @critical: will be non zero if the extension is marked as critical
 * @pathlen: pointer to output integer indicating path length (may be
 *   NULL), non-negative values indicate a present pCPathLenConstraint
 *   field and the actual value, -1 indicate that the field is absent.
 *
 * This function will read the certificate's basic constraints, and
 * return the certificates CA status.  It reads the basicConstraints
 * X.509 extension (2.5.29.19).
 *
 * Return value: If the certificate is a CA a positive value will be
 * returned, or zero if the certificate does not have CA flag set.  A
 * negative value may be returned in case of errors.  If the
 * certificate does not contain the basicConstraints extension
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 **/
int
MHD_gnutls_x509_crt_get_proxy (MHD_gnutls_x509_crt_t cert,
                           unsigned int *critical,
                           int *pathlen,
                           char **policyLanguage,
                           char **policy, size_t * sizeof_policy)
{
  int result;
  MHD_gnutls_datum_t proxyCertInfo;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((result = MHD__gnutls_x509_crt_get_extension (cert, "1.3.6.1.5.5.7.1.14", 0,
                                                &proxyCertInfo,
                                                critical)) < 0)
    {
      return result;
    }

  if (proxyCertInfo.size == 0 || proxyCertInfo.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result = MHD__gnutls_x509_ext_extract_proxyCertInfo (pathlen, policyLanguage,
                                                   policy, sizeof_policy,
                                                   proxyCertInfo.data,
                                                   proxyCertInfo.size);
  MHD__gnutls_free_datum (&proxyCertInfo);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}

/**
 * MHD_gnutls_x509_crt_get_extension_by_oid - This function returns the specified extension
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @oid: holds an Object Identified in null terminated string
 * @indx: In case multiple same OIDs exist in the extensions, this specifies which to send. Use zero to get the first one.
 * @buf: a pointer to a structure to hold the name (may be null)
 * @sizeof_buf: initially holds the size of @buf
 * @critical: will be non zero if the extension is marked as critical
 *
 * This function will return the extension specified by the OID in the certificate.
 * The extensions will be returned as binary data DER encoded, in the provided
 * buffer.
 *
 * A negative value may be returned in case of parsing error.
 * If the certificate does not contain the specified extension
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_extension_by_oid (MHD_gnutls_x509_crt_t cert,
                                      const char *oid,
                                      int indx,
                                      void *buf,
                                      size_t * sizeof_buf,
                                      unsigned int *critical)
{
  int result;
  MHD_gnutls_datum_t output;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if ((result = MHD__gnutls_x509_crt_get_extension (cert, oid, indx, &output,
                                                critical)) < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  if (output.size == 0 || output.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (output.size > (unsigned int) *sizeof_buf)
    {
      *sizeof_buf = output.size;
      MHD__gnutls_free_datum (&output);
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  *sizeof_buf = output.size;

  if (buf)
    memcpy (buf, output.data, output.size);

  MHD__gnutls_free_datum (&output);

  return 0;

}

/**
 * MHD_gnutls_x509_crt_get_extension_oid - This function returns the specified extension OID
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @indx: Specifies which extension OID to send. Use zero to get the first one.
 * @oid: a pointer to a structure to hold the OID (may be null)
 * @sizeof_oid: initially holds the size of @oid
 *
 * This function will return the requested extension OID in the certificate.
 * The extension OID will be stored as a string in the provided buffer.
 *
 * A negative value may be returned in case of parsing error.
 * If your have reached the last extension available
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_extension_oid (MHD_gnutls_x509_crt_t cert,
                                   int indx, void *oid, size_t * sizeof_oid)
{
  int result;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = MHD__gnutls_x509_crt_get_extension_oid (cert, indx, oid, sizeof_oid);
  if (result < 0)
    {
      return result;
    }

  return 0;

}

/**
 * MHD_gnutls_x509_crt_get_extension_info - Get extension id and criticality
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @indx: Specifies which extension OID to send. Use zero to get the first one.
 * @oid: a pointer to a structure to hold the OID
 * @sizeof_oid: initially holds the size of @oid
 * @critical: output variable with critical flag, may be NULL.
 *
 * This function will return the requested extension OID in the
 * certificate, and the critical flag for it.  The extension OID will
 * be stored as a string in the provided buffer.  Use
 * MHD_gnutls_x509_crt_get_extension_data() to extract the data.
 *
 * Return 0 on success.  A negative value may be returned in case of
 * parsing error.  If you have reached the last extension available
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 **/
int
MHD_gnutls_x509_crt_get_extension_info (MHD_gnutls_x509_crt_t cert,
                                    int indx,
                                    void *oid,
                                    size_t * sizeof_oid, int *critical)
{
  int result;
  char str_critical[10];
  char name[MAX_NAME_SIZE];
  int len;

  if (!cert)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u.extnID",
            indx + 1);

  len = *sizeof_oid;
  result = MHD__asn1_read_value (cert->cert, name, oid, &len);
  *sizeof_oid = len;

  if (result == ASN1_ELEMENT_NOT_FOUND)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  else if (result < 0)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u.critical",
            indx + 1);
  len = sizeof (str_critical);
  result = MHD__asn1_read_value (cert->cert, name, str_critical, &len);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  if (critical)
    {
      if (str_critical[0] == 'T')
        *critical = 1;
      else
        *critical = 0;
    }

  return 0;

}

/**
 * MHD_gnutls_x509_crt_get_extension_data - Get the specified extension data
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @indx: Specifies which extension OID to send. Use zero to get the first one.
 * @data: a pointer to a structure to hold the data (may be null)
 * @sizeof_data: initially holds the size of @oid
 *
 * This function will return the requested extension data in the
 * certificate.  The extension data will be stored as a string in the
 * provided buffer.
 *
 * Use MHD_gnutls_x509_crt_get_extension_info() to extract the OID and
 * critical flag.  Use MHD_gnutls_x509_crt_get_extension_by_oid() instead,
 * if you want to get data indexed by the extension OID rather than
 * sequence.
 *
 * Return 0 on success.  A negative value may be returned in case of
 * parsing error.  If you have reached the last extension available
 * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 **/
int
MHD_gnutls_x509_crt_get_extension_data (MHD_gnutls_x509_crt_t cert,
                                    int indx,
                                    void *data, size_t * sizeof_data)
{
  int result, len;
  char name[MAX_NAME_SIZE];

  if (!cert)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u.extnValue",
            indx + 1);

  len = *sizeof_data;
  result = MHD__asn1_read_value (cert->cert, name, data, &len);
  *sizeof_data = len;

  if (result == ASN1_ELEMENT_NOT_FOUND)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  else if (result < 0)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  return 0;
}

static int
MHD__gnutls_x509_crt_get_raw_dn2 (MHD_gnutls_x509_crt_t cert,
                              const char *whom, MHD_gnutls_datum_t * start)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result, len1;
  int start1, end1;
  MHD_gnutls_datum_t signed_data = { NULL,
    0
  };

  /* get the issuer of 'cert'
   */
  if ((result =
       MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.TBSCertificate",
                            &c2)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result = MHD__gnutls_x509_get_signed_data (cert->cert, "tbsCertificate",
                                         &signed_data);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  result = MHD__asn1_der_decoding (&c2, signed_data.data, signed_data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&c2);
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  result = MHD__asn1_der_decoding_startEnd (c2, signed_data.data, signed_data.size,
                                       whom, &start1, &end1);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  len1 = end1 - start1 + 1;

  MHD__gnutls_set_datum (start, &signed_data.data[start1], len1);

  result = 0;

cleanup:MHD__asn1_delete_structure (&c2);
  MHD__gnutls_free_datum (&signed_data);
  return result;
}

/**
 * MHD_gnutls_x509_crt_get_raw_issuer_dn - This function returns the issuer's DN DER encoded
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @start: will hold the starting point of the DN
 *
 * This function will return a pointer to the DER encoded DN structure
 * and the length.
 *
 * Returns 0 on success or a negative value on error.
 *
 **/
int
MHD_gnutls_x509_crt_get_raw_issuer_dn (MHD_gnutls_x509_crt_t cert,
                                   MHD_gnutls_datum_t * start)
{
  return MHD__gnutls_x509_crt_get_raw_dn2 (cert, "issuer", start);
}

/**
 * MHD_gnutls_x509_crt_get_raw_dn - This function returns the subject's DN DER encoded
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @start: will hold the starting point of the DN
 *
 * This function will return a pointer to the DER encoded DN structure and
 * the length.
 *
 * Returns 0 on success, or a negative value on error.
 *
 **/
int
MHD_gnutls_x509_crt_get_raw_dn (MHD_gnutls_x509_crt_t cert, MHD_gnutls_datum_t * start)
{
  return MHD__gnutls_x509_crt_get_raw_dn2 (cert, "subject", start);
}

static int
get_dn (MHD_gnutls_x509_crt_t cert, const char *whom, MHD_gnutls_x509_dn_t * dn)
{
  *dn = MHD__asn1_find_node (cert->cert, whom);
  if (!*dn)
    return GNUTLS_E_ASN1_ELEMENT_NOT_FOUND;
  return 0;
}

/**
 * MHD_gnutls_x509_crt_get_subject: get opaque subject DN pointer
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @dn: output variable with pointer to opaque DN.
 *
 * Return the Certificate's Subject DN as an opaque data type.  You
 * may use MHD_gnutls_x509_dn_get_rdn_ava() to decode the DN.
 *
 * Returns: Returns 0 on success, or an error code.
 **/
int
MHD_gnutls_x509_crt_get_subject (MHD_gnutls_x509_crt_t cert, MHD_gnutls_x509_dn_t * dn)
{
  return get_dn (cert, "tbsCertificate.subject.rdnSequence", dn);
}

/**
 * MHD_gnutls_x509_crt_get_issuer: get opaque issuer DN pointer
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @dn: output variable with pointer to opaque DN
 *
 * Return the Certificate's Issuer DN as an opaque data type.  You may
 * use MHD_gnutls_x509_dn_get_rdn_ava() to decode the DN.
 *
 * Note that @dn points into the @cert object, and thus you may not
 * deallocate @cert and continue to access @dn.
 *
 * Returns: Returns 0 on success, or an error code.
 **/
int
MHD_gnutls_x509_crt_get_issuer (MHD_gnutls_x509_crt_t cert, MHD_gnutls_x509_dn_t * dn)
{
  return get_dn (cert, "tbsCertificate.issuer.rdnSequence", dn);
}

/**
 * MHD_gnutls_x509_dn_get_rdn_ava:
 * @dn: input variable with opaque DN pointer
 * @irdn: index of RDN
 * @iava: index of AVA.
 * @ava: Pointer to structure which will hold output information.
 *
 * Get pointers to data within the DN.
 *
 * Note that @ava will contain pointers into the @dn structure, so you
 * should not modify any data or deallocate it.  Note also that the DN
 * in turn points into the original certificate structure, and thus
 * you may not deallocate the certificate and continue to access @dn.
 *
 * Returns: Returns 0 on success, or an error code.
 **/
int
MHD_gnutls_x509_dn_get_rdn_ava (MHD_gnutls_x509_dn_t dn,
                            int irdn, int iava, MHD_gnutls_x509_ava_st * ava)
{
  ASN1_TYPE rdn, elem;
  long len;
  int lenlen, remlen, ret;
  char rbuf[MAX_NAME_SIZE];
  unsigned char cls, *ptr;

  iava++;
  irdn++;                       /* 0->1, 1->2 etc */

  snprintf (rbuf, sizeof (rbuf), "rdnSequence.?%d.?%d", irdn, iava);
  rdn = MHD__asn1_find_node (dn, rbuf);
  if (!rdn)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_ASN1_ELEMENT_NOT_FOUND;
    }

  snprintf (rbuf, sizeof (rbuf), "?%d.type", iava);
  elem = MHD__asn1_find_node (rdn, rbuf);
  if (!elem)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_ASN1_ELEMENT_NOT_FOUND;
    }

  ava->oid.data = elem->value;
  ava->oid.size = elem->value_len;

  snprintf (rbuf, sizeof (rbuf), "?%d.value", iava);
  elem = MHD__asn1_find_node (rdn, rbuf);
  if (!elem)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_ASN1_ELEMENT_NOT_FOUND;
    }

  /* The value still has the previous tag's length bytes, plus the
   * current value's tag and length bytes. Decode them.
   */

  ptr = elem->value;
  remlen = elem->value_len;
  len = MHD__asn1_get_length_der (ptr, remlen, &lenlen);
  if (len < 0)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_ASN1_DER_ERROR;
    }

  ptr += lenlen;
  remlen -= lenlen;
  ret = MHD__asn1_get_tag_der (ptr, remlen, &cls, &lenlen, &ava->value_tag);
  if (ret)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (ret);
    }

  ptr += lenlen;
  remlen -= lenlen;

  ava->value.size = MHD__asn1_get_length_der (ptr, remlen, &lenlen);
  ava->value.data = ptr + lenlen;

  return 0;
}

/**
 * MHD_gnutls_x509_crt_get_fingerprint - This function returns the Certificate's fingerprint
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @algo: is a digest algorithm
 * @buf: a pointer to a structure to hold the fingerprint (may be null)
 * @sizeof_buf: initially holds the size of @buf
 *
 * This function will calculate and copy the certificate's fingerprint
 * in the provided buffer.
 *
 * If the buffer is null then only the size will be filled.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is
 * not long enough, and in that case the *sizeof_buf will be updated
 * with the required size.  On success 0 is returned.
 **/
int
MHD_gnutls_x509_crt_get_fingerprint (MHD_gnutls_x509_crt_t cert,
                                 enum MHD_GNUTLS_HashAlgorithm algo,
                                 void *buf, size_t * sizeof_buf)
{
  opaque *cert_buf;
  int cert_buf_size;
  int result;
  MHD_gnutls_datum_t tmp;

  if (sizeof_buf == 0 || cert == NULL)
    {
      return GNUTLS_E_INVALID_REQUEST;
    }

  cert_buf_size = 0;
  MHD__asn1_der_coding (cert->cert, "", NULL, &cert_buf_size, NULL);

  cert_buf = MHD_gnutls_alloca (cert_buf_size);
  if (cert_buf == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = MHD__asn1_der_coding (cert->cert, "", cert_buf, &cert_buf_size, NULL);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD_gnutls_afree (cert_buf);
      return MHD_gtls_asn2err (result);
    }

  tmp.data = cert_buf;
  tmp.size = cert_buf_size;

  result = MHD__gnutls_fingerprint (algo, &tmp, buf, sizeof_buf);
  MHD_gnutls_afree (cert_buf);

  return result;
}

/**
 * MHD_gnutls_x509_crt_export - This function will export the certificate
 * @cert: Holds the certificate
 * @format: the format of output params. One of PEM or DER.
 * @output_data: will contain a certificate PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the certificate to DER or PEM format.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN CERTIFICATE".
 *
 * Return value: In case of failure a negative value will be
 *   returned, and 0 on success.
 **/
int
MHD_gnutls_x509_crt_export (MHD_gnutls_x509_crt_t cert,
                        MHD_gnutls_x509_crt_fmt_t format,
                        void *output_data, size_t * output_data_size)
{
  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return MHD__gnutls_x509_export_int (cert->cert, format, "CERTIFICATE",
                                  output_data, output_data_size);
}

static int
rsadsa_get_key_id (MHD_gnutls_x509_crt_t crt,
                   int pk,
                   unsigned char *output_data, size_t * output_data_size)
{
  mpi_t params[MAX_PUBLIC_PARAMS_SIZE];
  int params_size = MAX_PUBLIC_PARAMS_SIZE;
  int i, result = 0;
  MHD_gnutls_datum_t der = { NULL,
    0
  };
  GNUTLS_HASH_HANDLE hd;

  result = MHD__gnutls_x509_crt_get_mpis (crt, params, &params_size);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  if (pk == MHD_GNUTLS_PK_RSA)
    {
      result = MHD__gnutls_x509_write_rsa_params (params, params_size, &der);
      if (result < 0)
        {
          MHD_gnutls_assert ();
          goto cleanup;
        }
    }
  else
    return GNUTLS_E_INTERNAL_ERROR;

  hd = MHD_gtls_hash_init (MHD_GNUTLS_MAC_SHA1);
  if (hd == GNUTLS_HASH_FAILED)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  MHD_gnutls_hash (hd, der.data, der.size);

  MHD_gnutls_hash_deinit (hd, output_data);
  *output_data_size = 20;

  result = 0;

cleanup:

  MHD__gnutls_free_datum (&der);

  /* release all allocated MPIs
   */
  for (i = 0; i < params_size; i++)
    {
      MHD_gtls_mpi_release (&params[i]);
    }
  return result;
}

/**
 * MHD_gnutls_x509_crt_get_key_id - Return unique ID of public key's parameters
 * @crt: Holds the certificate
 * @flags: should be 0 for now
 * @output_data: will contain the key ID
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will return a unique ID the depends on the public
 * key parameters. This ID can be used in checking whether a
 * certificate corresponds to the given private key.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.  The output will normally be a SHA-1 hash output,
 * which is 20 bytes.
 *
 * Return value: In case of failure a negative value will be
 *   returned, and 0 on success.
 **/
int
MHD_gnutls_x509_crt_get_key_id (MHD_gnutls_x509_crt_t crt,
                            unsigned int flags,
                            unsigned char *output_data,
                            size_t * output_data_size)
{
  int pk, result = 0;
  MHD_gnutls_datum_t pubkey;

  if (crt == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (*output_data_size < 20)
    {
      MHD_gnutls_assert ();
      *output_data_size = 20;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  pk = MHD_gnutls_x509_crt_get_pk_algorithm (crt, NULL);
  if (pk < 0)
    {
      MHD_gnutls_assert ();
      return pk;
    }

  if (pk == MHD_GNUTLS_PK_RSA)
    {
      /* This is for compatibility with what GnuTLS has printed for
         RSA/DSA before the code below was added.  The code below is
         applicable to all types, and it would probably be a better
         idea to use it for RSA/DSA too, but doing so would break
         backwards compatibility.  */
      return rsadsa_get_key_id (crt, pk, output_data, output_data_size);
    }

  pubkey.size = 0;
  result = MHD__asn1_der_coding (crt->cert, "tbsCertificate.subjectPublicKeyInfo",
                            NULL, &pubkey.size, NULL);
  if (result != ASN1_MEM_ERROR)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  pubkey.data = MHD_gnutls_alloca (pubkey.size);
  if (pubkey.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  result = MHD__asn1_der_coding (crt->cert, "tbsCertificate.subjectPublicKeyInfo",
                            pubkey.data, &pubkey.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD_gnutls_afree (pubkey.data);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__gnutls_fingerprint (MHD_GNUTLS_MAC_SHA1, &pubkey, output_data,
                                   output_data_size);

  MHD_gnutls_afree (pubkey.data);

  return result;
}

#ifdef ENABLE_PKI

/**
 * MHD_gnutls_x509_crt_check_revocation - This function checks if the given certificate is revoked
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @crl_list: should contain a list of MHD_gnutls_x509_crl_t structures
 * @crl_list_length: the length of the crl_list
 *
 * This function will return check if the given certificate is
 * revoked.  It is assumed that the CRLs have been verified before.
 *
 * Returns: 0 if the certificate is NOT revoked, and 1 if it is.  A
 * negative value is returned on error.
 **/
int
MHD_gnutls_x509_crt_check_revocation (MHD_gnutls_x509_crt_t cert,
                                  const MHD_gnutls_x509_crl_t * crl_list,
                                  int crl_list_length)
{
  opaque serial[64];
  opaque cert_serial[64];
  size_t serial_size, cert_serial_size;
  int ncerts, ret, i, j;
  MHD_gnutls_datum_t dn1, dn2;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  for (j = 0; j < crl_list_length; j++)
    {                           /* do for all the crls */

      /* Step 1. check if issuer's DN match
       */
      ret = MHD__gnutls_x509_crl_get_raw_issuer_dn (crl_list[j], &dn1);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }

      ret = MHD_gnutls_x509_crt_get_raw_issuer_dn (cert, &dn2);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }

      ret = MHD__gnutls_x509_compare_raw_dn (&dn1, &dn2);
      MHD__gnutls_free_datum (&dn1);
      MHD__gnutls_free_datum (&dn2);
      if (ret == 0)
        {
          /* issuers do not match so don't even
           * bother checking.
           */
          continue;
        }

      /* Step 2. Read the certificate's serial number
       */
      cert_serial_size = sizeof (cert_serial);
      ret = MHD_gnutls_x509_crt_get_serial (cert, cert_serial, &cert_serial_size);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          return ret;
        }

      /* Step 3. cycle through the CRL serials and compare with
       *   certificate serial we have.
       */

      ncerts = MHD_gnutls_x509_crl_get_crt_count (crl_list[j]);
      if (ncerts < 0)
        {
          MHD_gnutls_assert ();
          return ncerts;
        }

      for (i = 0; i < ncerts; i++)
        {
          serial_size = sizeof (serial);
          ret = MHD_gnutls_x509_crl_get_crt_serial (crl_list[j], i, serial,
                                                &serial_size, NULL);

          if (ret < 0)
            {
              MHD_gnutls_assert ();
              return ret;
            }

          if (serial_size == cert_serial_size)
            {
              if (memcmp (serial, cert_serial, serial_size) == 0)
                {
                  /* serials match */
                  return 1;     /* revoked! */
                }
            }
        }

    }
  return 0;                     /* not revoked. */
}

/**
 * MHD_gnutls_x509_crt_verify_data - This function will verify the given signed data.
 * @crt: Holds the certificate
 * @flags: should be 0 for now
 * @data: holds the data to be signed
 * @signature: contains the signature
 *
 * This function will verify the given signed data, using the
 * parameters from the certificate.
 *
 * Returns: In case of a verification failure 0 is returned, and 1 on
 * success.
 **/
int
MHD_gnutls_x509_crt_verify_data (MHD_gnutls_x509_crt_t crt,
                             unsigned int flags,
                             const MHD_gnutls_datum_t * data,
                             const MHD_gnutls_datum_t * signature)
{
  int result;

  if (crt == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = MHD__gnutls_x509_verify_signature (data, signature, crt);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return 0;
    }

  return result;
}

/**
 * MHD_gnutls_x509_crt_get_crl_dist_points - This function returns the CRL distribution points
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @seq: specifies the sequence number of the distribution point (0 for the first one, 1 for the second etc.)
 * @ret: is the place where the distribution point will be copied to
 * @ret_size: holds the size of ret.
 * @reason_flags: Revocation reasons flags.
 * @critical: will be non zero if the extension is marked as critical (may be null)
 *
 * This function will return the CRL distribution points (2.5.29.31),
 * contained in the given certificate.
 *
 * @reason_flags should be an ORed sequence of
 * GNUTLS_CRL_REASON_UNUSED, GNUTLS_CRL_REASON_KEY_COMPROMISE,
 * GNUTLS_CRL_REASON_CA_COMPROMISE,
 * GNUTLS_CRL_REASON_AFFILIATION_CHANGED,
 * GNUTLS_CRL_REASON_SUPERSEEDED,
 * GNUTLS_CRL_REASON_CESSATION_OF_OPERATION,
 * GNUTLS_CRL_REASON_CERTIFICATE_HOLD,
 * GNUTLS_CRL_REASON_PRIVILEGE_WITHDRAWN,
 * GNUTLS_CRL_REASON_AA_COMPROMISE, or zero for all possible reasons.
 *
 * This is specified in X509v3 Certificate Extensions. GNUTLS will
 * return the distribution point type, or a negative error code on
 * error.
 *
 * Returns %GNUTLS_E_SHORT_MEMORY_BUFFER and updates &@ret_size if
 * &@ret_size is not enough to hold the distribution point, or the
 * type of the distribution point if everything was ok. The type is
 * one of the enumerated %MHD_gnutls_x509_subject_alt_name_t.  If the
 * certificate does not have an Alternative name with the specified
 * sequence number then %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is
 * returned.
 **/
int
MHD_gnutls_x509_crt_get_crl_dist_points (MHD_gnutls_x509_crt_t cert,
                                     unsigned int seq,
                                     void *ret,
                                     size_t * ret_size,
                                     unsigned int *reason_flags,
                                     unsigned int *critical)
{
  int result;
  MHD_gnutls_datum_t dist_points = { NULL,
    0
  };
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  char name[MAX_NAME_SIZE];
  int len;
  MHD_gnutls_x509_subject_alt_name_t type;
  uint8_t reasons[2];

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (*ret_size > 0 && ret)
    memset (ret, 0, *ret_size);
  else
    *ret_size = 0;

  if (reason_flags)
    *reason_flags = 0;

  result = MHD__gnutls_x509_crt_get_extension (cert, "2.5.29.31", 0, &dist_points,
                                           critical);
  if (result < 0)
    {
      return result;
    }

  if (dist_points.size == 0 || dist_points.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.CRLDistributionPoints",
                         &c2);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (&dist_points);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_der_decoding (&c2, dist_points.data, dist_points.size, NULL);
  MHD__gnutls_free_datum (&dist_points);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&c2);
      return MHD_gtls_asn2err (result);
    }

  /* Return the different names from the first CRLDistr. point.
   * The whole thing is a mess.
   */
  MHD_gtls_str_cpy (name, sizeof (name), "?1.distributionPoint.fullName");

  result = parse_general_name (c2, name, seq, ret, ret_size, NULL, 0);
  if (result < 0)
    {
      MHD__asn1_delete_structure (&c2);
      return result;
    }

  type = result;

  /* Read the CRL reasons.
   */
  if (reason_flags)
    {
      MHD_gtls_str_cpy (name, sizeof (name), "?1.reasons");

      reasons[0] = reasons[1] = 0;

      len = sizeof (reasons);
      result = MHD__asn1_read_value (c2, name, reasons, &len);

      if (result != ASN1_VALUE_NOT_FOUND && result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          MHD__asn1_delete_structure (&c2);
          return MHD_gtls_asn2err (result);
        }

      *reason_flags = reasons[0] | (reasons[1] << 8);
    }

  return type;
}

/**
 * MHD_gnutls_x509_crt_get_key_purpose_oid - This function returns the Certificate's key purpose OIDs
 * @cert: should contain a MHD_gnutls_x509_crt_t structure
 * @indx: This specifies which OID to return. Use zero to get the first one.
 * @oid: a pointer to a buffer to hold the OID (may be null)
 * @sizeof_oid: initially holds the size of @oid
 *
 * This function will extract the key purpose OIDs of the Certificate
 * specified by the given index. These are stored in the Extended Key
 * Usage extension (2.5.29.37) See the GNUTLS_KP_* definitions for
 * human readable names.
 *
 * If @oid is null then only the size will be filled.
 *
 * Returns: %GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is
 * not long enough, and in that case the *sizeof_oid will be updated
 * with the required size.  On success 0 is returned.
 **/
int
MHD_gnutls_x509_crt_get_key_purpose_oid (MHD_gnutls_x509_crt_t cert,
                                     int indx,
                                     void *oid,
                                     size_t * sizeof_oid,
                                     unsigned int *critical)
{
  char tmpstr[MAX_NAME_SIZE];
  int result, len;
  MHD_gnutls_datum_t id;
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

  if (cert == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (oid)
    memset (oid, 0, *sizeof_oid);
  else
    *sizeof_oid = 0;

  if ((result = MHD__gnutls_x509_crt_get_extension (cert, "2.5.29.37", 0, &id,
                                                critical)) < 0)
    {
      return result;
    }

  if (id.size == 0 || id.data == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.ExtKeyUsageSyntax", &c2);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (&id);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_der_decoding (&c2, id.data, id.size, NULL);
  MHD__gnutls_free_datum (&id);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&c2);
      return MHD_gtls_asn2err (result);
    }

  indx++;
  /* create a string like "?1"
   */
  snprintf (tmpstr, sizeof (tmpstr), "?%u", indx);

  len = *sizeof_oid;
  result = MHD__asn1_read_value (c2, tmpstr, oid, &len);

  *sizeof_oid = len;
  MHD__asn1_delete_structure (&c2);

  if (result == ASN1_VALUE_NOT_FOUND || result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  return 0;

}

/**
 * MHD_gnutls_x509_crt_get_pk_rsa_raw - This function will export the RSA public key
 * @crt: Holds the certificate
 * @m: will hold the modulus
 * @e: will hold the public exponent
 *
 * This function will export the RSA public key's parameters found in
 * the given structure.  The new parameters will be allocated using
 * MHD_gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
 **/
int
MHD_gnutls_x509_crt_get_pk_rsa_raw (MHD_gnutls_x509_crt_t crt,
                                MHD_gnutls_datum_t * m, MHD_gnutls_datum_t * e)
{
  int ret;
  mpi_t params[MAX_PUBLIC_PARAMS_SIZE];
  int params_size = MAX_PUBLIC_PARAMS_SIZE;
  int i;

  if (crt == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = MHD_gnutls_x509_crt_get_pk_algorithm (crt, NULL);
  if (ret != MHD_GNUTLS_PK_RSA)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = MHD__gnutls_x509_crt_get_mpis (crt, params, &params_size);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  ret = MHD_gtls_mpi_dprint (m, params[0]);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  ret = MHD_gtls_mpi_dprint (e, params[1]);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (m);
      goto cleanup;
    }

  ret = 0;

cleanup:for (i = 0; i < params_size; i++)
    {
      MHD_gtls_mpi_release (&params[i]);
    }
  return ret;
}

/**
 * MHD_gnutls_x509_crt_get_pk_dsa_raw - This function will export the DSA public key
 * @crt: Holds the certificate
 * @p: will hold the p
 * @q: will hold the q
 * @g: will hold the g
 * @y: will hold the y
 *
 * This function will export the DSA public key's parameters found in
 * the given certificate.  The new parameters will be allocated using
 * MHD_gnutls_malloc() and will be stored in the appropriate datum.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
 **/
int
MHD_gnutls_x509_crt_get_pk_dsa_raw (MHD_gnutls_x509_crt_t crt,
                                MHD_gnutls_datum_t * p,
                                MHD_gnutls_datum_t * q,
                                MHD_gnutls_datum_t * g, MHD_gnutls_datum_t * y)
{
  int ret;
  mpi_t params[MAX_PUBLIC_PARAMS_SIZE];
  int params_size = MAX_PUBLIC_PARAMS_SIZE;
  int i;

  if (crt == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = MHD_gnutls_x509_crt_get_pk_algorithm (crt, NULL);

  ret = MHD__gnutls_x509_crt_get_mpis (crt, params, &params_size);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  /* P */
  ret = MHD_gtls_mpi_dprint (p, params[0]);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  /* Q */
  ret = MHD_gtls_mpi_dprint (q, params[1]);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (p);
      goto cleanup;
    }

  /* G */
  ret = MHD_gtls_mpi_dprint (g, params[2]);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (p);
      MHD__gnutls_free_datum (q);
      goto cleanup;
    }

  /* Y */
  ret = MHD_gtls_mpi_dprint (y, params[3]);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_free_datum (p);
      MHD__gnutls_free_datum (g);
      MHD__gnutls_free_datum (q);
      goto cleanup;
    }

  ret = 0;

cleanup:for (i = 0; i < params_size; i++)
    {
      MHD_gtls_mpi_release (&params[i]);
    }
  return ret;

}

#endif

/**
 * MHD_gnutls_x509_crt_list_import - This function will import a PEM encoded certificate list
 * @certs: The structures to store the parsed certificate. Must not be initialized.
 * @cert_max: Initially must hold the maximum number of certs. It will be updated with the number of certs available.
 * @data: The PEM encoded certificate.
 * @format: One of DER or PEM.
 * @flags: must be zero or an OR'd sequence of MHD_gnutls_certificate_import_flags.
 *
 * This function will convert the given PEM encoded certificate list
 * to the native MHD_gnutls_x509_crt_t format. The output will be stored
 * in @certs.  They will be automatically initialized.
 *
 * If the Certificate is PEM encoded it should have a header of "X509
 * CERTIFICATE", or "CERTIFICATE".
 *
 * Returns: the number of certificates read or a negative error value.
 **/
int
MHD_gnutls_x509_crt_list_import (MHD_gnutls_x509_crt_t * certs,
                             unsigned int *cert_max,
                             const MHD_gnutls_datum_t * data,
                             MHD_gnutls_x509_crt_fmt_t format, unsigned int flags)
{
  int size;
  const char *ptr;
  MHD_gnutls_datum_t tmp;
  int ret, nocopy = 0;
  unsigned int count = 0, j;

  if (format == GNUTLS_X509_FMT_DER)
    {
      if (*cert_max < 1)
        {
          *cert_max = 1;
          return GNUTLS_E_SHORT_MEMORY_BUFFER;
        }

      count = 1;                /* import only the first one */

      ret = MHD_gnutls_x509_crt_init (&certs[0]);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          goto error;
        }

      ret = MHD_gnutls_x509_crt_import (certs[0], data, format);
      if (ret < 0)
        {
          MHD_gnutls_assert ();
          goto error;
        }

      *cert_max = 1;
      return 1;
    }

  /* move to the certificate
   */
  ptr = MHD_memmem (data->data, data->size,
                PEM_CERT_SEP, sizeof (PEM_CERT_SEP) - 1);
  if (ptr == NULL)
    ptr = MHD_memmem (data->data, data->size,
                  PEM_CERT_SEP2, sizeof (PEM_CERT_SEP2) - 1);

  if (ptr == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_BASE64_DECODING_ERROR;
    }
  size = data->size - (ptr - (char *) data->data);

  count = 0;

  do
    {
      if (count >= *cert_max)
        {
          if (!(flags & GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED))
            break;
          else
            nocopy = 1;
        }

      if (!nocopy)
        {
          ret = MHD_gnutls_x509_crt_init (&certs[count]);
          if (ret < 0)
            {
              MHD_gnutls_assert ();
              goto error;
            }

          tmp.data = (void *) ptr;
          tmp.size = size;

          ret =
            MHD_gnutls_x509_crt_import (certs[count], &tmp, GNUTLS_X509_FMT_PEM);
          if (ret < 0)
            {
              MHD_gnutls_assert ();
              goto error;
            }
        }

      /* now we move ptr after the pem header
       */
      ptr++;
      /* find the next certificate (if any)
       */
      size = data->size - (ptr - (char *) data->data);

      if (size > 0)
        {
          char *ptr2;

          ptr2 = MHD_memmem (ptr, size, PEM_CERT_SEP, sizeof (PEM_CERT_SEP) - 1);
          if (ptr2 == NULL)
            ptr2 =
              MHD_memmem (ptr, size, PEM_CERT_SEP2, sizeof (PEM_CERT_SEP2) - 1);

          ptr = ptr2;
        }
      else
        ptr = NULL;

      count++;
    }
  while (ptr != NULL);

  *cert_max = count;

  if (nocopy == 0)
    return count;
  else
    return GNUTLS_E_SHORT_MEMORY_BUFFER;

error:for (j = 0; j < count; j++)
    MHD_gnutls_x509_crt_deinit (certs[j]);
  return ret;
}
