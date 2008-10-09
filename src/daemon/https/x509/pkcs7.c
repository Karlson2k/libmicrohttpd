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

/* Functions that relate on PKCS7 certificate lists parsing.
 */

#include <gnutls_int.h>
#include <libtasn1.h>

#ifdef ENABLE_PKI

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <x509_b64.h>
#include <pkcs7.h>
#include <dn.h>

#define SIGNED_DATA_OID "1.2.840.113549.1.7.2"

/* Decodes the PKCS #7 signed data, and returns an ASN1_TYPE,
 * which holds them. If raw is non null then the raw decoded
 * data are copied (they are locally allocated) there.
 */
static int
_decode_pkcs7_signed_data (ASN1_TYPE pkcs7, ASN1_TYPE * sdata,
                           MHD_gnutls_datum_t * raw)
{
  char oid[128];
  ASN1_TYPE c2;
  opaque *tmp = NULL;
  int tmp_size, len, result;

  len = sizeof (oid) - 1;
  result = MHD__asn1_read_value (pkcs7, "contentType", oid, &len);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  if (strcmp (oid, SIGNED_DATA_OID) != 0)
    {
      MHD_gnutls_assert ();
      MHD__gnutls_x509_log ("Unknown PKCS7 Content OID '%s'\n", oid);
      return GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE;
    }

  if ((result = MHD__asn1_create_element
       (MHD__gnutls_get_pkix (), "PKIX1.pkcs-7-SignedData", &c2)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  /* the Signed-data has been created, so
   * decode them.
   */
  tmp_size = 0;
  result = MHD__asn1_read_value (pkcs7, "content", NULL, &tmp_size);
  if (result != ASN1_MEM_ERROR)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  tmp = MHD_gnutls_malloc (tmp_size);
  if (tmp == NULL)
    {
      MHD_gnutls_assert ();
      result = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  result = MHD__asn1_read_value (pkcs7, "content", tmp, &tmp_size);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* tmp, tmp_size hold the data and the size of the CertificateSet structure
   * actually the ANY stuff.
   */

  /* Step 1. In case of a signed structure extract certificate set.
   */

  result = MHD__asn1_der_decoding (&c2, tmp, tmp_size, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if (raw == NULL)
    {
      MHD_gnutls_free (tmp);
    }
  else
    {
      raw->data = tmp;
      raw->size = tmp_size;
    }

  *sdata = c2;

  return 0;

cleanup:
  if (c2)
    MHD__asn1_delete_structure (&c2);
  MHD_gnutls_free (tmp);
  return result;
}

/**
  * MHD_gnutls_pkcs7_init - This function initializes a MHD_gnutls_pkcs7_t structure
  * @pkcs7: The structure to be initialized
  *
  * This function will initialize a PKCS7 structure. PKCS7 structures
  * usually contain lists of X.509 Certificates and X.509 Certificate
  * revocation lists.
  *
  * Returns 0 on success.
  *
  **/
int
MHD_gnutls_pkcs7_init (MHD_gnutls_pkcs7_t * pkcs7)
{
  *pkcs7 = MHD_gnutls_calloc (1, sizeof (MHD_gnutls_pkcs7_int));

  if (*pkcs7)
    {
      int result = MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                                        "PKIX1.pkcs-7-ContentInfo",
                                        &(*pkcs7)->pkcs7);
      if (result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          MHD_gnutls_free (*pkcs7);
          return MHD_gtls_asn2err (result);
        }
      return 0;                 /* success */
    }
  return GNUTLS_E_MEMORY_ERROR;
}

/**
  * MHD_gnutls_pkcs7_deinit - This function deinitializes memory used by a MHD_gnutls_pkcs7_t structure
  * @pkcs7: The structure to be initialized
  *
  * This function will deinitialize a PKCS7 structure.
  *
  **/
void
MHD_gnutls_pkcs7_deinit (MHD_gnutls_pkcs7_t pkcs7)
{
  if (!pkcs7)
    return;

  if (pkcs7->pkcs7)
    MHD__asn1_delete_structure (&pkcs7->pkcs7);

  MHD_gnutls_free (pkcs7);
}

/**
  * MHD_gnutls_pkcs7_import - This function will import a DER or PEM encoded PKCS7
  * @pkcs7: The structure to store the parsed PKCS7.
  * @data: The DER or PEM encoded PKCS7.
  * @format: One of DER or PEM
  *
  * This function will convert the given DER or PEM encoded PKCS7
  * to the native MHD_gnutls_pkcs7_t format. The output will be stored in 'pkcs7'.
  *
  * If the PKCS7 is PEM encoded it should have a header of "PKCS7".
  *
  * Returns 0 on success.
  *
  **/
int
MHD_gnutls_pkcs7_import (MHD_gnutls_pkcs7_t pkcs7, const MHD_gnutls_datum_t * data,
                     MHD_gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  MHD_gnutls_datum_t _data;

  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  _data.data = data->data;
  _data.size = data->size;

  /* If the PKCS7 is in PEM format then decode it
   */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      result = MHD__gnutls_fbase64_decode (PEM_PKCS7, data->data, data->size,
                                       &out);

      if (result <= 0)
        {
          if (result == 0)
            result = GNUTLS_E_INTERNAL_ERROR;
          MHD_gnutls_assert ();
          return result;
        }

      _data.data = out;
      _data.size = result;

      need_free = 1;
    }


  result = MHD__asn1_der_decoding (&pkcs7->pkcs7, _data.data, _data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      result = MHD_gtls_asn2err (result);
      MHD_gnutls_assert ();
      goto cleanup;
    }

  if (need_free)
    MHD__gnutls_free_datum (&_data);

  return 0;

cleanup:
  if (need_free)
    MHD__gnutls_free_datum (&_data);
  return result;
}

/**
  * MHD_gnutls_pkcs7_get_crt_raw - This function returns a certificate in a PKCS7 certificate set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  * @indx: contains the index of the certificate to extract
  * @certificate: the contents of the certificate will be copied there (may be null)
  * @certificate_size: should hold the size of the certificate
  *
  * This function will return a certificate of the PKCS7 or RFC2630 certificate set.
  * Returns 0 on success. If the provided buffer is not long enough,
  * then @certificate_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER is returned.
  *
  * After the last certificate has been read GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
  * will be returned.
  *
  **/
int
MHD_gnutls_pkcs7_get_crt_raw (MHD_gnutls_pkcs7_t pkcs7,
                          int indx, void *certificate,
                          size_t * certificate_size)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result, len;
  char root2[MAX_NAME_SIZE];
  char oid[128];
  MHD_gnutls_datum_t tmp = { NULL, 0 };

  if (certificate_size == NULL || pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  /* Step 1. decode the signed data.
   */
  result = _decode_pkcs7_signed_data (pkcs7->pkcs7, &c2, &tmp);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  /* Step 2. Parse the CertificateSet
   */

  snprintf (root2, sizeof (root2), "certificates.?%u", indx + 1);

  len = sizeof (oid) - 1;

  result = MHD__asn1_read_value (c2, root2, oid, &len);

  if (result == ASN1_VALUE_NOT_FOUND)
    {
      result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
      goto cleanup;
    }

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* if 'Certificate' is the choice found:
   */
  if (strcmp (oid, "certificate") == 0)
    {
      int start, end;

      result = MHD__asn1_der_decoding_startEnd (c2, tmp.data, tmp.size,
                                           root2, &start, &end);

      if (result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto cleanup;
        }

      end = end - start + 1;

      if ((unsigned) end > *certificate_size)
        {
          *certificate_size = end;
          result = GNUTLS_E_SHORT_MEMORY_BUFFER;
          goto cleanup;
        }

      if (certificate)
        memcpy (certificate, &tmp.data[start], end);

      *certificate_size = end;

      result = 0;

    }
  else
    {
      result = GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
    }

cleanup:
  MHD__gnutls_free_datum (&tmp);
  if (c2)
    MHD__asn1_delete_structure (&c2);
  return result;
}

/**
  * MHD_gnutls_pkcs7_get_crt_count - This function returns the number of certificates in a PKCS7 certificate set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  *
  * This function will return the number of certifcates in the PKCS7 or
  * RFC2630 certificate set.
  *
  * Returns a negative value on failure.
  *
  **/
int
MHD_gnutls_pkcs7_get_crt_count (MHD_gnutls_pkcs7_t pkcs7)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result, count;

  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  /* Step 1. decode the signed data.
   */
  result = _decode_pkcs7_signed_data (pkcs7->pkcs7, &c2, NULL);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  /* Step 2. Count the CertificateSet */

  result = MHD__asn1_number_of_elements (c2, "certificates", &count);

  MHD__asn1_delete_structure (&c2);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return 0;                 /* no certificates */
    }

  return count;

}

/**
  * MHD_gnutls_pkcs7_export - This function will export the pkcs7 structure
  * @pkcs7: Holds the pkcs7 structure
  * @format: the format of output params. One of PEM or DER.
  * @output_data: will contain a structure PEM or DER encoded
  * @output_data_size: holds the size of output_data (and will be
  *   replaced by the actual size of parameters)
  *
  * This function will export the pkcs7 structure to DER or PEM format.
  *
  * If the buffer provided is not long enough to hold the output, then
  * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
  * be returned.
  *
  * If the structure is PEM encoded, it will have a header
  * of "BEGIN PKCS7".
  *
  * Return value: In case of failure a negative value will be
  *   returned, and 0 on success.
  *
  **/
int
MHD_gnutls_pkcs7_export (MHD_gnutls_pkcs7_t pkcs7,
                     MHD_gnutls_x509_crt_fmt_t format, void *output_data,
                     size_t * output_data_size)
{
  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  return MHD__gnutls_x509_export_int (pkcs7->pkcs7, format, PEM_PKCS7,
                                  output_data, output_data_size);
}

/* Creates an empty signed data structure in the pkcs7
 * structure and returns a handle to the signed data.
 */
static int
create_empty_signed_data (ASN1_TYPE pkcs7, ASN1_TYPE * sdata)
{
  uint8_t one = 1;
  int result;

  *sdata = ASN1_TYPE_EMPTY;

  if ((result = MHD__asn1_create_element
       (MHD__gnutls_get_pkix (), "PKIX1.pkcs-7-SignedData",
        sdata)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* Use version 1
   */
  result = MHD__asn1_write_value (*sdata, "version", &one, 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* Use no digest algorithms
   */

  /* id-data */
  result =
    MHD__asn1_write_value (*sdata, "encapContentInfo.eContentType",
                      "1.2.840.113549.1.7.5", 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  result = MHD__asn1_write_value (*sdata, "encapContentInfo.eContent", NULL, 0);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* Add no certificates.
   */

  /* Add no crls.
   */

  /* Add no signerInfos.
   */

  /* Write the content type of the signed data
   */
  result = MHD__asn1_write_value (pkcs7, "contentType", SIGNED_DATA_OID, 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  return 0;

cleanup:
  MHD__asn1_delete_structure (sdata);
  return result;

}

/**
  * MHD_gnutls_pkcs7_set_crt_raw - This function adds a certificate in a PKCS7 certificate set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  * @crt: the DER encoded certificate to be added
  *
  * This function will add a certificate to the PKCS7 or RFC2630 certificate set.
  * Returns 0 on success.
  *
  **/
int
MHD_gnutls_pkcs7_set_crt_raw (MHD_gnutls_pkcs7_t pkcs7, const MHD_gnutls_datum_t * crt)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result;

  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  /* Step 1. decode the signed data.
   */
  result = _decode_pkcs7_signed_data (pkcs7->pkcs7, &c2, NULL);
  if (result < 0 && result != GNUTLS_E_ASN1_VALUE_NOT_FOUND)
    {
      MHD_gnutls_assert ();
      return result;
    }

  /* If the signed data are uninitialized
   * then create them.
   */
  if (result == GNUTLS_E_ASN1_VALUE_NOT_FOUND)
    {
      /* The pkcs7 structure is new, so create the
       * signedData.
       */
      result = create_empty_signed_data (pkcs7->pkcs7, &c2);
      if (result < 0)
        {
          MHD_gnutls_assert ();
          return result;
        }
    }

  /* Step 2. Append the new certificate.
   */

  result = MHD__asn1_write_value (c2, "certificates", "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  result = MHD__asn1_write_value (c2, "certificates.?LAST", "certificate", 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  result =
    MHD__asn1_write_value (c2, "certificates.?LAST.certificate", crt->data,
                      crt->size);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* Step 3. Replace the old content with the new
   */
  result =
    MHD__gnutls_x509_der_encode_and_copy (c2, "", pkcs7->pkcs7, "content", 0);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  MHD__asn1_delete_structure (&c2);

  return 0;

cleanup:
  if (c2)
    MHD__asn1_delete_structure (&c2);
  return result;
}

/**
  * MHD_gnutls_pkcs7_set_crt - This function adds a parsed certificate in a PKCS7 certificate set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  * @crt: the certificate to be copied.
  *
  * This function will add a parsed certificate to the PKCS7 or RFC2630 certificate set.
  * This is a wrapper function over MHD_gnutls_pkcs7_set_crt_raw() .
  *
  * Returns 0 on success.
  *
  **/
int
MHD_gnutls_pkcs7_set_crt (MHD_gnutls_pkcs7_t pkcs7, MHD_gnutls_x509_crt_t crt)
{
  int ret;
  MHD_gnutls_datum_t data;

  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  ret = MHD__gnutls_x509_der_encode (crt->cert, "", &data, 0);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  ret = MHD_gnutls_pkcs7_set_crt_raw (pkcs7, &data);

  MHD__gnutls_free_datum (&data);

  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  return 0;
}


/**
  * MHD_gnutls_pkcs7_delete_crt - This function deletes a certificate from a PKCS7 certificate set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  * @indx: the index of the certificate to delete
  *
  * This function will delete a certificate from a PKCS7 or RFC2630 certificate set.
  * Index starts from 0. Returns 0 on success.
  *
  **/
int
MHD_gnutls_pkcs7_delete_crt (MHD_gnutls_pkcs7_t pkcs7, int indx)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result;
  char root2[MAX_NAME_SIZE];

  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  /* Step 1. Decode the signed data.
   */
  result = _decode_pkcs7_signed_data (pkcs7->pkcs7, &c2, NULL);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  /* Step 2. Delete the certificate.
   */

  snprintf (root2, sizeof (root2), "certificates.?%u", indx + 1);

  result = MHD__asn1_write_value (c2, root2, NULL, 0);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* Step 3. Replace the old content with the new
   */
  result =
    MHD__gnutls_x509_der_encode_and_copy (c2, "", pkcs7->pkcs7, "content", 0);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  MHD__asn1_delete_structure (&c2);

  return 0;

cleanup:
  if (c2)
    MHD__asn1_delete_structure (&c2);
  return result;
}

/* Read and write CRLs
 */

/**
  * MHD_gnutls_pkcs7_get_crl_raw - This function returns a crl in a PKCS7 crl set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  * @indx: contains the index of the crl to extract
  * @crl: the contents of the crl will be copied there (may be null)
  * @crl_size: should hold the size of the crl
  *
  * This function will return a crl of the PKCS7 or RFC2630 crl set.
  * Returns 0 on success. If the provided buffer is not long enough,
  * then @crl_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER is returned.
  *
  * After the last crl has been read GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
  * will be returned.
  *
  **/
int
MHD_gnutls_pkcs7_get_crl_raw (MHD_gnutls_pkcs7_t pkcs7,
                          int indx, void *crl, size_t * crl_size)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result;
  char root2[MAX_NAME_SIZE];
  MHD_gnutls_datum_t tmp = { NULL, 0 };
  int start, end;

  if (pkcs7 == NULL || crl_size == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  /* Step 1. decode the signed data.
   */
  result = _decode_pkcs7_signed_data (pkcs7->pkcs7, &c2, &tmp);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  /* Step 2. Parse the CertificateSet
   */

  snprintf (root2, sizeof (root2), "crls.?%u", indx + 1);

  /* Get the raw CRL
   */
  result = MHD__asn1_der_decoding_startEnd (c2, tmp.data, tmp.size,
                                       root2, &start, &end);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  end = end - start + 1;

  if ((unsigned) end > *crl_size)
    {
      *crl_size = end;
      result = GNUTLS_E_SHORT_MEMORY_BUFFER;
      goto cleanup;
    }

  if (crl)
    memcpy (crl, &tmp.data[start], end);

  *crl_size = end;

  result = 0;

cleanup:
  MHD__gnutls_free_datum (&tmp);
  if (c2)
    MHD__asn1_delete_structure (&c2);
  return result;
}

/**
  * MHD_gnutls_pkcs7_get_crl_count - This function returns the number of crls in a PKCS7 crl set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  *
  * This function will return the number of certifcates in the PKCS7 or
  * RFC2630 crl set.
  *
  * Returns a negative value on failure.
  *
  **/
int
MHD_gnutls_pkcs7_get_crl_count (MHD_gnutls_pkcs7_t pkcs7)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result, count;

  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  /* Step 1. decode the signed data.
   */
  result = _decode_pkcs7_signed_data (pkcs7->pkcs7, &c2, NULL);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  /* Step 2. Count the CertificateSet */

  result = MHD__asn1_number_of_elements (c2, "crls", &count);

  MHD__asn1_delete_structure (&c2);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return 0;                 /* no crls */
    }

  return count;

}

/**
  * MHD_gnutls_pkcs7_set_crl_raw - This function adds a crl in a PKCS7 crl set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  * @crl: the DER encoded crl to be added
  *
  * This function will add a crl to the PKCS7 or RFC2630 crl set.
  * Returns 0 on success.
  *
  **/
int
MHD_gnutls_pkcs7_set_crl_raw (MHD_gnutls_pkcs7_t pkcs7, const MHD_gnutls_datum_t * crl)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result;

  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  /* Step 1. decode the signed data.
   */
  result = _decode_pkcs7_signed_data (pkcs7->pkcs7, &c2, NULL);
  if (result < 0 && result != GNUTLS_E_ASN1_VALUE_NOT_FOUND)
    {
      MHD_gnutls_assert ();
      return result;
    }

  /* If the signed data are uninitialized
   * then create them.
   */
  if (result == GNUTLS_E_ASN1_VALUE_NOT_FOUND)
    {
      /* The pkcs7 structure is new, so create the
       * signedData.
       */
      result = create_empty_signed_data (pkcs7->pkcs7, &c2);
      if (result < 0)
        {
          MHD_gnutls_assert ();
          return result;
        }
    }

  /* Step 2. Append the new crl.
   */

  result = MHD__asn1_write_value (c2, "crls", "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  result = MHD__asn1_write_value (c2, "crls.?LAST", crl->data, crl->size);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* Step 3. Replace the old content with the new
   */
  result =
    MHD__gnutls_x509_der_encode_and_copy (c2, "", pkcs7->pkcs7, "content", 0);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  MHD__asn1_delete_structure (&c2);

  return 0;

cleanup:
  if (c2)
    MHD__asn1_delete_structure (&c2);
  return result;
}

/**
  * MHD_gnutls_pkcs7_set_crl - This function adds a parsed crl in a PKCS7 crl set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  * @crl: the DER encoded crl to be added
  *
  * This function will add a parsed crl to the PKCS7 or RFC2630 crl set.
  * Returns 0 on success.
  *
  **/
int
MHD_gnutls_pkcs7_set_crl (MHD_gnutls_pkcs7_t pkcs7, MHD_gnutls_x509_crl_t crl)
{
  int ret;
  MHD_gnutls_datum_t data;

  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  ret = MHD__gnutls_x509_der_encode (crl->crl, "", &data, 0);
  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  ret = MHD_gnutls_pkcs7_set_crl_raw (pkcs7, &data);

  MHD__gnutls_free_datum (&data);

  if (ret < 0)
    {
      MHD_gnutls_assert ();
      return ret;
    }

  return 0;
}

/**
  * MHD_gnutls_pkcs7_delete_crl - This function deletes a crl from a PKCS7 crl set
  * @pkcs7_struct: should contain a MHD_gnutls_pkcs7_t structure
  * @indx: the index of the crl to delete
  *
  * This function will delete a crl from a PKCS7 or RFC2630 crl set.
  * Index starts from 0. Returns 0 on success.
  *
  **/
int
MHD_gnutls_pkcs7_delete_crl (MHD_gnutls_pkcs7_t pkcs7, int indx)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result;
  char root2[MAX_NAME_SIZE];

  if (pkcs7 == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  /* Step 1. Decode the signed data.
   */
  result = _decode_pkcs7_signed_data (pkcs7->pkcs7, &c2, NULL);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  /* Step 2. Delete the crl.
   */

  snprintf (root2, sizeof (root2), "crls.?%u", indx + 1);

  result = MHD__asn1_write_value (c2, root2, NULL, 0);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* Step 3. Replace the old content with the new
   */
  result =
    MHD__gnutls_x509_der_encode_and_copy (c2, "", pkcs7->pkcs7, "content", 0);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  MHD__asn1_delete_structure (&c2);

  return 0;

cleanup:
  if (c2)
    MHD__asn1_delete_structure (&c2);
  return result;
}

#endif /* ENABLE_PKI */
