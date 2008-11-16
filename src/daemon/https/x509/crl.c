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

#include <gnutls_int.h>
#include <libtasn1.h>

#ifdef ENABLE_PKI

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <x509_b64.h>
#include <x509.h>
#include <dn.h>

/**
  * MHD_gnutls_x509_crl_init - This function initializes a MHD_gnutls_x509_crl_t structure
  * @crl: The structure to be initialized
  *
  * This function will initialize a CRL structure. CRL stands for
  * Certificate Revocation List. A revocation list usually contains
  * lists of certificate serial numbers that have been revoked
  * by an Authority. The revocation lists are always signed with
  * the authority's private key.
  *
  * Returns 0 on success.
  *
  **/
int
MHD_gnutls_x509_crl_init (MHD_gnutls_x509_crl_t * crl)
{
  *crl = MHD_gnutls_calloc (1, sizeof (MHD_gnutls_x509_crl_int));

  if (*crl)
    {
      int result = MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                                             "PKIX1.CertificateList",
                                             &(*crl)->crl);
      if (result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          MHD_gnutls_free (*crl);
          return MHD_gtls_asn2err (result);
        }
      return 0;                 /* success */
    }
  return GNUTLS_E_MEMORY_ERROR;
}

/**
  * MHD_gnutls_x509_crl_deinit - This function deinitializes memory used by a MHD_gnutls_x509_crl_t structure
  * @crl: The structure to be initialized
  *
  * This function will deinitialize a CRL structure.
  *
  **/
void
MHD_gnutls_x509_crl_deinit (MHD_gnutls_x509_crl_t crl)
{
  if (!crl)
    return;

  if (crl->crl)
    MHD__asn1_delete_structure (&crl->crl);

  MHD_gnutls_free (crl);
}

/**
  * MHD_gnutls_x509_crl_import - This function will import a DER or PEM encoded CRL
  * @crl: The structure to store the parsed CRL.
  * @data: The DER or PEM encoded CRL.
  * @format: One of DER or PEM
  *
  * This function will convert the given DER or PEM encoded CRL
  * to the native MHD_gnutls_x509_crl_t format. The output will be stored in 'crl'.
  *
  * If the CRL is PEM encoded it should have a header of "X509 CRL".
  *
  * Returns 0 on success.
  *
  **/
int
MHD_gnutls_x509_crl_import (MHD_gnutls_x509_crl_t crl,
                            const MHD_gnutls_datum_t * data,
                            MHD_gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  MHD_gnutls_datum_t _data;

  _data.data = data->data;
  _data.size = data->size;

  if (crl == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* If the CRL is in PEM format then decode it
   */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      result =
        MHD__gnutls_fbase64_decode (PEM_CRL, data->data, data->size, &out);

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


  result = MHD__asn1_der_decoding (&crl->crl, _data.data, _data.size, NULL);
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
  * MHD_gnutls_x509_crl_get_signature_algorithm - This function returns the CRL's signature algorithm
  * @crl: should contain a MHD_gnutls_x509_crl_t structure
  *
  * This function will return a value of the MHD_gnutls_sign_algorithm_t enumeration that
  * is the signature algorithm.
  *
  * Returns a negative value on error.
  *
  **/
int
MHD_gnutls_x509_crl_get_signature_algorithm (MHD_gnutls_x509_crl_t crl)
{
  int result;
  MHD_gnutls_datum_t sa;

  if (crl == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Read the signature algorithm. Note that parameters are not
   * read. They will be read from the issuer's certificate if needed.
   */

  result =
    MHD__gnutls_x509_read_value (crl->crl, "signatureAlgorithm.algorithm",
                                 &sa, 0);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  result = MHD_gtls_x509_oid2sign_algorithm ((const char *) sa.data);

  MHD__gnutls_free_datum (&sa);

  return result;
}

/**
 * MHD_gnutls_x509_crl_get_signature - Returns the CRL's signature
 * @crl: should contain a MHD_gnutls_x509_crl_t structure
 * @sig: a pointer where the signature part will be copied (may be null).
 * @sizeof_sig: initially holds the size of @sig
 *
 * This function will extract the signature field of a CRL.
 *
 * Returns 0 on success, and a negative value on error.
 **/
int
MHD_gnutls_x509_crl_get_signature (MHD_gnutls_x509_crl_t crl,
                                   char *sig, size_t * sizeof_sig)
{
  int result;
  int bits, len;

  if (crl == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  bits = 0;
  result = MHD__asn1_read_value (crl->crl, "signature", NULL, &bits);
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

  result = MHD__asn1_read_value (crl->crl, "signature", sig, &len);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  return 0;
}


/**
  * MHD_gnutls_x509_crl_get_crt_count - This function returns the number of revoked certificates in a CRL
  * @crl: should contain a MHD_gnutls_x509_crl_t structure
  *
  * This function will return the number of revoked certificates in the
  * given CRL.
  *
  * Returns a negative value on failure.
  *
  **/
int
MHD_gnutls_x509_crl_get_crt_count (MHD_gnutls_x509_crl_t crl)
{

  int count, result;

  if (crl == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result =
    MHD__asn1_number_of_elements (crl->crl,
                                  "tbsCertList.revokedCertificates", &count);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return 0;                 /* no certificates */
    }

  return count;
}

/**
  * MHD_gnutls_x509_crl_get_crt_serial - This function returns the serial number of a revoked certificate
  * @crl: should contain a MHD_gnutls_x509_crl_t structure
  * @indx: the index of the certificate to extract (starting from 0)
  * @serial: where the serial number will be copied
  * @serial_size: initially holds the size of serial
  * @t: if non null, will hold the time this certificate was revoked
  *
  * This function will return the serial number of the specified, by
  * the index, revoked certificate.
  *
  * Returns a negative value on failure.
  *
  **/
int
MHD_gnutls_x509_crl_get_crt_serial (MHD_gnutls_x509_crl_t crl, int indx,
                                    unsigned char *serial,
                                    size_t * serial_size, time_t * t)
{

  int result, _serial_size;
  char serial_name[MAX_NAME_SIZE];
  char date_name[MAX_NAME_SIZE];

  if (crl == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  snprintf (serial_name, sizeof (serial_name),
            "tbsCertList.revokedCertificates.?%u.userCertificate", indx + 1);
  snprintf (date_name, sizeof (date_name),
            "tbsCertList.revokedCertificates.?%u.revocationDate", indx + 1);

  _serial_size = *serial_size;
  result =
    MHD__asn1_read_value (crl->crl, serial_name, serial, &_serial_size);

  *serial_size = _serial_size;
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      if (result == ASN1_ELEMENT_NOT_FOUND)
        return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
      return MHD_gtls_asn2err (result);
    }

  if (t)
    {
      *t = MHD__gnutls_x509_get_time (crl->crl, date_name);
    }

  return 0;
}

/*-
  * MHD__gnutls_x509_crl_get_raw_issuer_dn - This function returns the issuer's DN DER encoded
  * @crl: should contain a MHD_gnutls_x509_crl_t structure
  * @dn: will hold the starting point of the DN
  *
  * This function will return a pointer to the DER encoded DN structure and
  * the length.
  *
  * Returns a negative value on error, and zero on success.
  *
  -*/
int
MHD__gnutls_x509_crl_get_raw_issuer_dn (MHD_gnutls_x509_crl_t crl,
                                        MHD_gnutls_datum_t * dn)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result, len1;
  int start1, end1;
  MHD_gnutls_datum_t crl_signed_data;

  if (crl == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* get the issuer of 'crl'
   */
  if ((result =
       MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.TBSCertList",
                                 &c2)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result =
    MHD__gnutls_x509_get_signed_data (crl->crl, "tbsCertList",
                                      &crl_signed_data);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  result =
    MHD__asn1_der_decoding (&c2, crl_signed_data.data, crl_signed_data.size,
                            NULL);
  if (result != ASN1_SUCCESS)
    {
      /* couldn't decode DER */
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&c2);
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  result =
    MHD__asn1_der_decoding_startEnd (c2, crl_signed_data.data,
                                     crl_signed_data.size, "issuer",
                                     &start1, &end1);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  len1 = end1 - start1 + 1;

  MHD__gnutls_set_datum (dn, &crl_signed_data.data[start1], len1);

  result = 0;

cleanup:
  MHD__asn1_delete_structure (&c2);
  MHD__gnutls_free_datum (&crl_signed_data);
  return result;
}

#endif
