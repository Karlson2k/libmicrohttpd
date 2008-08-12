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
  * gnutls_x509_crl_init - This function initializes a gnutls_x509_crl_t structure
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
gnutls_x509_crl_init (gnutls_x509_crl_t * crl)
{
  *crl = gnutls_calloc (1, sizeof (gnutls_x509_crl_int));

  if (*crl)
    {
      int result = asn1_create_element (_gnutls_get_pkix (),
                                        "PKIX1.CertificateList",
                                        &(*crl)->crl);
      if (result != ASN1_SUCCESS)
        {
          gnutls_assert ();
          gnutls_free (*crl);
          return mhd_gtls_asn2err (result);
        }
      return 0;                 /* success */
    }
  return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_x509_crl_deinit - This function deinitializes memory used by a gnutls_x509_crl_t structure
  * @crl: The structure to be initialized
  *
  * This function will deinitialize a CRL structure. 
  *
  **/
void
gnutls_x509_crl_deinit (gnutls_x509_crl_t crl)
{
  if (!crl)
    return;

  if (crl->crl)
    asn1_delete_structure (&crl->crl);

  gnutls_free (crl);
}

/**
  * gnutls_x509_crl_import - This function will import a DER or PEM encoded CRL
  * @crl: The structure to store the parsed CRL.
  * @data: The DER or PEM encoded CRL.
  * @format: One of DER or PEM
  *
  * This function will convert the given DER or PEM encoded CRL
  * to the native gnutls_x509_crl_t format. The output will be stored in 'crl'.
  *
  * If the CRL is PEM encoded it should have a header of "X509 CRL".
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crl_import (gnutls_x509_crl_t crl,
                        const gnutls_datum_t * data,
                        gnutls_x509_crt_fmt_t format)
{
  int result = 0, need_free = 0;
  gnutls_datum_t _data;

  _data.data = data->data;
  _data.size = data->size;

  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* If the CRL is in PEM format then decode it
   */
  if (format == GNUTLS_X509_FMT_PEM)
    {
      opaque *out;

      result = _gnutls_fbase64_decode (PEM_CRL, data->data, data->size, &out);

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


  result = asn1_der_decoding (&crl->crl, _data.data, _data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      result = mhd_gtls_asn2err (result);
      gnutls_assert ();
      goto cleanup;
    }

  if (need_free)
    _gnutls_free_datum (&_data);

  return 0;

cleanup:
  if (need_free)
    _gnutls_free_datum (&_data);
  return result;
}


/**
  * gnutls_x509_crl_get_issuer_dn - This function returns the CRL's issuer distinguished name
  * @crl: should contain a gnutls_x509_crl_t structure
  * @buf: a pointer to a structure to hold the peer's name (may be null)
  * @sizeof_buf: initially holds the size of @buf
  *
  * This function will copy the name of the CRL issuer in the provided buffer. The name 
  * will be in the form "C=xxxx,O=yyyy,CN=zzzz" as described in RFC2253. The output
  * string will be ASCII or UTF-8 encoded, depending on the certificate data.
  *
  * If buf is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough, and
  * in that case the sizeof_buf will be updated with the required size, and
  * 0 on success.
  *
  **/
int
gnutls_x509_crl_get_issuer_dn (const gnutls_x509_crl_t crl, char *buf,
                               size_t * sizeof_buf)
{
  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn (crl->crl,
                                "tbsCertList.issuer.rdnSequence",
                                buf, sizeof_buf);
}

/**
  * gnutls_x509_crl_get_issuer_dn_by_oid - This function returns the CRL's issuer distinguished name
  * @crl: should contain a gnutls_x509_crl_t structure
  * @oid: holds an Object Identified in null terminated string
  * @indx: In case multiple same OIDs exist in the RDN, this specifies which to send. Use zero to get the first one.
  * @raw_flag: If non zero returns the raw DER data of the DN part.
  * @buf: a pointer to a structure to hold the peer's name (may be null)
  * @sizeof_buf: initially holds the size of @buf
  *
  * This function will extract the part of the name of the CRL issuer specified
  * by the given OID. The output will be encoded as described in RFC2253. The output
  * string will be ASCII or UTF-8 encoded, depending on the certificate data.
  *
  * Some helper macros with popular OIDs can be found in gnutls/x509.h
  * If raw flag is zero, this function will only return known OIDs as text. Other OIDs 
  * will be DER encoded, as described in RFC2253 -- in hex format with a '\#' prefix.
  * You can check about known OIDs using gnutls_x509_dn_oid_known().
  *
  * If buf is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough, and
  * in that case the sizeof_buf will be updated with the required size,
  * and 0 on success.
  *
  **/
int
gnutls_x509_crl_get_issuer_dn_by_oid (gnutls_x509_crl_t crl,
                                      const char *oid, int indx,
                                      unsigned int raw_flag, void *buf,
                                      size_t * sizeof_buf)
{
  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_parse_dn_oid (crl->crl,
                                    "tbsCertList.issuer.rdnSequence",
                                    oid, indx, raw_flag, buf, sizeof_buf);
}

/**
  * gnutls_x509_crl_get_dn_oid - This function returns the Certificate request issuer's distinguished name OIDs
  * @crl: should contain a gnutls_x509_crl_t structure
  * @indx: Specifies which DN OID to send. Use zero to get the first one.
  * @oid: a pointer to a structure to hold the name (may be null)
  * @sizeof_oid: initially holds the size of 'oid'
  *
  * This function will extract the requested OID of the name of the CRL issuer, specified
  * by the given index. 
  *
  * If oid is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough, and
  * in that case the sizeof_oid will be updated with the required size.
  * On success 0 is returned.
  *
  **/
int
gnutls_x509_crl_get_dn_oid (gnutls_x509_crl_t crl,
                            int indx, void *oid, size_t * sizeof_oid)
{
  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_get_dn_oid (crl->crl,
                                  "tbsCertList.issuer.rdnSequence", indx,
                                  oid, sizeof_oid);
}


/**
  * gnutls_x509_crl_get_signature_algorithm - This function returns the CRL's signature algorithm
  * @crl: should contain a gnutls_x509_crl_t structure
  *
  * This function will return a value of the gnutls_sign_algorithm_t enumeration that 
  * is the signature algorithm. 
  *
  * Returns a negative value on error.
  *
  **/
int
gnutls_x509_crl_get_signature_algorithm (gnutls_x509_crl_t crl)
{
  int result;
  gnutls_datum_t sa;

  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* Read the signature algorithm. Note that parameters are not
   * read. They will be read from the issuer's certificate if needed.
   */

  result =
    _gnutls_x509_read_value (crl->crl, "signatureAlgorithm.algorithm",
                             &sa, 0);

  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  result = mhd_gtls_x509_oid2sign_algorithm ((const char *) sa.data);

  _gnutls_free_datum (&sa);

  return result;
}

/**
 * gnutls_x509_crl_get_signature - Returns the CRL's signature
 * @crl: should contain a gnutls_x509_crl_t structure
 * @sig: a pointer where the signature part will be copied (may be null).
 * @sizeof_sig: initially holds the size of @sig
 *
 * This function will extract the signature field of a CRL.
 *
 * Returns 0 on success, and a negative value on error.
 **/
int
gnutls_x509_crl_get_signature (gnutls_x509_crl_t crl,
                               char *sig, size_t * sizeof_sig)
{
  int result;
  int bits, len;

  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  bits = 0;
  result = asn1_read_value (crl->crl, "signature", NULL, &bits);
  if (result != ASN1_MEM_ERROR)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  if (bits % 8 != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  len = bits / 8;

  if (*sizeof_sig < len)
    {
      *sizeof_sig = bits / 8;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  result = asn1_read_value (crl->crl, "signature", sig, &len);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  return 0;
}

/**
  * gnutls_x509_crl_get_version - This function returns the CRL's version number
  * @crl: should contain a gnutls_x509_crl_t structure
  *
  * This function will return the version of the specified CRL.
  *
  * Returns a negative value on error.
  *
  **/
int
gnutls_x509_crl_get_version (gnutls_x509_crl_t crl)
{
  opaque version[5];
  int len, result;

  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  len = sizeof (version);
  if ((result =
       asn1_read_value (crl->crl, "tbsCertList.version", version,
                        &len)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  return (int) version[0] + 1;
}

/**
  * gnutls_x509_crl_get_this_update - This function returns the CRL's thisUpdate time
  * @crl: should contain a gnutls_x509_crl_t structure
  *
  * This function will return the time this CRL was issued.
  *
  * Returns (time_t)-1 on error.
  *
  **/
time_t
gnutls_x509_crl_get_this_update (gnutls_x509_crl_t crl)
{
  if (crl == NULL)
    {
      gnutls_assert ();
      return (time_t) - 1;
    }

  return _gnutls_x509_get_time (crl->crl, "tbsCertList.thisUpdate");
}

/**
  * gnutls_x509_crl_get_next_update - This function returns the CRL's nextUpdate time
  * @crl: should contain a gnutls_x509_crl_t structure
  *
  * This function will return the time the next CRL will be issued.
  * This field is optional in a CRL so it might be normal to get
  * an error instead.
  *
  * Returns (time_t)-1 on error.
  *
  **/
time_t
gnutls_x509_crl_get_next_update (gnutls_x509_crl_t crl)
{
  if (crl == NULL)
    {
      gnutls_assert ();
      return (time_t) - 1;
    }

  return _gnutls_x509_get_time (crl->crl, "tbsCertList.nextUpdate");
}

/**
  * gnutls_x509_crl_get_crt_count - This function returns the number of revoked certificates in a CRL
  * @crl: should contain a gnutls_x509_crl_t structure
  *
  * This function will return the number of revoked certificates in the
  * given CRL.
  *
  * Returns a negative value on failure.
  *
  **/
int
gnutls_x509_crl_get_crt_count (gnutls_x509_crl_t crl)
{

  int count, result;

  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result =
    asn1_number_of_elements (crl->crl,
                             "tbsCertList.revokedCertificates", &count);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return 0;                 /* no certificates */
    }

  return count;
}

/**
  * gnutls_x509_crl_get_crt_serial - This function returns the serial number of a revoked certificate
  * @crl: should contain a gnutls_x509_crl_t structure
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
gnutls_x509_crl_get_crt_serial (gnutls_x509_crl_t crl, int indx,
                                unsigned char *serial,
                                size_t * serial_size, time_t * t)
{

  int result, _serial_size;
  char serial_name[MAX_NAME_SIZE];
  char date_name[MAX_NAME_SIZE];

  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  snprintf (serial_name, sizeof (serial_name),
            "tbsCertList.revokedCertificates.?%u.userCertificate", indx + 1);
  snprintf (date_name, sizeof (date_name),
            "tbsCertList.revokedCertificates.?%u.revocationDate", indx + 1);

  _serial_size = *serial_size;
  result = asn1_read_value (crl->crl, serial_name, serial, &_serial_size);

  *serial_size = _serial_size;
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      if (result == ASN1_ELEMENT_NOT_FOUND)
        return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
      return mhd_gtls_asn2err (result);
    }

  if (t)
    {
      *t = _gnutls_x509_get_time (crl->crl, date_name);
    }

  return 0;
}

/*-
  * _gnutls_x509_crl_get_raw_issuer_dn - This function returns the issuer's DN DER encoded
  * @crl: should contain a gnutls_x509_crl_t structure
  * @dn: will hold the starting point of the DN
  *
  * This function will return a pointer to the DER encoded DN structure and
  * the length.
  *
  * Returns a negative value on error, and zero on success.
  *
  -*/
int
_gnutls_x509_crl_get_raw_issuer_dn (gnutls_x509_crl_t crl,
                                    gnutls_datum_t * dn)
{
  ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
  int result, len1;
  int start1, end1;
  gnutls_datum_t crl_signed_data;

  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* get the issuer of 'crl'
   */
  if ((result =
       asn1_create_element (_gnutls_get_pkix (), "PKIX1.TBSCertList",
                            &c2)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return mhd_gtls_asn2err (result);
    }

  result =
    _gnutls_x509_get_signed_data (crl->crl, "tbsCertList", &crl_signed_data);
  if (result < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  result =
    asn1_der_decoding (&c2, crl_signed_data.data, crl_signed_data.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      /* couldn't decode DER */
      gnutls_assert ();
      asn1_delete_structure (&c2);
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  result =
    asn1_der_decoding_startEnd (c2, crl_signed_data.data,
                                crl_signed_data.size, "issuer",
                                &start1, &end1);

  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      result = mhd_gtls_asn2err (result);
      goto cleanup;
    }

  len1 = end1 - start1 + 1;

  _gnutls_set_datum (dn, &crl_signed_data.data[start1], len1);

  result = 0;

cleanup:
  asn1_delete_structure (&c2);
  _gnutls_free_datum (&crl_signed_data);
  return result;
}

/**
  * gnutls_x509_crl_export - This function will export the CRL
  * @crl: Holds the revocation list
  * @format: the format of output params. One of PEM or DER.
  * @output_data: will contain a private key PEM or DER encoded
  * @output_data_size: holds the size of output_data (and will be replaced by the actual size of parameters)
  *
  * This function will export the revocation list to DER or PEM format.
  *
  * If the buffer provided is not long enough to hold the output, then
  * GNUTLS_E_SHORT_MEMORY_BUFFER will be returned.
  *
  * If the structure is PEM encoded, it will have a header
  * of "BEGIN X509 CRL".
  *
  * Returns 0 on success, and a negative value on failure.
  *
  **/
int
gnutls_x509_crl_export (gnutls_x509_crl_t crl,
                        gnutls_x509_crt_fmt_t format, void *output_data,
                        size_t * output_data_size)
{
  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_export_int (crl->crl, format, PEM_CRL,
                                  output_data, output_data_size);
}

/*-
  * _gnutls_x509_crl_cpy - This function copies a gnutls_x509_crl_t structure
  * @dest: The structure where to copy
  * @src: The structure to be copied
  *
  * This function will copy an X.509 certificate structure. 
  *
  * Returns 0 on success.
  *
  -*/
int
_gnutls_x509_crl_cpy (gnutls_x509_crl_t dest, gnutls_x509_crl_t src)
{
  int ret;
  size_t der_size;
  opaque *der;
  gnutls_datum_t tmp;

  ret = gnutls_x509_crl_export (src, GNUTLS_X509_FMT_DER, NULL, &der_size);
  if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      gnutls_assert ();
      return ret;
    }

  der = gnutls_alloca (der_size);
  if (der == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = gnutls_x509_crl_export (src, GNUTLS_X509_FMT_DER, der, &der_size);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_afree (der);
      return ret;
    }

  tmp.data = der;
  tmp.size = der_size;
  ret = gnutls_x509_crl_import (dest, &tmp, GNUTLS_X509_FMT_DER);

  gnutls_afree (der);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;

}

#endif
