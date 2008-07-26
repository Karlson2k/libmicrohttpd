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

/* This file contains functions to handle CRL generation.
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

static void disable_optional_stuff (gnutls_x509_crl_t crl);

/**
  * gnutls_x509_crl_set_version - This function will set the CRL version
  * @crl: should contain a gnutls_x509_crl_t structure
  * @version: holds the version number. For CRLv1 crls must be 1.
  *
  * This function will set the version of the CRL. This
  * must be one for CRL version 1, and so on. The CRLs generated
  * by gnutls should have a version number of 2.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crl_set_version (gnutls_x509_crl_t crl, unsigned int version)
{
  int result;
  char null = version;

  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  null -= 1;
  if (null < 0)
    null = 0;

  result = asn1_write_value (crl->crl, "tbsCertList.version", &null, 1);
  if (result != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  return 0;
}

/**
  * gnutls_x509_crl_sign2 - This function will sign a CRL with a key
  * @crl: should contain a gnutls_x509_crl_t structure
  * @issuer: is the certificate of the certificate issuer
  * @issuer_key: holds the issuer's private key
  * @dig: The message digest to use. GNUTLS_DIG_SHA1 is the safe choice unless you know what you're doing.
  * @flags: must be 0
  *
  * This function will sign the CRL with the issuer's private key, and
  * will copy the issuer's information into the CRL.
  *
  * This must be the last step in a certificate CRL since all
  * the previously set parameters are now signed.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crl_sign2 (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer,
                       gnutls_x509_privkey_t issuer_key,
                       gnutls_digest_algorithm_t dig, unsigned int flags)
{
  int result;

  if (crl == NULL || issuer == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* disable all the unneeded OPTIONAL fields.
   */
  disable_optional_stuff (crl);

  result = _gnutls_x509_pkix_sign (crl->crl, "tbsCertList",
                                   dig, issuer, issuer_key);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}

/**
  * gnutls_x509_crl_sign - This function will sign a CRL with a key
  * @crl: should contain a gnutls_x509_crl_t structure
  * @issuer: is the certificate of the certificate issuer
  * @issuer_key: holds the issuer's private key
  *
  * This function is the same a gnutls_x509_crl_sign2() with no flags, and
  * SHA1 as the hash algorithm.
  *
  * Returns 0 on success.
  *
  **/
int
gnutls_x509_crl_sign (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer,
                      gnutls_x509_privkey_t issuer_key)
{
  return gnutls_x509_crl_sign2 (crl, issuer, issuer_key, MHD_GNUTLS_DIG_SHA1,
                                0);
}

/**
  * gnutls_x509_crl_set_this_update - This function will set the CRL's issuing time
  * @crl: should contain a gnutls_x509_crl_t structure
  * @act_time: The actual time
  *
  * This function will set the time this CRL was issued.
  *
  * Returns 0 on success, or a negative value in case of an error.
  *
  **/
int
gnutls_x509_crl_set_this_update (gnutls_x509_crl_t crl, time_t act_time)
{
  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_x509_set_time (crl->crl, "tbsCertList.thisUpdate", act_time);
}

/**
  * gnutls_x509_crl_set_next_update - This function will set the CRL next update time
  * @crl: should contain a gnutls_x509_crl_t structure
  * @exp_time: The actual time
  *
  * This function will set the time this CRL will be updated.
  *
  * Returns 0 on success, or a negative value in case of an error.
  *
  **/
int
gnutls_x509_crl_set_next_update (gnutls_x509_crl_t crl, time_t exp_time)
{
  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
  return _gnutls_x509_set_time (crl->crl, "tbsCertList.nextUpdate", exp_time);
}

/**
  * gnutls_x509_crl_set_crt_serial - This function will set a revoked certificate's serial number
  * @crl: should contain a gnutls_x509_crl_t structure
  * @serial: The revoked certificate's serial number
  * @serial_size: Holds the size of the serial field.
  * @revocation_time: The time this certificate was revoked
  *
  * This function will set a revoked certificate's serial number to the CRL. 
  *
  * Returns 0 on success, or a negative value in case of an error.
  *
  **/
int
gnutls_x509_crl_set_crt_serial (gnutls_x509_crl_t crl,
                                const void *serial, size_t serial_size,
                                time_t revocation_time)
{
  int ret;

  if (crl == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret =
    asn1_write_value (crl->crl, "tbsCertList.revokedCertificates", "NEW", 1);
  if (ret != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (ret);
    }

  ret =
    asn1_write_value (crl->crl,
                      "tbsCertList.revokedCertificates.?LAST.userCertificate",
                      serial, serial_size);
  if (ret != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (ret);
    }

  ret =
    _gnutls_x509_set_time (crl->crl,
                           "tbsCertList.revokedCertificates.?LAST.revocationDate",
                           revocation_time);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret =
    asn1_write_value (crl->crl,
                      "tbsCertList.revokedCertificates.?LAST.crlEntryExtensions",
                      NULL, 0);
  if (ret != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (ret);
    }

  return 0;
}

/**
  * gnutls_x509_crl_set_crt - This function will set a revoked certificate's serial number
  * @crl: should contain a gnutls_x509_crl_t structure
  * @crt: should contain a gnutls_x509_crt_t structure with the revoked certificate
  * @revocation_time: The time this certificate was revoked
  *
  * This function will set a revoked certificate's serial number to the CRL. 
  *
  * Returns 0 on success, or a negative value in case of an error.
  *
  **/
int
gnutls_x509_crl_set_crt (gnutls_x509_crl_t crl, gnutls_x509_crt_t crt,
                         time_t revocation_time)
{
  int ret;
  opaque serial[128];
  size_t serial_size;

  if (crl == NULL || crt == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  serial_size = sizeof (serial);
  ret = gnutls_x509_crt_get_serial (crt, serial, &serial_size);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret =
    gnutls_x509_crl_set_crt_serial (crl, serial, serial_size,
                                    revocation_time);
  if (ret < 0)
    {
      gnutls_assert ();
      return _gnutls_asn2err (ret);
    }

  return 0;
}


/* If OPTIONAL fields have not been initialized then
 * disable them.
 */
static void
disable_optional_stuff (gnutls_x509_crl_t crl)
{

  asn1_write_value (crl->crl, "tbsCertList.crlExtensions", NULL, 0);

  return;
}

#endif /* ENABLE_PKI */
