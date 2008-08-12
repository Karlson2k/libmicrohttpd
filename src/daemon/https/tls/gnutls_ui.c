/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation
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

/* This file contains certificate authentication functions to be exported in the
 * API and did not fit elsewhere.
 */

#include <gnutls_int.h>
#include <auth_anon.h>
#include <auth_cert.h>
#include <gnutls_errors.h>
#include <gnutls_auth_int.h>
#include <gnutls_state.h>
#include <gnutls_datum.h>

/* ANON & DHE */

/**
 * MHD_gnutls_dh_set_prime_bits - Used to set the bits for a DH ciphersuite
 * @session: is a #mhd_gtls_session_t structure.
 * @bits: is the number of bits
 *
 * This function sets the number of bits, for use in an 
 * Diffie Hellman key exchange. This is used both in DH ephemeral and
 * DH anonymous cipher suites. This will set the
 * minimum size of the prime that will be used for the handshake.
 *
 * In the client side it sets the minimum accepted number of bits.
 * If a server sends a prime with less bits than that 
 * GNUTLS_E_DH_PRIME_UNACCEPTABLE will be returned by the
 * handshake.
 *
 **/
void
MHD_gnutls_dh_set_prime_bits (mhd_gtls_session_t session, unsigned int bits)
{
  session->internals.dh_prime_bits = bits;
}

/**
 * MHD_gnutls_dh_get_group - This function returns the group of the DH authentication
 * @session: is a gnutls session
 * @raw_gen: will hold the generator.
 * @raw_prime: will hold the prime.
 *
 * This function will return the group parameters used in the last Diffie Hellman 
 * authentication with the peer. These are the prime and the generator used.
 * This function should be used for both anonymous and ephemeral diffie Hellman.
 * The output parameters must be freed with gnutls_free().
 *
 * Returns a negative value in case of an error.
 *
 **/
int
MHD_gnutls_dh_get_group (mhd_gtls_session_t session,
                     gnutls_datum_t * raw_gen, gnutls_datum_t * raw_prime)
{
  mhd_gtls_dh_info_st *dh;
  int ret;
  mhd_anon_auth_info_t anon_info;
  cert_auth_info_t cert_info;

  switch (MHD_gtls_auth_get_type (session))
    {
    case MHD_GNUTLS_CRD_ANON:
      anon_info = mhd_gtls_get_auth_info (session);
      if (anon_info == NULL)
        return GNUTLS_E_INTERNAL_ERROR;
      dh = &anon_info->dh;
      break;
    case MHD_GNUTLS_CRD_CERTIFICATE:
      cert_info = mhd_gtls_get_auth_info (session);
      if (cert_info == NULL)
        return GNUTLS_E_INTERNAL_ERROR;
      dh = &cert_info->dh;
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = _gnutls_set_datum (raw_prime, dh->prime.data, dh->prime.size);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_set_datum (raw_gen, dh->generator.data, dh->generator.size);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (raw_prime);
      return ret;
    }

  return 0;
}

/**
 * MHD_gnutls_dh_get_pubkey - This function returns the peer's public key used in DH authentication
 * @session: is a gnutls session
 * @raw_key: will hold the public key.
 *
 * This function will return the peer's public key used in the last Diffie Hellman authentication.
 * This function should be used for both anonymous and ephemeral diffie Hellman.
 * The output parameters must be freed with gnutls_free().
 *
 * Returns a negative value in case of an error.
 *
 **/
int
MHD_gnutls_dh_get_pubkey (mhd_gtls_session_t session, gnutls_datum_t * raw_key)
{
  mhd_gtls_dh_info_st *dh;
  mhd_anon_auth_info_t anon_info;
  cert_auth_info_t cert_info;
  cert_auth_info_t psk_info;

  switch (MHD_gtls_auth_get_type (session))
    {
    case MHD_GNUTLS_CRD_ANON:
      {
        anon_info = mhd_gtls_get_auth_info (session);
        if (anon_info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;
        dh = &anon_info->dh;
        break;
      }
    case MHD_GNUTLS_CRD_PSK:
      {
        psk_info = mhd_gtls_get_auth_info (session);
        if (psk_info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;
        dh = &psk_info->dh;
        break;
      }
    case MHD_GNUTLS_CRD_CERTIFICATE:
      {

        cert_info = mhd_gtls_get_auth_info (session);
        if (cert_info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;
        dh = &cert_info->dh;
        break;
      }
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return _gnutls_set_datum (raw_key, dh->public_key.data,
                            dh->public_key.size);
}

/**
 * MHD_gtls_rsa_export_get_pubkey - This function returns the peer's public key used in RSA-EXPORT authentication
 * @session: is a gnutls session
 * @exponent: will hold the exponent.
 * @modulus: will hold the modulus.
 *
 * This function will return the peer's public key exponent and
 * modulus used in the last RSA-EXPORT authentication.  The output
 * parameters must be freed with gnutls_free().
 *
 * Returns a negative value in case of an error.
 *
 **/
int
MHD_gtls_rsa_export_get_pubkey (mhd_gtls_session_t session,
                              gnutls_datum_t * exponent,
                              gnutls_datum_t * modulus)
{
  cert_auth_info_t info;
  int ret;

  if (MHD_gtls_auth_get_type (session) == MHD_GNUTLS_CRD_CERTIFICATE)
    {
      info = mhd_gtls_get_auth_info (session);
      if (info == NULL)
        return GNUTLS_E_INTERNAL_ERROR;

      ret = _gnutls_set_datum (modulus, info->rsa_export.modulus.data,
                               info->rsa_export.modulus.size);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      ret = _gnutls_set_datum (exponent, info->rsa_export.exponent.data,
                               info->rsa_export.exponent.size);
      if (ret < 0)
        {
          gnutls_assert ();
          _gnutls_free_datum (modulus);
          return ret;
        }

      return 0;
    }

  return GNUTLS_E_INVALID_REQUEST;
}

/**
 * MHD_gnutls_dh_get_secret_bits - This function returns the bits used in DH authentication
 * @session: is a gnutls session
 *
 * This function will return the bits used in the last Diffie Hellman authentication
 * with the peer. Should be used for both anonymous and ephemeral diffie Hellman.
 * Returns a negative value in case of an error.
 *
 **/
int
MHD_gnutls_dh_get_secret_bits (mhd_gtls_session_t session)
{
  switch (MHD_gtls_auth_get_type (session))
    {
    case MHD_GNUTLS_CRD_ANON:
      {
        mhd_anon_auth_info_t info;

        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;
        return info->dh.secret_bits;
      }
    case MHD_GNUTLS_CRD_CERTIFICATE:
      {
        cert_auth_info_t info;

        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;

        return info->dh.secret_bits;
      }
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
}

/**
 * MHD_gnutls_dh_get_prime_bits - This function returns the bits used in DH authentication
 * @session: is a gnutls session
 *
 * This function will return the bits of the prime used in the last Diffie Hellman authentication
 * with the peer. Should be used for both anonymous and ephemeral diffie Hellman.
 * Returns a negative value in case of an error.
 *
 **/
int
MHD_gnutls_dh_get_prime_bits (mhd_gtls_session_t session)
{
  mhd_gtls_dh_info_st *dh;

  switch (MHD_gtls_auth_get_type (session))
    {
    case MHD_GNUTLS_CRD_ANON:
      {
        mhd_anon_auth_info_t info;

        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;
        dh = &info->dh;
        break;
      }
    case MHD_GNUTLS_CRD_CERTIFICATE:
      {
        cert_auth_info_t info;

        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;

        dh = &info->dh;
        break;
      }
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return (dh->prime.size) * 8;

}

/**
 * MHD_gtls_rsa_export_get_modulus_bits - This function returns the bits used in RSA-export key exchange
 * @session: is a gnutls session
 *
 * This function will return the bits used in the last RSA-EXPORT key exchange
 * with the peer. 
 * Returns a negative value in case of an error.
 *
 **/
int
MHD_gtls_rsa_export_get_modulus_bits (mhd_gtls_session_t session)
{
  cert_auth_info_t info;

  info = mhd_gtls_get_auth_info (session);
  if (info == NULL)
    return GNUTLS_E_INTERNAL_ERROR;

  return info->rsa_export.modulus.size * 8;
}

/**
 * MHD_gnutls_dh_get_peers_public_bits - This function returns the bits used in DH authentication
 * @session: is a gnutls session
 *
 * This function will return the bits used in the last Diffie Hellman authentication
 * with the peer. Should be used for both anonymous and ephemeral diffie Hellman.
 * Returns a negative value in case of an error.
 *
 **/
int
MHD_gnutls_dh_get_peers_public_bits (mhd_gtls_session_t session)
{
  mhd_gtls_dh_info_st *dh;

  switch (MHD_gtls_auth_get_type (session))
    {
    case MHD_GNUTLS_CRD_ANON:
      {
        mhd_anon_auth_info_t info;

        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;

        dh = &info->dh;
        break;
      }
    case MHD_GNUTLS_CRD_CERTIFICATE:
      {
        cert_auth_info_t info;

        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;

        dh = &info->dh;
        break;
      }
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return dh->public_key.size * 8;

}

/* CERTIFICATE STUFF */

/**
 * MHD_gtls_certificate_get_ours - This function returns the raw certificate sent in the last handshake
 * @session: is a gnutls session
 *
 * This function will return the certificate as sent to the peer,
 * in the last handshake. These certificates are in raw format. 
 * In X.509 this is a certificate list. In OpenPGP this is a single
 * certificate.
 * Returns NULL in case of an error, or if no certificate was used.
 *
 **/
const gnutls_datum_t *
MHD_gtls_certificate_get_ours (mhd_gtls_session_t session)
{
  mhd_gtls_cert_credentials_t cred;

  CHECK_AUTH (MHD_GNUTLS_CRD_CERTIFICATE, NULL);

  cred
    = (mhd_gtls_cert_credentials_t) mhd_gtls_get_cred (session->key,
                                                           MHD_GNUTLS_CRD_CERTIFICATE,
                                                           NULL);
  if (cred == NULL || cred->cert_list == NULL)
    {
      gnutls_assert ();
      return NULL;
    }

  if (session->internals.selected_cert_list == NULL)
    return NULL;

  return &session->internals.selected_cert_list[0].raw;
}

/**
 * MHD_gtls_certificate_get_peers - This function returns the peer's raw certificate
 * @session: is a gnutls session
 * @list_size: is the length of the certificate list
 *
 * This function will return the peer's raw certificate (chain) as 
 * sent by the peer. These certificates are in raw format (DER encoded 
 * for X.509). In case of a X.509 then a certificate list may be present. 
 * The first certificate in the list is the peer's certificate,
 * following the issuer's certificate, then the issuer's issuer etc.
 *
 * In case of OpenPGP keys a single key will be returned
 * in raw format.
 *
 * Returns NULL in case of an error, or if no certificate was sent.
 *
 **/
const gnutls_datum_t *
MHD_gtls_certificate_get_peers (mhd_gtls_session_t
                              session, unsigned int *list_size)
{
  cert_auth_info_t info;

  CHECK_AUTH (MHD_GNUTLS_CRD_CERTIFICATE, NULL);

  info = mhd_gtls_get_auth_info (session);
  if (info == NULL)
    return NULL;

  *list_size = info->ncerts;
  return info->raw_certificate_list;
}

/**
 * MHD_gtls_certificate_client_get_request_status - This function returns the certificate request status
 * @session: is a gnutls session
 *
 * This function will return 0 if the peer (server) did not request client
 * authentication or 1 otherwise.
 * Returns a negative value in case of an error.
 *
 **/
int
MHD_gtls_certificate_client_get_request_status (mhd_gtls_session_t session)
{
  cert_auth_info_t info;

  CHECK_AUTH (MHD_GNUTLS_CRD_CERTIFICATE, 0);

  info = mhd_gtls_get_auth_info (session);
  if (info == NULL)
    return GNUTLS_E_INTERNAL_ERROR;
  return info->certificate_requested;
}

/**
 * MHD_gnutls_fingerprint - This function calculates the fingerprint of the given data
 * @algo: is a digest algorithm
 * @data: is the data
 * @result: is the place where the result will be copied (may be null). 
 * @result_size: should hold the size of the result. The actual size
 * of the returned result will also be copied there.
 *
 * This function will calculate a fingerprint (actually a hash), of the
 * given data. The result is not printable data. You should convert it
 * to hex, or to something else printable.
 *
 * This is the usual way to calculate a fingerprint of an X.509 
 * DER encoded certificate. Note however that the fingerprint 
 * of an OpenPGP is not just a hash and cannot be calculated with
 * this function.
 *
 * Returns a negative value in case of an error.
 *
 **/
int
MHD_gnutls_fingerprint (gnutls_digest_algorithm_t algo,
                    const gnutls_datum_t * data,
                    void *result, size_t * result_size)
{
  GNUTLS_HASH_HANDLE td;
  int hash_len = mhd_gnutls_hash_get_algo_len (HASH2MAC (algo));

  if (hash_len < 0 || (unsigned) hash_len > *result_size || result == NULL)
    {
      *result_size = hash_len;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }
  *result_size = hash_len;

  if (result)
    {
      td = mhd_gtls_hash_init (HASH2MAC (algo));
      if (td == NULL)
        return GNUTLS_E_HASH_FAILED;

      mhd_gnutls_hash (td, data->data, data->size);

      mhd_gnutls_hash_deinit (td, result);
    }

  return 0;
}

/**
 * MHD_gnutls_certificate_set_dh_params - This function will set the DH parameters for a server to use
 * @res: is a mhd_gtls_cert_credentials_t structure
 * @dh_params: is a structure that holds diffie hellman parameters.
 *
 * This function will set the diffie hellman parameters for a
 * certificate server to use. These parameters will be used in
 * Ephemeral Diffie Hellman cipher suites.  Note that only a pointer
 * to the parameters are stored in the certificate handle, so if you
 * deallocate the parameters before the certificate is deallocated,
 * you must change the parameters stored in the certificate first.
 *
 **/
void
MHD_gnutls_certificate_set_dh_params (mhd_gtls_cert_credentials_t res,
                                  mhd_gtls_dh_params_t dh_params)
{
  res->dh_params = dh_params;
}

/**
 * gnutls_certificate_set_params_function - This function will set the DH or RSA parameters callback
 * @res: is a mhd_gtls_cert_credentials_t structure
 * @func: is the function to be called
 *
 * This function will set a callback in order for the server to get the 
 * diffie hellman or RSA parameters for certificate authentication. The callback
 * should return zero on success.
 *
 **/
void
gnutls_certificate_set_params_function (mhd_gtls_cert_credentials_t res,
                                        gnutls_params_function * func)
{
  res->params_func = func;
}

/**
 * MHD_gnutls_certificate_set_verify_flags - This function will set the flags to be used at certificate verification
 * @res: is a mhd_gtls_cert_credentials_t structure
 * @flags: are the flags
 *
 * This function will set the flags to be used at verification of the
 * certificates.  Flags must be OR of the
 * #gnutls_certificate_verify_flags enumerations.
 *
 **/
void
MHD_gnutls_certificate_set_verify_flags (mhd_gtls_cert_credentials_t
                                     res, unsigned int flags)
{
  res->verify_flags = flags;
}

/**
 * MHD_gnutls_certificate_set_verify_limits - This function will set the upper limits to be used at certificate verification
 * @res: is a gnutls_certificate_credentials structure
 * @max_bits: is the number of bits of an acceptable certificate (default 8200)
 * @max_depth: is maximum depth of the verification of a certificate chain (default 5)
 *
 * This function will set some upper limits for the default verification function,
 * MHD_gtls_certificate_verify_peers2(), to avoid denial of service attacks.
 * You can set them to zero to disable limits.
 *
 **/
void
MHD_gnutls_certificate_set_verify_limits (mhd_gtls_cert_credentials_t
                                      res,
                                      unsigned int max_bits,
                                      unsigned int max_depth)
{
  res->verify_depth = max_depth;
  res->verify_bits = max_bits;
}

/**
 * MHD_gnutls_certificate_set_rsa_export_params - This function will set the RSA parameters for a server to use
 * @res: is a mhd_gtls_cert_credentials_t structure
 * @rsa_params: is a structure that holds temporary RSA parameters.
 *
 * This function will set the temporary RSA parameters for a certificate
 * server to use. These parameters will be used in RSA-EXPORT
 * cipher suites.
 *
 **/
void
MHD_gnutls_certificate_set_rsa_export_params (mhd_gtls_cert_credentials_t
                                          res, mhd_gtls_rsa_params_t rsa_params)
{
  res->rsa_params = rsa_params;
}

/**
 * gnutls_anon_set_params_function - This function will set the DH or RSA parameters callback
 * @res: is a mhd_gtls_anon_server_credentials_t structure
 * @func: is the function to be called
 *
 * This function will set a callback in order for the server to get the 
 * diffie hellman or RSA parameters for anonymous authentication. The callback
 * should return zero on success.
 *
 **/
void
gnutls_anon_set_params_function (mhd_gtls_anon_server_credentials_t res,
                                 gnutls_params_function * func)
{
  res->params_func = func;
}
