/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2007 Free Software Foundation
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

/* This file contains the RSA key exchange part of the certificate
 * authentication.
 */

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "libtasn1.h"
#include "gnutls_datum.h"
#include "auth_cert.h"
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include "debug.h"
#include <gnutls_sig.h>
#include <gnutls_x509.h>
#include <gc.h>

int _gnutls_gen_rsa_client_kx (mhd_gtls_session_t, opaque **);
int _gnutls_proc_rsa_client_kx (mhd_gtls_session_t, opaque *, size_t);

const mhd_gtls_mod_auth_st rsa_auth_struct = {
  "RSA",
  mhd_gtls_gen_cert_server_certificate,
  mhd_gtls_gen_cert_client_certificate,
  NULL,                         /* gen server kx */
  _gnutls_gen_rsa_client_kx,
  mhd_gtls_gen_cert_client_cert_vrfy,    /* gen client cert vrfy */
  mhd_gtls_gen_cert_server_cert_req,     /* server cert request */

  mhd_gtls_proc_cert_server_certificate,
  _gnutls_proc_cert_client_certificate,
  NULL,                         /* proc server kx */
  _gnutls_proc_rsa_client_kx,   /* proc client kx */
  mhd_gtls_proc_cert_client_cert_vrfy,   /* proc client cert vrfy */
  mhd_gtls_proc_cert_cert_req    /* proc server cert request */
};

/* This function reads the RSA parameters from peer's certificate;
 */
int
_gnutls_get_public_rsa_params (mhd_gtls_session_t session,
                               mpi_t params[MAX_PUBLIC_PARAMS_SIZE],
                               int *params_len)
{
  int ret;
  cert_auth_info_t info;
  gnutls_cert peer_cert;
  int i;

  /* normal non export case */

  info = mhd_gtls_get_auth_info (session);

  if (info == NULL || info->ncerts == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ret =
    mhd_gtls_raw_cert_to_gcert (&peer_cert,
                               session->security_parameters.cert_type,
                               &info->raw_certificate_list[0],
                               CERT_ONLY_PUBKEY | CERT_NO_COPY);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }


  /* EXPORT case: */
  if (mhd_gtls_cipher_suite_get_kx_algo
      (&session->security_parameters.current_cipher_suite)
      == MHD_GNUTLS_KX_RSA_EXPORT
      && _gnutls_mpi_get_nbits (peer_cert.params[0]) > 512)
    {

      mhd_gtls_gcert_deinit (&peer_cert);

      if (session->key->rsa[0] == NULL || session->key->rsa[1] == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }

      if (*params_len < 2)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
      *params_len = 2;
      for (i = 0; i < *params_len; i++)
        {
          params[i] = _gnutls_mpi_copy (session->key->rsa[i]);
        }

      return 0;
    }

  /* end of export case */

  if (*params_len < peer_cert.params_size)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }
  *params_len = peer_cert.params_size;

  for (i = 0; i < *params_len; i++)
    {
      params[i] = _gnutls_mpi_copy (peer_cert.params[i]);
    }
  mhd_gtls_gcert_deinit (&peer_cert);

  return 0;
}

/* This function reads the RSA parameters from the private key
 */
int
_gnutls_get_private_rsa_params (mhd_gtls_session_t session,
                                mpi_t ** params, int *params_size)
{
  int bits;
  mhd_gtls_cert_credentials_t cred;
  mhd_gtls_rsa_params_t rsa_params;

  cred = (mhd_gtls_cert_credentials_t)
    mhd_gtls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  if (session->internals.selected_cert_list == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  bits =
    _gnutls_mpi_get_nbits (session->internals.selected_cert_list[0].
                           params[0]);

  if (mhd_gtls_cipher_suite_get_kx_algo
      (&session->security_parameters.current_cipher_suite)
      == MHD_GNUTLS_KX_RSA_EXPORT && bits > 512)
    {

      rsa_params =
        mhd_gtls_certificate_get_rsa_params (cred->rsa_params,
                                            cred->params_func, session);
      /* EXPORT case: */
      if (rsa_params == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_NO_TEMPORARY_RSA_PARAMS;
        }

      /* In the export case, we do use temporary RSA params
       * of 512 bits size. The params in the certificate are
       * used to sign this temporary stuff.
       */
      *params_size = RSA_PRIVATE_PARAMS;
      *params = rsa_params->params;

      return 0;
    }

  /* non export cipher suites. */

  *params_size = session->internals.selected_key->params_size;
  *params = session->internals.selected_key->params;

  return 0;
}

int
_gnutls_proc_rsa_client_kx (mhd_gtls_session_t session, opaque * data,
                            size_t _data_size)
{
  gnutls_datum_t plaintext;
  gnutls_datum_t ciphertext;
  int ret, dsize;
  mpi_t *params;
  int params_len;
  int randomize_key = 0;
  ssize_t data_size = _data_size;

  if (MHD_gnutls_protocol_get_version (session) == MHD_GNUTLS_SSL3)
    {
      /* SSL 3.0 
       */
      ciphertext.data = data;
      ciphertext.size = data_size;
    }
  else
    {
      /* TLS 1.0
       */
      DECR_LEN (data_size, 2);
      ciphertext.data = &data[2];
      dsize = mhd_gtls_read_uint16 (data);

      if (dsize != data_size)
        {
          gnutls_assert ();
          return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        }
      ciphertext.size = dsize;
    }

  ret = _gnutls_get_private_rsa_params (session, &params, &params_len);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = mhd_gtls_pkcs1_rsa_decrypt (&plaintext, &ciphertext, params, params_len, 2);     /* btype==2 */

  if (ret < 0 || plaintext.size != TLS_MASTER_SIZE)
    {
      /* In case decryption fails then don't inform
       * the peer. Just use a random key. (in order to avoid
       * attack against pkcs-1 formating).
       */
      gnutls_assert ();
      _gnutls_x509_log ("auth_rsa: Possible PKCS #1 format attack\n");
      randomize_key = 1;
    }
  else
    {
      /* If the secret was properly formatted, then
       * check the version number.
       */
      if (_gnutls_get_adv_version_major (session) != plaintext.data[0]
          || _gnutls_get_adv_version_minor (session) != plaintext.data[1])
        {
          /* No error is returned here, if the version number check
           * fails. We proceed normally.
           * That is to defend against the attack described in the paper
           * "Attacking RSA-based sessions in SSL/TLS" by Vlastimil Klima,
           * Ondej Pokorny and Tomas Rosa.
           */
          gnutls_assert ();
          _gnutls_x509_log
            ("auth_rsa: Possible PKCS #1 version check format attack\n");
        }
    }

  if (randomize_key != 0)
    {
      session->key->key.size = TLS_MASTER_SIZE;
      session->key->key.data = gnutls_malloc (session->key->key.size);
      if (session->key->key.data == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }

      /* we do not need strong random numbers here.
       */
      if (gc_nonce (session->key->key.data, session->key->key.size) != GC_OK)
        {
          gnutls_assert ();
          return GNUTLS_E_RANDOM_FAILED;
        }

    }
  else
    {
      session->key->key.data = plaintext.data;
      session->key->key.size = plaintext.size;
    }

  /* This is here to avoid the version check attack
   * discussed above.
   */
  session->key->key.data[0] = _gnutls_get_adv_version_major (session);
  session->key->key.data[1] = _gnutls_get_adv_version_minor (session);

  return 0;
}



/* return RSA(random) using the peers public key 
 */
int
_gnutls_gen_rsa_client_kx (mhd_gtls_session_t session, opaque ** data)
{
  cert_auth_info_t auth = session->key->auth_info;
  gnutls_datum_t sdata;         /* data to send */
  mpi_t params[MAX_PUBLIC_PARAMS_SIZE];
  int params_len = MAX_PUBLIC_PARAMS_SIZE;
  int ret, i;
  gnutls_protocol_t ver;

  if (auth == NULL)
    {
      /* this shouldn't have happened. The proc_certificate
       * function should have detected that.
       */
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  session->key->key.size = TLS_MASTER_SIZE;
  session->key->key.data = gnutls_secure_malloc (session->key->key.size);

  if (session->key->key.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  if (gc_pseudo_random (session->key->key.data,
                        session->key->key.size) != GC_OK)
    {
      gnutls_assert ();
      return GNUTLS_E_RANDOM_FAILED;
    }

  ver = mhd_gtls_get_adv_version (session);

  if (session->internals.rsa_pms_version[0] == 0)
    {
      session->key->key.data[0] = mhd_gtls_version_get_major (ver);
      session->key->key.data[1] = mhd_gtls_version_get_minor (ver);
    }
  else
    {                           /* use the version provided */
      session->key->key.data[0] = session->internals.rsa_pms_version[0];
      session->key->key.data[1] = session->internals.rsa_pms_version[1];
    }

  /* move RSA parameters to key (session).
   */
  if ((ret =
       _gnutls_get_public_rsa_params (session, params, &params_len)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if ((ret =
       mhd_gtls_pkcs1_rsa_encrypt (&sdata, &session->key->key,
                                  params, params_len, 2)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  for (i = 0; i < params_len; i++)
    mhd_gtls_mpi_release (&params[i]);

  if (MHD_gnutls_protocol_get_version (session) == MHD_GNUTLS_SSL3)
    {
      /* SSL 3.0 */
      *data = sdata.data;
      return sdata.size;
    }
  else
    {                           /* TLS 1 */
      *data = gnutls_malloc (sdata.size + 2);
      if (*data == NULL)
        {
          _gnutls_free_datum (&sdata);
          return GNUTLS_E_MEMORY_ERROR;
        }
      mhd_gtls_write_datum16 (*data, sdata);
      ret = sdata.size + 2;
      _gnutls_free_datum (&sdata);
      return ret;
    }

}
