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

/* This file contains everything for the Ephemeral Diffie Hellman (DHE)
 * key exchange. This is used in the handshake procedure of the certificate
 * authentication.
 */

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "gnutls_sig.h"
#include <gnutls_datum.h>
#include <auth_cert.h>
#include <gnutls_x509.h>
#include <gnutls_state.h>
#include <auth_dh_common.h>

static int gen_dhe_server_kx (gnutls_session_t, opaque **);
static int proc_dhe_server_kx (gnutls_session_t, opaque *, size_t);
static int proc_dhe_client_kx (gnutls_session_t, opaque *, size_t);

const mod_auth_st dhe_rsa_auth_struct = {
  "DHE_RSA",
  _gnutls_gen_cert_server_certificate,
  _gnutls_gen_cert_client_certificate,
  gen_dhe_server_kx,
  _gnutls_gen_dh_common_client_kx,
  _gnutls_gen_cert_client_cert_vrfy,    /* gen client cert vrfy */
  _gnutls_gen_cert_server_cert_req,     /* server cert request */

  _gnutls_proc_cert_server_certificate,
  _gnutls_proc_cert_client_certificate,
  proc_dhe_server_kx,
  proc_dhe_client_kx,
  _gnutls_proc_cert_client_cert_vrfy,   /* proc client cert vrfy */
  _gnutls_proc_cert_cert_req    /* proc server cert request */
};

const mod_auth_st dhe_dss_auth_struct = {
  "DHE_DSS",
  _gnutls_gen_cert_server_certificate,
  _gnutls_gen_cert_client_certificate,
  gen_dhe_server_kx,
  _gnutls_gen_dh_common_client_kx,
  _gnutls_gen_cert_client_cert_vrfy,    /* gen client cert vrfy */
  _gnutls_gen_cert_server_cert_req,     /* server cert request */

  _gnutls_proc_cert_server_certificate,
  _gnutls_proc_cert_client_certificate,
  proc_dhe_server_kx,
  proc_dhe_client_kx,
  _gnutls_proc_cert_client_cert_vrfy,   /* proc client cert vrfy */
  _gnutls_proc_cert_cert_req    /* proc server cert request */
};


static int
gen_dhe_server_kx (gnutls_session_t session, opaque ** data)
{
  mpi_t g, p;
  const mpi_t *mpis;
  int ret = 0, data_size;
  int bits;
  gnutls_cert *apr_cert_list;
  gnutls_privkey *apr_pkey;
  int apr_cert_list_length;
  gnutls_datum_t signature, ddata;
  gnutls_certificate_credentials_t cred;
  gnutls_dh_params_t dh_params;

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  bits = _gnutls_dh_get_allowed_prime_bits (session);

  /* find the appropriate certificate */
  if ((ret =
       _gnutls_get_selected_cert (session, &apr_cert_list,
                                  &apr_cert_list_length, &apr_pkey)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  dh_params =
    _gnutls_get_dh_params (cred->dh_params, cred->params_func, session);
  mpis = _gnutls_dh_params_to_mpi (dh_params);
  if (mpis == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_TEMPORARY_DH_PARAMS;
    }

  p = mpis[0];
  g = mpis[1];

  if ((ret = _gnutls_auth_info_set (session, MHD_GNUTLS_CRD_CERTIFICATE,
                                    sizeof (cert_auth_info_st), 0)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_dh_set_group (session, g, p);

  ret = _gnutls_dh_common_print_server_kx (session, g, p, data, 0);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }
  data_size = ret;

  /* Generate the signature. */

  ddata.data = *data;
  ddata.size = data_size;

  if (apr_cert_list_length > 0)
    {
      if ((ret =
           _gnutls_tls_sign_params (session, &apr_cert_list[0],
                                    apr_pkey, &ddata, &signature)) < 0)
        {
          gnutls_assert ();
          gnutls_free (*data);
          return ret;
        }
    }
  else
    {
      gnutls_assert ();
      return data_size;         /* do not put a signature - ILLEGAL! */
    }

  *data = gnutls_realloc_fast (*data, data_size + signature.size + 2);
  if (*data == NULL)
    {
      _gnutls_free_datum (&signature);
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  _gnutls_write_datum16 (&(*data)[data_size], signature);
  data_size += signature.size + 2;

  _gnutls_free_datum (&signature);

  return data_size;
}

static int
proc_dhe_server_kx (gnutls_session_t session, opaque * data,
                    size_t _data_size)
{
  int sigsize;
  gnutls_datum_t vparams, signature;
  int ret;
  cert_auth_info_t info = _gnutls_get_auth_info (session);
  ssize_t data_size = _data_size;
  gnutls_cert peer_cert;

  if (info == NULL || info->ncerts == 0)
    {
      gnutls_assert ();
      /* we need this in order to get peer's certificate */
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ret = _gnutls_proc_dh_common_server_kx (session, data, _data_size, 0);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* VERIFY SIGNATURE */

  vparams.size = ret;
  vparams.data = data;

  DECR_LEN (data_size, 2);
  sigsize = _gnutls_read_uint16 (&data[vparams.size]);

  DECR_LEN (data_size, sigsize);
  signature.data = &data[vparams.size + 2];
  signature.size = sigsize;

  if ((ret =
       _gnutls_raw_cert_to_gcert (&peer_cert,
                                  session->security_parameters.cert_type,
                                  &info->raw_certificate_list[0],
                                  CERT_NO_COPY)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_verify_sig_params (session, &peer_cert, &vparams, &signature);

  _gnutls_gcert_deinit (&peer_cert);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return ret;
}



static int
proc_dhe_client_kx (gnutls_session_t session, opaque * data,
                    size_t _data_size)
{
  gnutls_certificate_credentials_t cred;
  int ret;
  mpi_t p, g;
  const mpi_t *mpis;
  gnutls_dh_params_t dh_params;

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  dh_params =
    _gnutls_get_dh_params (cred->dh_params, cred->params_func, session);
  mpis = _gnutls_dh_params_to_mpi (dh_params);
  if (mpis == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_TEMPORARY_DH_PARAMS;
    }

  p = mpis[0];
  g = mpis[1];

  ret = _gnutls_proc_dh_common_client_kx (session, data, _data_size, g, p);

  return ret;

}
