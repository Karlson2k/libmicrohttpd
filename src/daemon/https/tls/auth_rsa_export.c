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
#include <gnutls_rsa_export.h>
#include <gnutls_state.h>

int _gnutls_gen_rsa_client_kx (gnutls_session_t, opaque **);
int _gnutls_proc_rsa_client_kx (gnutls_session_t, opaque *, size_t);
static int gen_rsa_export_server_kx (gnutls_session_t, opaque **);
static int proc_rsa_export_server_kx (gnutls_session_t, opaque *, size_t);

const mod_auth_st rsa_export_auth_struct = {
  "RSA EXPORT",
  _gnutls_gen_cert_server_certificate,
  _gnutls_gen_cert_client_certificate,
  gen_rsa_export_server_kx,
  _gnutls_gen_rsa_client_kx,
  _gnutls_gen_cert_client_cert_vrfy,    /* gen client cert vrfy */
  _gnutls_gen_cert_server_cert_req,     /* server cert request */

  _gnutls_proc_cert_server_certificate,
  _gnutls_proc_cert_client_certificate,
  proc_rsa_export_server_kx,
  _gnutls_proc_rsa_client_kx,   /* proc client kx */
  _gnutls_proc_cert_client_cert_vrfy,   /* proc client cert vrfy */
  _gnutls_proc_cert_cert_req    /* proc server cert request */
};

static int
gen_rsa_export_server_kx (gnutls_session_t session, opaque ** data)
{
  gnutls_rsa_params_t rsa_params;
  const mpi_t *rsa_mpis;
  size_t n_e, n_m;
  uint8_t *data_e, *data_m;
  int ret = 0, data_size;
  gnutls_cert *apr_cert_list;
  gnutls_privkey *apr_pkey;
  int apr_cert_list_length;
  gnutls_datum_t signature, ddata;
  cert_auth_info_t info;
  gnutls_certificate_credentials_t cred;

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  /* find the appropriate certificate */
  if ((ret =
       _gnutls_get_selected_cert (session, &apr_cert_list,
                                  &apr_cert_list_length, &apr_pkey)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* abort sending this message if we have a certificate
   * of 512 bits or less.
   */
  if (apr_pkey && _gnutls_mpi_get_nbits (apr_pkey->params[0]) <= 512)
    {
      gnutls_assert ();
      return GNUTLS_E_INT_RET_0;
    }

  rsa_params =
    _gnutls_certificate_get_rsa_params (cred->rsa_params, cred->params_func,
                                        session);
  rsa_mpis = _gnutls_rsa_params_to_mpi (rsa_params);
  if (rsa_mpis == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_TEMPORARY_RSA_PARAMS;
    }

  if ((ret = _gnutls_auth_info_set (session, GNUTLS_CRD_CERTIFICATE,
                                    sizeof (cert_auth_info_st), 0)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  info = _gnutls_get_auth_info (session);
  _gnutls_rsa_export_set_pubkey (session, rsa_mpis[1], rsa_mpis[0]);

  _gnutls_mpi_print (NULL, &n_m, rsa_mpis[0]);
  _gnutls_mpi_print (NULL, &n_e, rsa_mpis[1]);

  (*data) = gnutls_malloc (n_e + n_m + 4);
  if (*data == NULL)
    {
      return GNUTLS_E_MEMORY_ERROR;
    }

  data_m = &(*data)[0];
  _gnutls_mpi_print (&data_m[2], &n_m, rsa_mpis[0]);

  _gnutls_write_uint16 (n_m, data_m);

  data_e = &data_m[2 + n_m];
  _gnutls_mpi_print (&data_e[2], &n_e, rsa_mpis[1]);

  _gnutls_write_uint16 (n_e, data_e);

  data_size = n_m + n_e + 4;


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
          *data = NULL;
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

  _gnutls_write_datum16 (&((*data)[data_size]), signature);
  data_size += signature.size + 2;

  _gnutls_free_datum (&signature);

  return data_size;
}

/* if the peer's certificate is of 512 bits or less, returns non zero.
 */
int
_gnutls_peers_cert_less_512 (gnutls_session_t session)
{
  gnutls_cert peer_cert;
  int ret;
  cert_auth_info_t info = _gnutls_get_auth_info (session);

  if (info == NULL || info->ncerts == 0)
    {
      gnutls_assert ();
      /* we need this in order to get peer's certificate */
      return 0;
    }

  if ((ret =
       _gnutls_raw_cert_to_gcert (&peer_cert,
                                  session->security_parameters.cert_type,
                                  &info->raw_certificate_list[0],
                                  CERT_NO_COPY)) < 0)
    {
      gnutls_assert ();
      return 0;
    }

  if (peer_cert.subject_pk_algorithm != GNUTLS_PK_RSA)
    {
      gnutls_assert ();
      _gnutls_gcert_deinit (&peer_cert);
      return 0;
    }

  if (_gnutls_mpi_get_nbits (peer_cert.params[0]) <= 512)
    {
      _gnutls_gcert_deinit (&peer_cert);
      return 1;
    }

  _gnutls_gcert_deinit (&peer_cert);

  return 0;
}

static int
proc_rsa_export_server_kx (gnutls_session_t session,
                           opaque * data, size_t _data_size)
{
  uint16_t n_m, n_e;
  size_t _n_m, _n_e;
  uint8_t *data_m;
  uint8_t *data_e;
  int i, sigsize;
  gnutls_datum_t vparams, signature;
  int ret;
  ssize_t data_size = _data_size;
  cert_auth_info_t info;
  gnutls_cert peer_cert;

  info = _gnutls_get_auth_info (session);
  if (info == NULL || info->ncerts == 0)
    {
      gnutls_assert ();
      /* we need this in order to get peer's certificate */
      return GNUTLS_E_INTERNAL_ERROR;
    }


  i = 0;

  DECR_LEN (data_size, 2);
  n_m = _gnutls_read_uint16 (&data[i]);
  i += 2;

  DECR_LEN (data_size, n_m);
  data_m = &data[i];
  i += n_m;

  DECR_LEN (data_size, 2);
  n_e = _gnutls_read_uint16 (&data[i]);
  i += 2;

  DECR_LEN (data_size, n_e);
  data_e = &data[i];
  i += n_e;

  _n_e = n_e;
  _n_m = n_m;

  if (_gnutls_mpi_scan_nz (&session->key->rsa[0], data_m, &_n_m) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  if (_gnutls_mpi_scan_nz (&session->key->rsa[1], data_e, &_n_e) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  _gnutls_rsa_export_set_pubkey (session, session->key->rsa[1],
                                 session->key->rsa[0]);

  /* VERIFY SIGNATURE */

  vparams.size = n_m + n_e + 4;
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
    }

  return ret;
}
