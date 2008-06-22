/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation
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

/* This file contains the Anonymous Diffie Hellman key exchange part of
 * the anonymous authentication. The functions here are used in the
 * handshake.
 */

#include <gnutls_int.h>

#ifdef ENABLE_ANON

#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "auth_anon.h"
#include "gnutls_num.h"
#include "gnutls_mpi.h"
#include <gnutls_state.h>
#include <auth_dh_common.h>

static int gen_anon_server_kx (gnutls_session_t, opaque **);
static int proc_anon_client_kx (gnutls_session_t, opaque *, size_t);
static int proc_anon_server_kx (gnutls_session_t, opaque *, size_t);

const mod_auth_st anon_auth_struct = {
  "ANON",
  NULL,
  NULL,
  gen_anon_server_kx,
  _gnutls_gen_dh_common_client_kx,      /* this can be shared */
  NULL,
  NULL,

  NULL,
  NULL,                         /* certificate */
  proc_anon_server_kx,
  proc_anon_client_kx,
  NULL,
  NULL
};

static int
gen_anon_server_kx (gnutls_session_t session, opaque ** data)
{
  mpi_t g, p;
  const mpi_t *mpis;
  int ret;
  gnutls_dh_params_t dh_params;
  gnutls_anon_server_credentials_t cred;

  cred = (gnutls_anon_server_credentials_t)
    _gnutls_get_cred (session->key, GNUTLS_CRD_ANON, NULL);
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

  if ((ret =
       _gnutls_auth_info_set (session, GNUTLS_CRD_ANON,
                              sizeof (anon_auth_info_st), 1)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_dh_set_group (session, g, p);

  ret = _gnutls_dh_common_print_server_kx (session, g, p, data, 0);
  if (ret < 0)
    {
      gnutls_assert ();
    }

  return ret;
}


static int
proc_anon_client_kx (gnutls_session_t session, opaque * data,
                     size_t _data_size)
{
  gnutls_anon_server_credentials_t cred;
  int bits;
  int ret;
  mpi_t p, g;
  gnutls_dh_params_t dh_params;
  const mpi_t *mpis;

  bits = _gnutls_dh_get_allowed_prime_bits (session);

  cred = (gnutls_anon_server_credentials_t)
    _gnutls_get_cred (session->key, GNUTLS_CRD_ANON, NULL);
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

int
proc_anon_server_kx (gnutls_session_t session, opaque * data,
                     size_t _data_size)
{

  int ret;

  /* set auth_info */
  if ((ret =
       _gnutls_auth_info_set (session, GNUTLS_CRD_ANON,
                              sizeof (anon_auth_info_st), 1)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_proc_dh_common_server_kx (session, data, _data_size, 0);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

#endif /* ENABLE_ANON */
