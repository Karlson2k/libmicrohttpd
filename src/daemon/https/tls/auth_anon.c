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

static int gen_anon_server_kx (mhd_gtls_session_t, opaque **);
static int proc_anon_client_kx (mhd_gtls_session_t, opaque *, size_t);
static int mhd_gtls_proc_anon_server_kx (mhd_gtls_session_t, opaque *, size_t);

const mhd_gtls_mod_auth_st anon_auth_struct = {
  "ANON",
  NULL,
  NULL,
  gen_anon_server_kx,
  mhd_gtls_gen_dh_common_client_kx,      /* this can be shared */
  NULL,
  NULL,

  NULL,
  NULL,                         /* certificate */
  mhd_gtls_proc_anon_server_kx,
  proc_anon_client_kx,
  NULL,
  NULL
};

static int
gen_anon_server_kx (mhd_gtls_session_t session, opaque ** data)
{
  mpi_t g, p;
  const mpi_t *mpis;
  int ret;
  mhd_gtls_dh_params_t dh_params;
  mhd_gtls_anon_server_credentials_t cred;

  cred = (mhd_gtls_anon_server_credentials_t)
    mhd_gtls_get_cred (session->key, MHD_GNUTLS_CRD_ANON, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  dh_params =
    mhd_gtls_get_dh_params (cred->dh_params, cred->params_func, session);
  mpis = mhd_gtls_dh_params_to_mpi (dh_params);
  if (mpis == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_TEMPORARY_DH_PARAMS;
    }

  p = mpis[0];
  g = mpis[1];

  if ((ret =
       mhd_gtls_auth_info_set (session, MHD_GNUTLS_CRD_ANON,
                              sizeof (anon_auth_info_st), 1)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  mhd_gtls_dh_set_group (session, g, p);

  ret = mhd_gtls_dh_common_print_server_kx (session, g, p, data, 0);
  if (ret < 0)
    {
      gnutls_assert ();
    }

  return ret;
}


static int
proc_anon_client_kx (mhd_gtls_session_t session, opaque * data,
                     size_t _data_size)
{
  mhd_gtls_anon_server_credentials_t cred;
  int bits;
  int ret;
  mpi_t p, g;
  mhd_gtls_dh_params_t dh_params;
  const mpi_t *mpis;

  bits = mhd_gtls_dh_get_allowed_prime_bits (session);

  cred = (mhd_gtls_anon_server_credentials_t)
    mhd_gtls_get_cred (session->key, MHD_GNUTLS_CRD_ANON, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  dh_params =
    mhd_gtls_get_dh_params (cred->dh_params, cred->params_func, session);
  mpis = mhd_gtls_dh_params_to_mpi (dh_params);
  if (mpis == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_TEMPORARY_DH_PARAMS;
    }

  p = mpis[0];
  g = mpis[1];

  ret = mhd_gtls_proc_dh_common_client_kx (session, data, _data_size, g, p);

  return ret;

}

int
mhd_gtls_proc_anon_server_kx (mhd_gtls_session_t session, opaque * data,
                     size_t _data_size)
{

  int ret;

  /* set auth_info */
  if ((ret =
       mhd_gtls_auth_info_set (session, MHD_GNUTLS_CRD_ANON,
                              sizeof (anon_auth_info_st), 1)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = mhd_gtls_proc_dh_common_server_kx (session, data, _data_size, 0);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

#endif /* ENABLE_ANON */
