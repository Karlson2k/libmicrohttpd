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

/* This file contains code for DSA keys.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <debug.h>

/* resarr will contain: p(0), q(1), g(2), y(3), x(4).
 */
int
MHD__gnutls_dsa_generate_params (mpi_t * resarr, int *resarr_len, int bits)
{

  int ret;
  gcry_sexp_t parms, key, list;

  /* FIXME: Remove me once we depend on 1.3.1 */
  if (bits > 1024 && gcry_check_version ("1.3.1") == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (bits < 512)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = gcry_sexp_build (&parms, NULL, "(genkey(dsa(nbits %d)))", bits);
  if (ret != 0)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* generate the DSA key
   */
  ret = gcry_pk_genkey (&key, parms);
  gcry_sexp_release (parms);

  if (ret != 0)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  list = gcry_sexp_find_token (key, "p", 0);
  if (list == NULL)
    {
      MHD_gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[0] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "q", 0);
  if (list == NULL)
    {
      MHD_gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[1] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "g", 0);
  if (list == NULL)
    {
      MHD_gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[2] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "y", 0);
  if (list == NULL)
    {
      MHD_gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[3] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);


  list = gcry_sexp_find_token (key, "x", 0);
  if (list == NULL)
    {
      MHD_gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  resarr[4] = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);


  gcry_sexp_release (key);

  MHD__gnutls_dump_mpi ("p: ", resarr[0]);
  MHD__gnutls_dump_mpi ("q: ", resarr[1]);
  MHD__gnutls_dump_mpi ("g: ", resarr[2]);
  MHD__gnutls_dump_mpi ("y: ", resarr[3]);
  MHD__gnutls_dump_mpi ("x: ", resarr[4]);

  *resarr_len = 5;

  return 0;

}
