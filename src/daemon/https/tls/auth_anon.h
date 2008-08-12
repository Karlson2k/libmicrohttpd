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

/* this is not to be included by gnutls_anon.c */
#include <gnutls_auth.h>
#include <auth_dh_common.h>

typedef struct mhd_gtls_anon_server_credentials_st
{
  mhd_gtls_dh_params_t dh_params;
  /* this callback is used to retrieve the DH or RSA
   * parameters.
   */
  gnutls_params_function *params_func;
} mhd_anon_server_credentials_st;

typedef struct mhd_gtls_anon_client_credentials_st
{
  int dummy;
} mhd_anon_client_credentials_st;

typedef struct mhd_gtls_anon_auth_info_st
{
  mhd_gtls_dh_info_st dh;
} * mhd_anon_auth_info_t;

typedef struct mhd_gtls_anon_auth_info_st anon_auth_info_st;
