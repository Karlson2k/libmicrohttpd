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

#ifndef GNUTLS_DH_H
# define GNUTLS_DH_H

const mpi_t *_gnutls_dh_params_to_mpi (gnutls_dh_params_t);
mpi_t gnutls_calc_dh_secret (mpi_t * ret_x, mpi_t g, mpi_t prime);
mpi_t gnutls_calc_dh_key (mpi_t f, mpi_t x, mpi_t prime);
int _gnutls_dh_generate_prime (mpi_t * ret_g, mpi_t * ret_n, unsigned bits);

gnutls_dh_params_t
_gnutls_get_dh_params (gnutls_dh_params_t dh_params,
		       gnutls_params_function * func,
		       gnutls_session_t session);

#endif
