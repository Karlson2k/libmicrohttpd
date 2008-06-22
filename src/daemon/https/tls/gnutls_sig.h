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

#ifndef GNUTLS_SIG_H
# define GNUTLS_SIG_H

int _gnutls_tls_sign_hdata (gnutls_session_t session,
			    gnutls_cert * cert,
			    gnutls_privkey * pkey,
			    gnutls_datum_t * signature);

int _gnutls_tls_sign_params (gnutls_session_t session,
			     gnutls_cert * cert,
			     gnutls_privkey * pkey,
			     gnutls_datum_t * params,
			     gnutls_datum_t * signature);

int _gnutls_verify_sig_hdata (gnutls_session_t session,
			      gnutls_cert * cert, gnutls_datum_t * signature);

int _gnutls_verify_sig_params (gnutls_session_t session,
			       gnutls_cert * cert,
			       const gnutls_datum_t * params,
			       gnutls_datum_t * signature);

int _gnutls_sign (gnutls_pk_algorithm_t algo,
		  mpi_t * params, int params_size,
		  const gnutls_datum_t * data, gnutls_datum_t * signature);

#endif
