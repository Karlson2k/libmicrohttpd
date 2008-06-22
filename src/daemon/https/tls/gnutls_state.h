/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006 Free Software Foundation
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

#ifndef GNUTLS_STATE_H
# define GNUTLS_STATE_H

#include <gnutls_int.h>

void _gnutls_session_cert_type_set (gnutls_session_t session,
				    gnutls_certificate_type_t);
gnutls_kx_algorithm_t gnutls_kx_get (gnutls_session_t session);
gnutls_cipher_algorithm_t gnutls_cipher_get (gnutls_session_t session);
gnutls_certificate_type_t gnutls_certificate_type_get (gnutls_session_t);

#include <gnutls_auth_int.h>

#define CHECK_AUTH(auth, ret) if (gnutls_auth_get_type(session) != auth) { \
	gnutls_assert(); \
	return ret; \
	}

#endif

int _gnutls_session_cert_type_supported (gnutls_session_t,
					 gnutls_certificate_type_t);

int _gnutls_dh_set_secret_bits (gnutls_session_t session, unsigned bits);

int _gnutls_dh_set_peer_public (gnutls_session_t session, mpi_t public);
int _gnutls_dh_set_group (gnutls_session_t session, mpi_t gen, mpi_t prime);

int _gnutls_dh_get_allowed_prime_bits (gnutls_session_t session);
void _gnutls_handshake_internal_state_clear (gnutls_session_t);

int _gnutls_rsa_export_set_pubkey (gnutls_session_t session,
				   mpi_t exponent, mpi_t modulus);

int _gnutls_session_is_resumable (gnutls_session_t session);
int _gnutls_session_is_export (gnutls_session_t session);

int _gnutls_openpgp_send_fingerprint (gnutls_session_t session);

int _gnutls_PRF (gnutls_session_t session,
		 const opaque * secret, int secret_size,
		 const char *label, int label_size,
		 const opaque * seed, int seed_size,
		 int total_bytes, void *ret);

int gnutls_init (gnutls_session_t * session, gnutls_connection_end_t con_end);

#define DEFAULT_CERT_TYPE GNUTLS_CRT_X509
