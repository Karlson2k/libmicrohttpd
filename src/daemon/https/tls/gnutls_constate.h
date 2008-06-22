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

int _gnutls_connection_state_init (gnutls_session_t session);
int _gnutls_read_connection_state_init (gnutls_session_t session);
int _gnutls_write_connection_state_init (gnutls_session_t session);
int _gnutls_set_write_cipher (gnutls_session_t session,
			      gnutls_cipher_algorithm_t algo);
int _gnutls_set_write_mac (gnutls_session_t session,
			   gnutls_mac_algorithm_t algo);
int _gnutls_set_read_cipher (gnutls_session_t session,
			     gnutls_cipher_algorithm_t algo);
int _gnutls_set_read_mac (gnutls_session_t session,
			  gnutls_mac_algorithm_t algo);
int _gnutls_set_read_compression (gnutls_session_t session,
				  gnutls_compression_method_t algo);
int _gnutls_set_write_compression (gnutls_session_t session,
				   gnutls_compression_method_t algo);
int _gnutls_set_kx (gnutls_session_t session, gnutls_kx_algorithm_t algo);
