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

typedef enum Optional
{ OPTIONAL_PACKET, MANDATORY_PACKET } Optional;

int mhd_gtls_send_handshake (mhd_gtls_session_t session, void *i_data,
			    uint32_t i_datasize,
			    gnutls_handshake_description_t type);
int mhd_gtls_recv_hello_request (mhd_gtls_session_t session, void *data,
				uint32_t data_size);
int mhd_gtls_send_hello (mhd_gtls_session_t session, int again);
int mhd_gtls_recv_hello (mhd_gtls_session_t session, opaque * data, int datalen);
int mhd_gtls_recv_handshake (mhd_gtls_session_t session, uint8_t **, int *,
			    gnutls_handshake_description_t,
			    Optional optional);
int mhd_gtls_generate_session_id (opaque * session_id, uint8_t * len);
int mhd_gtls_handshake_common (mhd_gtls_session_t session);
int mhd_gtls_handshake_server (mhd_gtls_session_t session);
void mhd_gtls_set_server_random (mhd_gtls_session_t session, uint8_t * rnd);
void mhd_gtls_set_client_random (mhd_gtls_session_t session, uint8_t * rnd);
int mhd_gtls_tls_create_random (opaque * dst);
int mhd_gtls_remove_unwanted_ciphersuites (mhd_gtls_session_t session,
					  cipher_suite_st ** cipherSuites,
					  int numCipherSuites,
					  gnutls_pk_algorithm_t);
int mhd_gtls_find_pk_algos_in_ciphersuites (opaque * data, int datalen);
int mhd_gtls_server_select_suite (mhd_gtls_session_t session, opaque * data,
				 int datalen);

int mhd_gtls_negotiate_version( mhd_gtls_session_t session, gnutls_protocol_t adv_version);
int mhd_gtls_user_hello_func( mhd_gtls_session_t, gnutls_protocol_t adv_version);

#if MHD_DEBUG_TLS
int mhd_gtls_handshake_client (mhd_gtls_session_t session);
#endif

#define STATE session->internals.handshake_state
/* This returns true if we have got there
 * before (and not finished due to an interrupt).
 */
#define AGAIN(target) STATE==target?1:0
