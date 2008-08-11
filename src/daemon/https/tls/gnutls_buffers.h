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

int mhd_gnutls_record_buffer_put (content_type_t type,
			       mhd_gtls_session_t session, opaque * data,
			       size_t length);
int mhd_gnutls_record_buffer_get_size (content_type_t type,
				    mhd_gtls_session_t session);
int mhd_gtls_record_buffer_get (content_type_t type,
			       mhd_gtls_session_t session, opaque * data,
			       size_t length);
ssize_t mhd_gtls_io_read_buffered (mhd_gtls_session_t, opaque ** iptr,
				  size_t n, content_type_t);
void mhd_gtls_io_clear_read_buffer (mhd_gtls_session_t);
int mhd_gtls_io_clear_peeked_data (mhd_gtls_session_t session);

ssize_t mhd_gtls_io_write_buffered (mhd_gtls_session_t, const void *iptr,
				   size_t n);
ssize_t mhd_gtls_io_write_buffered2 (mhd_gtls_session_t, const void *iptr,
				    size_t n, const void *iptr2, size_t n2);

int mhd_gtls_handshake_buffer_get_size (mhd_gtls_session_t session);
int mhd_gtls_handshake_buffer_peek (mhd_gtls_session_t session, opaque * data,
				   size_t length);
int mhd_gtls_handshake_buffer_put (mhd_gtls_session_t session, opaque * data,
				  size_t length);
int mhd_gtls_handshake_buffer_clear (mhd_gtls_session_t session);
int mhd_gtls_handshake_buffer_empty (mhd_gtls_session_t session);
int mhd_gtls_handshake_buffer_get_ptr (mhd_gtls_session_t session,
				      opaque ** data_ptr, size_t * length);

#define _gnutls_handshake_io_buffer_clear( session) \
        mhd_gtls_buffer_clear( &session->internals.handshake_send_buffer); \
        mhd_gtls_buffer_clear( &session->internals.handshake_recv_buffer); \
        session->internals.handshake_send_buffer_prev_size = 0

ssize_t mhd_gtls_handshake_io_recv_int (mhd_gtls_session_t, content_type_t,
				       gnutls_handshake_description_t, void *,
				       size_t);
ssize_t mhd_gtls_handshake_io_send_int (mhd_gtls_session_t, content_type_t,
				       gnutls_handshake_description_t,
				       const void *, size_t);
ssize_t mhd_gtls_io_write_flush (mhd_gtls_session_t session);
ssize_t mhd_gtls_handshake_io_write_flush (mhd_gtls_session_t session);

size_t MHD_gtls_record_check_pending (mhd_gtls_session_t session);
