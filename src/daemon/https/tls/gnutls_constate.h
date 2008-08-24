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

int mhd_gtls_connection_state_init (mhd_gtls_session_t session);
int mhd_gtls_read_connection_state_init (mhd_gtls_session_t session);
int mhd_gtls_write_connection_state_init (mhd_gtls_session_t session);
int mhd_gtls_set_write_cipher (mhd_gtls_session_t session,
                               enum MHD_GNUTLS_CipherAlgorithm algo);
int mhd_gtls_set_write_mac (mhd_gtls_session_t session,
                            enum MHD_GNUTLS_HashAlgorithm algo);
int mhd_gtls_set_read_cipher (mhd_gtls_session_t session,
                              enum MHD_GNUTLS_CipherAlgorithm algo);
int mhd_gtls_set_read_mac (mhd_gtls_session_t session,
                           enum MHD_GNUTLS_HashAlgorithm algo);
int mhd_gtls_set_read_compression (mhd_gtls_session_t session,
                                   enum MHD_GNUTLS_CompressionMethod algo);
int mhd_gtls_set_write_compression (mhd_gtls_session_t session,
                                    enum MHD_GNUTLS_CompressionMethod algo);
int mhd_gtls_set_kx (mhd_gtls_session_t session,
                     enum MHD_GNUTLS_KeyExchangeAlgorithm algo);
