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

const void *_gnutls_get_cred (gnutls_key_st key,
			      gnutls_credentials_type_t kx, int *err);
const void *_gnutls_get_kx_cred (gnutls_session_t session,
				 gnutls_kx_algorithm_t algo, int *err);
void *_gnutls_get_auth_info (gnutls_session_t session);
int _gnutls_auth_info_set (gnutls_session_t session,
			   gnutls_credentials_type_t type, int size,
			   int allow_change);
