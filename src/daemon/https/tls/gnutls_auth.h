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

#ifndef GNUTLS_AUTH_H
# define GNUTLS_AUTH_H

typedef struct mod_auth_st_int
{
  const char *name;		/* null terminated */
  int (*gnutls_generate_server_certificate) (gnutls_session_t, opaque **);
  int (*gnutls_generate_client_certificate) (gnutls_session_t, opaque **);
  int (*gnutls_generate_server_kx) (gnutls_session_t, opaque **);
  int (*gnutls_generate_client_kx) (gnutls_session_t, opaque **);	/* used in SRP */
  int (*gnutls_generate_client_cert_vrfy) (gnutls_session_t, opaque **);
  int (*gnutls_generate_server_certificate_request) (gnutls_session_t,
						     opaque **);

  int (*gnutls_process_server_certificate) (gnutls_session_t, opaque *,
					    size_t);
  int (*gnutls_process_client_certificate) (gnutls_session_t, opaque *,
					    size_t);
  int (*gnutls_process_server_kx) (gnutls_session_t, opaque *, size_t);
  int (*gnutls_process_client_kx) (gnutls_session_t, opaque *, size_t);
  int (*gnutls_process_client_cert_vrfy) (gnutls_session_t, opaque *, size_t);
  int (*gnutls_process_server_certificate_request) (gnutls_session_t,
						    opaque *, size_t);
} mod_auth_st;

#endif
