/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2007 Free Software Foundation
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

#include <gnutls_int.h>

const char *_gnutls_extension_get_name (uint16_t type);
int _gnutls_parse_extensions (gnutls_session_t, tls_ext_parse_type_t, const opaque *, int);
int _gnutls_gen_extensions (gnutls_session_t session, opaque * data,
			    size_t data_size);

typedef int (*ext_recv_func) (gnutls_session_t, const opaque *, size_t);	/* recv data */
typedef int (*ext_send_func) (gnutls_session_t, opaque *, size_t);	/* send data */

ext_send_func _gnutls_ext_func_send (uint16_t type);
ext_recv_func _gnutls_ext_func_recv (uint16_t type, tls_ext_parse_type_t);

typedef struct
{
  const char *name;
  uint16_t type;
  tls_ext_parse_type_t parse_type;
  ext_recv_func gnutls_ext_func_recv;
  ext_send_func gnutls_ext_func_send;
} gnutls_extension_entry;
