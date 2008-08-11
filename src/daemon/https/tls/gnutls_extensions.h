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

const char * mhd_gtls_extension_get_name (uint16_t type);
int mhd_gtls_parse_extensions (mhd_gtls_session_t, mhd_gtls_ext_parse_type_t, const opaque *, int);
int mhd_gtls_gen_extensions (mhd_gtls_session_t session, opaque * data,
			    size_t data_size);

typedef int (* mhd_gtls_ext_recv_func) (mhd_gtls_session_t, const opaque *, size_t);	/* recv data */
typedef int (* mhd_gtls_ext_send_func) (mhd_gtls_session_t, opaque *, size_t);	/* send data */

mhd_gtls_ext_send_func mhd_gtls_ext_func_send (uint16_t type);
mhd_gtls_ext_recv_func mhd_gtls_ext_func_recv (uint16_t type, mhd_gtls_ext_parse_type_t);

typedef struct
{
  const char *name;
  uint16_t type;
  mhd_gtls_ext_parse_type_t parse_type;
  mhd_gtls_ext_recv_func gnutls_ext_func_recv;
  mhd_gtls_ext_send_func gnutls_ext_func_send;
} mhd_gtls_extension_entry;
