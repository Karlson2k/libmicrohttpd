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

#ifndef GNUTLS_COMP_INT
# define GNUTLS_COMP_INT

#ifdef HAVE_LIBZ
# include <zlib.h>
#endif

#define GNUTLS_COMP_FAILED NULL

typedef struct comp_hd_t_STRUCT
{
  void *handle;
  gnutls_compression_method_t algo;
} *comp_hd_t;

comp_hd_t _gnutls_comp_init (gnutls_compression_method_t, int d);
void _gnutls_comp_deinit (comp_hd_t handle, int d);

int _gnutls_decompress (comp_hd_t handle, opaque * compressed,
			size_t compressed_size, opaque ** plain,
			size_t max_record_size);
int _gnutls_compress (comp_hd_t, const opaque * plain, size_t plain_size,
		      opaque ** compressed, size_t max_comp_size);

#endif
