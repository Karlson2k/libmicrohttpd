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

#ifndef GNUTLS_STR_H
#define GNUTLS_STR_H

#include <gnutls_int.h>

void mhd_gtls_str_cpy (char *dest, size_t dest_tot_size, const char *src);
void mhd_gtls_mem_cpy (char *dest, size_t dest_tot_size, const char *src,
		      size_t src_size);
void mhd_gtls_str_cat (char *dest, size_t dest_tot_size, const char *src);

typedef struct
{
  opaque * data;
  size_t max_length;
  size_t length;
  gnutls_realloc_function realloc_func;
  gnutls_alloc_function alloc_func;
  gnutls_free_function free_func;
} mhd_gtls_string;

void mhd_gtls_string_init (mhd_gtls_string *, gnutls_alloc_function,
			  gnutls_realloc_function, gnutls_free_function);
void mhd_gtls_string_clear (mhd_gtls_string *);

/* Beware, do not clear the string, after calling this
 * function
 */
gnutls_datum_t mhd_gtls_string2datum (mhd_gtls_string * str);

int mhd_gtls_string_copy_str (mhd_gtls_string * dest, const char *src);
int mhd_gtls_string_append_str (mhd_gtls_string *, const char *str);
int mhd_gtls_string_append_data (mhd_gtls_string *, const void *data,
				size_t data_size);
int mhd_gtls_string_append_printf (mhd_gtls_string * dest, const char *fmt, ...);

char * mhd_gtls_bin2hex (const void *old, size_t oldlen, char *buffer,
		       size_t buffer_size);
int mhd_gtls_hex2bin (const opaque * hex_data, int hex_size, opaque * bin_data,
		     size_t * bin_size);

#endif
