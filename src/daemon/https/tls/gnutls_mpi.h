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

#ifndef GNUTLS_MPI_H
#define GNUTLS_MPI_H

# include <gnutls_int.h>
# include <gcrypt.h>
# include <libtasn1.h>
/* lgl */
# include "gc.h"

typedef gcry_mpi_t mpi_t;

#define _gnutls_mpi_cmp gcry_mpi_cmp
#define _gnutls_mpi_cmp_ui gcry_mpi_cmp_ui
#define _gnutls_mpi_mod gcry_mpi_mod
#define _gnutls_mpi_new gcry_mpi_new
#define _gnutls_mpi_snew gcry_mpi_snew
#define _gnutls_mpi_copy gcry_mpi_copy
#define _gnutls_mpi_set_ui gcry_mpi_set_ui
#define _gnutls_mpi_set gcry_mpi_set
#define _gnutls_mpi_randomize gcry_mpi_randomize
#define _gnutls_mpi_get_nbits gcry_mpi_get_nbits
#define _gnutls_mpi_powm gcry_mpi_powm
#define _gnutls_mpi_invm gcry_mpi_invm
#define _gnutls_mpi_addm gcry_mpi_addm
#define _gnutls_mpi_subm gcry_mpi_subm
#define _gnutls_mpi_sub_ui gcry_mpi_sub_ui
#define _gnutls_mpi_mulm gcry_mpi_mulm
#define _gnutls_mpi_mul gcry_mpi_mul
#define _gnutls_mpi_add gcry_mpi_add
#define _gnutls_mpi_add_ui gcry_mpi_add_ui
#define _gnutls_mpi_sub_ui gcry_mpi_sub_ui
#define _gnutls_mpi_mul_ui gcry_mpi_mul_ui
#define _gnutls_prime_check gcry_prime_check
#define _gnutls_mpi_div gcry_mpi_div

#define _gnutls_mpi_alloc_like(x) _gnutls_mpi_new(_gnutls_mpi_get_nbits(x))
#define _gnutls_mpi_salloc_like(x) _gnutls_mpi_snew(_gnutls_mpi_get_nbits(x))

void mhd_gtls_mpi_release (mpi_t * x);

int mhd_gtls_mpi_scan_nz (mpi_t * ret_mpi, const opaque * buffer,
			 size_t * nbytes);
int mhd_gtls_mpi_scan (mpi_t * ret_mpi, const opaque * buffer,
		      size_t * nbytes);
int mhd_gtls_mpi_scan_pgp (mpi_t * ret_mpi, const opaque * buffer,
			  size_t * nbytes);

int mhd_gtls_mpi_print (void *buffer, size_t * nbytes, const mpi_t a);
int mhd_gtls_mpi_print_lz (void *buffer, size_t * nbytes, const mpi_t a);

int mhd_gtls_mpi_dprint_lz (gnutls_datum_t * dest, const mpi_t a);
int mhd_gtls_mpi_dprint (gnutls_datum_t * dest, const mpi_t a);

#endif
