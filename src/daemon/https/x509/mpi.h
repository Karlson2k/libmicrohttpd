/*
 * Copyright (C) 2003, 2004, 2005 Free Software Foundation
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
#include "x509.h"

int _gnutls_x509_crt_get_mpis (gnutls_x509_crt_t cert,
			       mpi_t * params, int *params_size);
int _gnutls_x509_read_rsa_params (opaque * der, int dersize, mpi_t * params);
int _gnutls_x509_read_dsa_pubkey (opaque * der, int dersize, mpi_t * params);
int _gnutls_x509_read_dsa_params (opaque * der, int dersize, mpi_t * params);

int _gnutls_x509_write_rsa_params (mpi_t * params, int params_size,
				   gnutls_datum_t * der);
int _gnutls_x509_write_dsa_params (mpi_t * params, int params_size,
				   gnutls_datum_t * der);
int _gnutls_x509_write_dsa_public_key (mpi_t * params, int params_size,
				       gnutls_datum_t * der);

int _gnutls_x509_read_uint (ASN1_TYPE node, const char *value,
			    unsigned int *ret);

int  
_gnutls_x509_read_der_int  (opaque * der, int dersize, mpi_t* out);

int _gnutls_x509_read_int (ASN1_TYPE node, const char *value,
			   mpi_t * ret_mpi);
int _gnutls_x509_write_int (ASN1_TYPE node, const char *value, mpi_t mpi,
			    int lz);
int _gnutls_x509_write_uint32 (ASN1_TYPE node, const char *value,
			       uint32_t num);

int _gnutls_x509_write_sig_params (ASN1_TYPE dst, const char *dst_name,
				   gnutls_pk_algorithm_t pk_algorithm,
				   gnutls_digest_algorithm_t, mpi_t * params,
				   int params_size);
