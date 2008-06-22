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

#ifndef GNUTLS_PK_H
# define GNUTLS_PK_H

int _gnutls_pkcs1_rsa_encrypt (gnutls_datum_t * ciphertext,
			       const gnutls_datum_t * plaintext,
			       mpi_t * params, unsigned params_len,
			       unsigned btype);
int _gnutls_dsa_sign (gnutls_datum_t * signature,
		      const gnutls_datum_t * plaintext, mpi_t * params,
		      unsigned params_len);
int _gnutls_pkcs1_rsa_decrypt (gnutls_datum_t * plaintext,
			       const gnutls_datum_t * ciphertext,
			       mpi_t * params, unsigned params_len,
			       unsigned btype);
int _gnutls_rsa_verify (const gnutls_datum_t * vdata,
			const gnutls_datum_t * ciphertext, mpi_t * params,
			int params_len, int btype);
int _gnutls_dsa_verify (const gnutls_datum_t * vdata,
			const gnutls_datum_t * sig_value, mpi_t * params,
			int params_len);

#endif /* GNUTLS_PK_H */
