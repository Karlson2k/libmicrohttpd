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

int _gnutls_x509_sign (const gnutls_datum_t * tbs,
		       gnutls_digest_algorithm_t hash,
		       gnutls_x509_privkey_t signer,
		       gnutls_datum_t * signature);
int _gnutls_x509_sign_tbs (ASN1_TYPE cert, const char *tbs_name,
			   gnutls_digest_algorithm_t hash,
			   gnutls_x509_privkey_t signer,
			   gnutls_datum_t * signature);
int _gnutls_x509_pkix_sign (ASN1_TYPE src, const char *src_name,
			    gnutls_digest_algorithm_t,
			    gnutls_x509_crt_t issuer,
			    gnutls_x509_privkey_t issuer_key);
