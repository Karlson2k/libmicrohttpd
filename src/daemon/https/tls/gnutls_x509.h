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

#include <libtasn1.h>

int _gnutls_x509_cert_verify_peers (gnutls_session_t session,
				    unsigned int *status);

#define PEM_CERT_SEP2 "-----BEGIN X509 CERTIFICATE"
#define PEM_CERT_SEP "-----BEGIN CERTIFICATE"
#define PEM_PKCS7_SEP "-----BEGIN PKCS7"

#define PEM_CRL_SEP "-----BEGIN X509 CRL"

#define PEM_KEY_RSA_SEP "-----BEGIN RSA"
#define PEM_KEY_DSA_SEP "-----BEGIN DSA"

int _gnutls_check_key_usage (const gnutls_cert * cert,
			     gnutls_kx_algorithm_t alg);

int _gnutls_x509_read_rsa_params (opaque * der, int dersize, mpi_t * params);
int _gnutls_x509_read_dsa_pubkey (opaque * der, int dersize, mpi_t * params);

int _gnutls_x509_raw_privkey_to_gkey (gnutls_privkey * privkey,
				      const gnutls_datum_t * raw_key,
				      gnutls_x509_crt_fmt_t type);
int _gnutls_x509_privkey_to_gkey (gnutls_privkey * privkey,
				  gnutls_x509_privkey_t);
