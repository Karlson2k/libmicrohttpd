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

#include "x509.h"

int gnutls_x509_crt_is_issuer (gnutls_x509_crt_t cert,
			       gnutls_x509_crt_t issuer);
int _gnutls_x509_verify_signature (const gnutls_datum_t * tbs,
				   const gnutls_datum_t * signature,
				   gnutls_x509_crt_t issuer);
int _gnutls_x509_privkey_verify_signature (const gnutls_datum_t * tbs,
					   const gnutls_datum_t * signature,
					   gnutls_x509_privkey_t issuer);
