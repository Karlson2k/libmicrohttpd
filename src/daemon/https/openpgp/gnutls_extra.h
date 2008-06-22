/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS-EXTRA.
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUTLS-EXTRA; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include <auth_cert.h>

typedef int (*OPENPGP_VERIFY_KEY_FUNC) (const
					gnutls_certificate_credentials_t,
					const gnutls_datum_t *, int,
					unsigned int *);

typedef time_t (*OPENPGP_KEY_CREATION_TIME_FUNC) (const gnutls_datum_t *);
typedef time_t (*OPENPGP_KEY_EXPIRATION_TIME_FUNC) (const gnutls_datum_t *);
typedef int (*OPENPGP_KEY_REQUEST) (gnutls_session_t, gnutls_datum_t *,
				    const gnutls_certificate_credentials_t,
				    opaque *, int);

typedef int (*OPENPGP_FINGERPRINT) (const gnutls_datum_t *,
				    unsigned char *, size_t *);

typedef int (*OPENPGP_RAW_KEY_TO_GCERT) (gnutls_cert *,
					 const gnutls_datum_t *);
typedef int (*OPENPGP_RAW_PRIVKEY_TO_GKEY) (gnutls_privkey *,
					    const gnutls_datum_t *);

typedef int (*OPENPGP_KEY_TO_GCERT) (gnutls_cert *, gnutls_openpgp_crt_t);
typedef int (*OPENPGP_PRIVKEY_TO_GKEY) (gnutls_privkey *,
					gnutls_openpgp_privkey_t);
typedef void (*OPENPGP_KEY_DEINIT) (gnutls_openpgp_crt_t);
typedef void (*OPENPGP_PRIVKEY_DEINIT) (gnutls_openpgp_privkey_t);
