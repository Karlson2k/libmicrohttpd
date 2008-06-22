/*
 * Copyright (C) 2007 Free Software Foundation
 *
 * Author: Simon Josefsson
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

/* This file is included by libgnutls-extra, and it will call the
   _gnutls_add_openpgp_functions() function to register its OpenPGP
   functions. */

#include <auth_cert.h>

typedef int (*_gnutls_openpgp_verify_key_func)
(const gnutls_certificate_credentials_t,
 const gnutls_datum_t *, int,
 unsigned int *);

typedef time_t (*_gnutls_openpgp_crt_creation_time_func)
(const gnutls_datum_t *);

typedef time_t (*_gnutls_openpgp_crt_expiration_time_func)
(const gnutls_datum_t *);

typedef int (*_gnutls_openpgp_crt_request_func)
(gnutls_session_t, gnutls_datum_t *,
 const gnutls_certificate_credentials_t,
 opaque *, int);

typedef int (*_gnutls_openpgp_fingerprint_func)
(const gnutls_datum_t *,
 unsigned char *, size_t *);

typedef int (*_gnutls_openpgp_raw_key_to_gcert_func)
(gnutls_cert *,
 const gnutls_datum_t *);
typedef int (*_gnutls_openpgp_raw_privkey_to_gkey_func)
(gnutls_privkey *,
 const gnutls_datum_t *,
 gnutls_openpgp_crt_fmt_t);

typedef int (*_gnutls_openpgp_crt_to_gcert_func)
(gnutls_cert *, gnutls_openpgp_crt_t);

typedef int (*_gnutls_openpgp_privkey_to_gkey_func)
(gnutls_privkey *,
 gnutls_openpgp_privkey_t);

typedef void (*_gnutls_openpgp_crt_deinit_func)
(gnutls_openpgp_crt_t);

typedef void (*_gnutls_openpgp_keyring_deinit_func)
(gnutls_openpgp_keyring_t);

typedef void (*_gnutls_openpgp_privkey_deinit_func)
(gnutls_openpgp_privkey_t);

/* These are defined in libgnutls, but not exported from libgnutls,
   and not intended to be used by libgnutls-extra or elsewhere.  They
   are declared here, because this file is included by auth_cert.c and
   gnutls_cert.c too.  */
extern _gnutls_openpgp_verify_key_func _E_gnutls_openpgp_verify_key;
extern _gnutls_openpgp_crt_creation_time_func
_E_gnutls_openpgp_get_raw_key_creation_time;
extern _gnutls_openpgp_crt_expiration_time_func
_E_gnutls_openpgp_get_raw_key_expiration_time;
extern _gnutls_openpgp_fingerprint_func _E_gnutls_openpgp_fingerprint;
extern _gnutls_openpgp_crt_request_func _E_gnutls_openpgp_request_key;
extern _gnutls_openpgp_raw_key_to_gcert_func _E_gnutls_openpgp_raw_key_to_gcert;
extern _gnutls_openpgp_raw_privkey_to_gkey_func _E_gnutls_openpgp_raw_privkey_to_gkey;
extern _gnutls_openpgp_crt_to_gcert_func _E_gnutls_openpgp_crt_to_gcert;
extern _gnutls_openpgp_privkey_to_gkey_func _E_gnutls_openpgp_privkey_to_gkey;
extern _gnutls_openpgp_crt_deinit_func _E_gnutls_openpgp_crt_deinit;
extern _gnutls_openpgp_keyring_deinit_func _E_gnutls_openpgp_keyring_deinit;
extern _gnutls_openpgp_privkey_deinit_func _E_gnutls_openpgp_privkey_deinit;

extern void _gnutls_add_openpgp_functions
(_gnutls_openpgp_verify_key_func verify_key,
 _gnutls_openpgp_crt_creation_time_func key_creation_time,
 _gnutls_openpgp_crt_expiration_time_func key_expiration_time,
 _gnutls_openpgp_fingerprint_func fingerprint,
 _gnutls_openpgp_crt_request_func request_key,
 _gnutls_openpgp_raw_key_to_gcert_func raw_key_to_gcert,
 _gnutls_openpgp_raw_privkey_to_gkey_func raw_privkey_to_gkey,
 _gnutls_openpgp_crt_to_gcert_func key_to_gcert,
 _gnutls_openpgp_privkey_to_gkey_func privkey_to_gkey,
 _gnutls_openpgp_crt_deinit_func key_deinit,
 _gnutls_openpgp_keyring_deinit_func keyring_deinit,
 _gnutls_openpgp_privkey_deinit_func privkey_deinit);
