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

#include <gnutls_int.h>
#include <gnutls_extra_hooks.h>

/* Variables used by libgnutls, set by
   _gnutls_add_openpgp_functions(), typically invoked by
   libgnutls_extra. */
_gnutls_openpgp_verify_key_func _E_gnutls_openpgp_verify_key = NULL;
_gnutls_openpgp_crt_creation_time_func
  _E_gnutls_openpgp_get_raw_key_creation_time = NULL;
_gnutls_openpgp_crt_expiration_time_func
  _E_gnutls_openpgp_get_raw_key_expiration_time = NULL;
_gnutls_openpgp_fingerprint_func _E_gnutls_openpgp_fingerprint = NULL;
_gnutls_openpgp_crt_request_func _E_gnutls_openpgp_request_key = NULL;
_gnutls_openpgp_raw_key_to_gcert_func _E_gnutls_openpgp_raw_key_to_gcert =
  NULL;
_gnutls_openpgp_raw_privkey_to_gkey_func _E_gnutls_openpgp_raw_privkey_to_gkey
  = NULL;
_gnutls_openpgp_crt_to_gcert_func _E_gnutls_openpgp_crt_to_gcert = NULL;
_gnutls_openpgp_privkey_to_gkey_func _E_gnutls_openpgp_privkey_to_gkey = NULL;
_gnutls_openpgp_crt_deinit_func _E_gnutls_openpgp_crt_deinit = NULL;
_gnutls_openpgp_keyring_deinit_func _E_gnutls_openpgp_keyring_deinit = NULL;
_gnutls_openpgp_privkey_deinit_func _E_gnutls_openpgp_privkey_deinit = NULL;

/* Called by libgnutls_extra to set the OpenPGP functions that are
   needed by GnuTLS.  */
extern void
  _gnutls_add_openpgp_functions
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
   _gnutls_openpgp_privkey_deinit_func privkey_deinit)
{
  _E_gnutls_openpgp_verify_key = verify_key;
  _E_gnutls_openpgp_get_raw_key_creation_time = key_creation_time;
  _E_gnutls_openpgp_get_raw_key_expiration_time = key_expiration_time;
  _E_gnutls_openpgp_fingerprint = fingerprint;
  _E_gnutls_openpgp_request_key = request_key;
  _E_gnutls_openpgp_raw_key_to_gcert = raw_key_to_gcert;
  _E_gnutls_openpgp_raw_privkey_to_gkey = raw_privkey_to_gkey;
  _E_gnutls_openpgp_crt_to_gcert = key_to_gcert;
  _E_gnutls_openpgp_privkey_to_gkey = privkey_to_gkey;
  _E_gnutls_openpgp_crt_deinit = key_deinit;
  _E_gnutls_openpgp_keyring_deinit = keyring_deinit;
  _E_gnutls_openpgp_privkey_deinit = privkey_deinit;

}
