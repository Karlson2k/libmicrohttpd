/*
 * Copyright (C) 2001, 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS-EXTRA.
 *
 * GNUTLS-EXTRA is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *               
 * GNUTLS-EXTRA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *                               
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_extensions.h>
#include <gnutls_openpgp.h>
#include <gnutls_extra.h>
#include <gnutls_extra_hooks.h>
#include <gnutls_algorithms.h>

/* the number of the compression algorithms available in the compression
 * structure.
 */
extern int _gnutls_comp_algorithms_size;

/* Functions in gnutls that have not been initialized.
 */

static int _gnutls_init_extra = 0;

/**
 * gnutls_global_init_extra - This function initializes the global state of gnutls-extra 
 *
 * This function initializes the global state of gnutls-extra library
 * to defaults.  Returns zero on success.
 *
 * Note that gnutls_global_init() has to be called before this
 * function.  If this function is not called then the gnutls-extra
 * library will not be usable.
 *
 **/
int
gnutls_global_init_extra (void)
{
  int ret;

  /* If the version of libgnutls != version of
   * libextra, then do not initialize the library.
   * This is because it may break things.
   */
  if (strcmp (gnutls_check_version (NULL), VERSION) != 0)
    {
      return GNUTLS_E_LIBRARY_VERSION_MISMATCH;
    }

  _gnutls_init_extra++;

  if (_gnutls_init_extra != 1)
    {
      return 0;
    }

  /* Register the openpgp functions. This is because some
   * of them are defined to be NULL in the main library.
   */
  _gnutls_add_openpgp_functions (_gnutls_openpgp_verify_key,
                                 _gnutls_openpgp_get_raw_key_creation_time,
                                 _gnutls_openpgp_get_raw_key_expiration_time,
                                 _gnutls_openpgp_fingerprint,
                                 _gnutls_openpgp_request_key,
                                 _gnutls_openpgp_raw_key_to_gcert,
                                 _gnutls_openpgp_raw_privkey_to_gkey,
                                 _gnutls_openpgp_crt_to_gcert,
                                 _gnutls_openpgp_privkey_to_gkey,
                                 gnutls_openpgp_crt_deinit,
                                 gnutls_openpgp_keyring_deinit,
                                 gnutls_openpgp_privkey_deinit);

  return 0;
}

#include <strverscmp.h>

/**
 * gnutls_extra_check_version - This function checks the library's version
 * @req_version: the version to check
 *
 * Check that the version of the gnutls-extra library is at minimum
 * the requested one and return the version string; return NULL if the
 * condition is not satisfied.  If a NULL is passed to this function,
 * no check is done, but the version string is simply returned.
 *
 **/
const char *
gnutls_extra_check_version (const char *req_version)
{
  if (!req_version || strverscmp (req_version, VERSION) <= 0)
    return VERSION;

  return NULL;
}
