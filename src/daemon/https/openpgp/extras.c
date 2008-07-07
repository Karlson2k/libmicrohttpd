/*
 * Copyright (C) 2003, 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos, Timo Schulz
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

/* Functions on OpenPGP keyring parsing
 */

#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <gnutls_openpgp.h>
#include <gnutls_num.h>
#include "openpgp.h"

/* Keyring stuff. */

/**
 * gnutls_openpgp_keyring_init - This function initializes a gnutls_openpgp_keyring_t structure
 * @keyring: The structure to be initialized
 *-
 * This function will initialize an OpenPGP keyring structure. 
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_openpgp_keyring_init (gnutls_openpgp_keyring_t * keyring)
{
  *keyring = gnutls_calloc (1, sizeof (gnutls_openpgp_keyring_int));

  if (*keyring)
    return 0;                   /* success */
  return GNUTLS_E_MEMORY_ERROR;
}

/**
 * gnutls_openpgp_keyring_deinit - This function deinitializes memory used by a gnutls_openpgp_keyring_t structure
 * @keyring: The structure to be initialized
 *
 * This function will deinitialize a keyring structure. 
 *
 **/
void
gnutls_openpgp_keyring_deinit (gnutls_openpgp_keyring_t keyring)
{
  if (!keyring)
    return;

  if (keyring->db)
    {
      cdk_keydb_free (keyring->db);
      keyring->db = NULL;
    }

  /* In some cases the stream is also stored outside the keydb context
     and we need to close it here then. */
  if (keyring->db_stream)
    {
      cdk_stream_close (keyring->db_stream);
      keyring->db_stream = NULL;
    }

  gnutls_free (keyring);
}

/**
 * gnutls_openpgp_keyring_check_id - Check if a key id exists in the keyring
 * @ring: holds the keyring to check against
 * @keyid: will hold the keyid to check for.
 * @flags: unused (should be 0)
 *
 * Check if a given key ID exists in the keyring.
 *
 * Returns 0 on success (if keyid exists) and a negative error code
 * on failure.
 **/
int
gnutls_openpgp_keyring_check_id (gnutls_openpgp_keyring_t ring,
                                 const unsigned char keyid[8],
                                 unsigned int flags)
{
  cdk_pkt_pubkey_t pk;
  uint32_t id[2];

  id[0] = _gnutls_read_uint32 (keyid);
  id[1] = _gnutls_read_uint32 (&keyid[4]);

  if (!cdk_keydb_get_pk (ring->db, id, &pk))
    {
      cdk_pk_release (pk);
      return 0;
    }

  _gnutls_debug_log ("PGP: key not found %08lX\n", (unsigned long) id[1]);
  return GNUTLS_E_NO_CERTIFICATE_FOUND;
}

/**
 * gnutls_openpgp_keyring_import - Import a raw- or Base64-encoded OpenPGP keyring
 * @keyring: The structure to store the parsed key.
 * @data: The RAW or BASE64 encoded keyring.
 * @format: One of #gnutls_openpgp_keyring_fmt elements.
 *
 * This function will convert the given RAW or Base64 encoded keyring to the
 * native #gnutls_openpgp_keyring_t format.  The output will be stored in
 * 'keyring'.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_openpgp_keyring_import (gnutls_openpgp_keyring_t keyring,
                               const gnutls_datum_t * data,
                               gnutls_openpgp_crt_fmt_t format)
{
  cdk_error_t err;
  cdk_stream_t input;

  _gnutls_debug_log ("PGP: keyring import format '%s'\n",
                     format == GNUTLS_OPENPGP_FMT_RAW ? "raw" : "base64");

  if (format == GNUTLS_OPENPGP_FMT_RAW)
    {
      err
        =
        cdk_keydb_new (&keyring->db, CDK_DBTYPE_DATA, data->data, data->size);
      if (err)
        gnutls_assert ();
      return _gnutls_map_cdk_rc (err);
    }

  /* Create a new stream from the given data, which means to
     allocate a new stream and to write the data in the stream.
     Then push the armor filter to decode the data and to store
     it in the raw format. */
  err = cdk_stream_tmp_from_mem (data->data, data->size, &input);
  if (!err)
    err = cdk_stream_set_armor_flag (input, 0);
  if (!err)
    err = cdk_keydb_new_from_stream (&keyring->db, 0, input);
  if (err)
    {
      cdk_stream_close (input);
      gnutls_assert ();
    }
  else
    /* The keydb function will not close the stream itself, so we need to
       store it separately to close it later. */
    keyring->db_stream = input;

  return _gnutls_map_cdk_rc (err);
}
