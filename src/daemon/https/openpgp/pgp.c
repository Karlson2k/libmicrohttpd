/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Free Software Foundation
 *
 * Author: Timo Schulz, Nikos Mavrogiannopoulos
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

/* Functions on OpenPGP key parsing
 */

#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include "openpgp.h"
/* x509 */
#include <rfc2818.h>

/**
 * gnutls_openpgp_crt_init - This function initializes a gnutls_openpgp_crt_t structure
 * @key: The structure to be initialized
 *
 * This function will initialize an OpenPGP key structure. 
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_openpgp_crt_init (gnutls_openpgp_crt_t * key)
{
  *key = gnutls_calloc (1, sizeof (gnutls_openpgp_crt_int));

  if (*key)
    return 0;                   /* success */
  return GNUTLS_E_MEMORY_ERROR;
}

/**
 * gnutls_openpgp_crt_deinit - This function deinitializes memory used by a gnutls_openpgp_crt_t structure
 * @key: The structure to be initialized
 *
 * This function will deinitialize a key structure. 
 **/
void
gnutls_openpgp_crt_deinit (gnutls_openpgp_crt_t key)
{
  if (!key)
    return;

  if (key->knode)
    {
      cdk_kbnode_release (key->knode);
      key->knode = NULL;
    }

  gnutls_free (key);
}

/**
 * gnutls_openpgp_crt_import - This function will import a RAW or BASE64 encoded key
 * @key: The structure to store the parsed key.
 * @data: The RAW or BASE64 encoded key.
 * @format: One of gnutls_openpgp_crt_fmt_t elements.
 *
 * This function will convert the given RAW or Base64 encoded key
 * to the native gnutls_openpgp_crt_t format. The output will be stored in 'key'.
 *
 * Returns 0 on success.
 **/
int
gnutls_openpgp_crt_import (gnutls_openpgp_crt_t key,
                           const gnutls_datum_t * data,
                           gnutls_openpgp_crt_fmt_t format)
{
  cdk_stream_t inp;
  int rc;

  if (format == GNUTLS_OPENPGP_FMT_RAW)
    rc = cdk_kbnode_read_from_mem (&key->knode, data->data, data->size);
  else
    {
      rc = cdk_stream_tmp_from_mem (data->data, data->size, &inp);
      if (rc)
        {
          rc = _gnutls_map_cdk_rc (rc);
          gnutls_assert ();
          return rc;
        }
      if (cdk_armor_filter_use (inp))
        rc = cdk_stream_set_armor_flag (inp, 0);
      if (!rc)
        rc = cdk_keydb_get_keyblock (inp, &key->knode);
      cdk_stream_close (inp);
      if (rc)
        {
          rc = _gnutls_map_cdk_rc (rc);
          gnutls_assert ();
          return rc;
        }
    }

  return 0;
}

/**
 * gnutls_openpgp_crt_export - This function will export a RAW or BASE64 encoded key
 * @key: Holds the key.
 * @format: One of gnutls_openpgp_crt_fmt_t elements.
 * @output_data: will contain the key base64 encoded or raw
 * @output_data_size: holds the size of output_data (and will be replaced by the actual size of parameters)
 *
 * This function will convert the given key to RAW or Base64 format.
 * If the buffer provided is not long enough to hold the output, then
 * GNUTLS_E_SHORT_MEMORY_BUFFER will be returned.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_openpgp_crt_export (gnutls_openpgp_crt_t key,
                           gnutls_openpgp_crt_fmt_t format,
                           void *output_data, size_t * output_data_size)
{
  size_t input_data_size = *output_data_size;
  size_t calc_size;
  int rc;

  rc = cdk_kbnode_write_to_mem (key->knode, output_data, output_data_size);
  if (rc)
    {
      rc = _gnutls_map_cdk_rc (rc);
      gnutls_assert ();
      return rc;
    }

  /* FIXME: The first call of this function is with output_data == NULL
     to figure out the size and the caller expects this error here. */
  if (!output_data)
    return GNUTLS_E_SHORT_MEMORY_BUFFER;

  if (format == GNUTLS_OPENPGP_FMT_BASE64)
    {
      unsigned char *in = cdk_calloc (1, *output_data_size);
      memcpy (in, output_data, *output_data_size);

      /* Calculate the size of the encoded data and check if the provided
         buffer is large enough. */
      rc = cdk_armor_encode_buffer (in, input_data_size,
                                    NULL, 0, &calc_size, CDK_ARMOR_PUBKEY);
      if (rc || calc_size > input_data_size)
        {
          cdk_free (in);
          *output_data_size = calc_size;
          rc = _gnutls_map_cdk_rc (CDK_Too_Short);
          gnutls_assert ();
          return rc;
        }

      rc = cdk_armor_encode_buffer (in, input_data_size, output_data,
                                    input_data_size, &calc_size,
                                    CDK_ARMOR_PUBKEY);
      cdk_free (in);
      *output_data_size = calc_size;
    }

  return 0;
}

/**
 * gnutls_openpgp_crt_get_fingerprint - Gets the fingerprint
 * @key: the raw data that contains the OpenPGP public key.
 * @fpr: the buffer to save the fingerprint, must hold at least 20 bytes.
 * @fprlen: the integer to save the length of the fingerprint.
 *
 * Returns the fingerprint of the OpenPGP key. Depends on the algorithm,
 * the fingerprint can be 16 or 20 bytes.
 **/
int
gnutls_openpgp_crt_get_fingerprint (gnutls_openpgp_crt_t key,
                                    void *fpr, size_t * fprlen)
{
  cdk_packet_t pkt;
  cdk_pkt_pubkey_t pk = NULL;

  if (!fpr || !fprlen)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  *fprlen = 0;

  pkt = cdk_kbnode_find_packet (key->knode, CDK_PKT_PUBLIC_KEY);
  if (!pkt)
    return GNUTLS_E_OPENPGP_GETKEY_FAILED;

  pk = pkt->pkt.public_key;
  *fprlen = 20;

  /* FIXME: Check if the draft allows old PGP keys. */
  if (is_RSA (pk->pubkey_algo) && pk->version < 4)
    *fprlen = 16;
  cdk_pk_get_fingerprint (pk, fpr);

  return 0;
}

int
_gnutls_openpgp_count_key_names (gnutls_openpgp_crt_t key)
{
  cdk_kbnode_t p, ctx;
  cdk_packet_t pkt;
  int nuids;

  if (key == NULL)
    {
      gnutls_assert ();
      return 0;
    }

  ctx = NULL;
  nuids = 0;
  while ((p = cdk_kbnode_walk (key->knode, &ctx, 0)))
    {
      pkt = cdk_kbnode_get_packet (p);
      if (pkt->pkttype == CDK_PKT_USER_ID)
        nuids++;
    }

  return nuids;
}

/**
 * gnutls_openpgp_crt_get_name - Extracts the userID
 * @key: the structure that contains the OpenPGP public key.
 * @idx: the index of the ID to extract
 * @buf: a pointer to a structure to hold the name
 * @sizeof_buf: holds the maximum size of @buf, on return hold the
 *   actual/required size of @buf.
 *
 * Extracts the userID from the parsed OpenPGP key.
 *
 * Returns 0 on success, and GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the index of the ID does not exist.
 *
 **/
int
gnutls_openpgp_crt_get_name (gnutls_openpgp_crt_t key,
                             int idx, char *buf, size_t * sizeof_buf)
{
  cdk_kbnode_t ctx = NULL, p;
  cdk_packet_t pkt = NULL;
  cdk_pkt_userid_t uid = NULL;
  int pos = 0;

  if (!key || !buf)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (idx < 0 || idx > _gnutls_openpgp_count_key_names (key))
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

  if (!idx)
    pkt = cdk_kbnode_find_packet (key->knode, CDK_PKT_USER_ID);
  else
    {
      pos = 0;
      while ((p = cdk_kbnode_walk (key->knode, &ctx, 0)))
        {
          pkt = cdk_kbnode_get_packet (p);
          if (pkt->pkttype == CDK_PKT_USER_ID && ++pos == idx)
            break;
        }
    }

  if (!pkt)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  uid = pkt->pkt.user_id;
  if (uid->len >= *sizeof_buf)
    {
      gnutls_assert ();
      *sizeof_buf = uid->len + 1;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  memcpy (buf, uid->name, uid->len);
  buf[uid->len] = '\0';         /* make sure it's a string */
  *sizeof_buf = uid->len + 1;

  if (uid->is_revoked)
    return GNUTLS_E_OPENPGP_UID_REVOKED;

  return 0;
}

/**
 * gnutls_openpgp_crt_get_pk_algorithm - This function returns the key's PublicKey algorithm
 * @key: is an OpenPGP key
 * @bits: if bits is non null it will hold the size of the parameters' in bits
 *
 * This function will return the public key algorithm of an OpenPGP
 * certificate.
 *
 * If bits is non null, it should have enough size to hold the parameters
 * size in bits. For RSA the bits returned is the modulus. 
 * For DSA the bits returned are of the public exponent.
 *
 * Returns a member of the GNUTLS_PKAlgorithm enumeration on success,
 * or a negative value on error.
 *
 **/
gnutls_pk_algorithm_t
gnutls_openpgp_crt_get_pk_algorithm (gnutls_openpgp_crt_t key,
                                     unsigned int *bits)
{
  cdk_packet_t pkt;
  int algo;

  if (!key)
    return MHD_GNUTLS_PK_UNKNOWN;

  algo = 0;
  pkt = cdk_kbnode_find_packet (key->knode, CDK_PKT_PUBLIC_KEY);
  if (pkt && pkt->pkttype == CDK_PKT_PUBLIC_KEY)
    {
      if (bits)
        *bits = cdk_pk_get_nbits (pkt->pkt.public_key);
      algo = pkt->pkt.public_key->pubkey_algo;
      if (is_RSA (algo))
        algo = MHD_GNUTLS_PK_RSA;
      else
        algo = GNUTLS_E_UNKNOWN_PK_ALGORITHM;
    }

  return algo;
}

/**
 * gnutls_openpgp_crt_get_version - Extracts the version of the key.
 * @key: the structure that contains the OpenPGP public key.
 *
 * Extract the version of the OpenPGP key.
 **/
int
gnutls_openpgp_crt_get_version (gnutls_openpgp_crt_t key)
{
  cdk_packet_t pkt;
  int version;

  if (!key)
    return -1;

  pkt = cdk_kbnode_find_packet (key->knode, CDK_PKT_PUBLIC_KEY);
  if (pkt)
    version = pkt->pkt.public_key->version;
  else
    version = 0;

  return version;
}

/**
 * gnutls_openpgp_crt_get_creation_time - Extract the timestamp
 * @key: the structure that contains the OpenPGP public key.
 *
 * Returns the timestamp when the OpenPGP key was created.
 **/
time_t
gnutls_openpgp_crt_get_creation_time (gnutls_openpgp_crt_t key)
{
  cdk_packet_t pkt;
  time_t timestamp;

  if (!key)
    return (time_t) - 1;

  pkt = cdk_kbnode_find_packet (key->knode, CDK_PKT_PUBLIC_KEY);
  if (pkt)
    timestamp = pkt->pkt.public_key->timestamp;
  else
    timestamp = 0;

  return timestamp;
}

/**
 * gnutls_openpgp_crt_get_expiration_time - Extract the expire date
 * @key: the structure that contains the OpenPGP public key.
 *
 * Returns the time when the OpenPGP key expires. A value of '0' means
 * that the key doesn't expire at all.
 **/
time_t
gnutls_openpgp_crt_get_expiration_time (gnutls_openpgp_crt_t key)
{
  cdk_packet_t pkt;
  time_t expiredate;

  if (!key)
    return (time_t) - 1;

  pkt = cdk_kbnode_find_packet (key->knode, CDK_PKT_PUBLIC_KEY);
  if (pkt)
    expiredate = pkt->pkt.public_key->expiredate;
  else
    expiredate = 0;

  return expiredate;
}

/**
 * gnutls_openpgp_crt_get_id - Gets the keyID
 * @key: the structure that contains the OpenPGP public key.
 * @keyid: the buffer to save the keyid.
 *
 * Returns the 64-bit keyID of the OpenPGP key.
 **/
int
gnutls_openpgp_crt_get_id (gnutls_openpgp_crt_t key, unsigned char keyid[8])
{
  cdk_packet_t pkt;
  uint32_t kid[2];

  if (!key || !keyid)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  pkt = cdk_kbnode_find_packet (key->knode, CDK_PKT_PUBLIC_KEY);
  if (!pkt)
    return GNUTLS_E_OPENPGP_GETKEY_FAILED;

  cdk_pk_get_keyid (pkt->pkt.public_key, kid);
  keyid[0] = kid[0] >> 24;
  keyid[1] = kid[0] >> 16;
  keyid[2] = kid[0] >> 8;
  keyid[3] = kid[0];
  keyid[4] = kid[1] >> 24;
  keyid[5] = kid[1] >> 16;
  keyid[6] = kid[1] >> 8;
  keyid[7] = kid[1];

  return 0;
}

/**
 * gnutls_openpgp_crt_check_hostname - This function compares the given hostname with the hostname in the key
 * @key: should contain an gnutls_openpgp_crt_t structure
 * @hostname: A null terminated string that contains a DNS name
 *
 * This function will check if the given key's owner matches
 * the given hostname. This is a basic implementation of the matching 
 * described in RFC2818 (HTTPS), which takes into account wildcards.
 *
 * Returns non zero on success, and zero on failure.
 *
 **/
int
gnutls_openpgp_crt_check_hostname (gnutls_openpgp_crt_t key,
                                   const char *hostname)
{
  char dnsname[MAX_CN];
  size_t dnsnamesize;
  int ret;
  int i;

  /* Check through all included names. */
  for (i = 0; !(ret < 0); i++)
    {
      dnsnamesize = sizeof (dnsname);
      ret = gnutls_openpgp_crt_get_name (key, i, dnsname, &dnsnamesize);
      /* FIXME: ret is not used */
      if (_gnutls_hostname_compare (dnsname, hostname))
        return 1;
    }

  /* not found a matching name */
  return 0;
}

/**
 * gnutls_openpgp_crt_get_key_usage - This function returns the key's usage
 * @key: should contain a gnutls_openpgp_crt_t structure
 * @key_usage: where the key usage bits will be stored
 *
 * This function will return certificate's key usage, by checking the
 * key algorithm. The key usage value will ORed values of the:
 * GNUTLS_KEY_DIGITAL_SIGNATURE, GNUTLS_KEY_KEY_ENCIPHERMENT.
 *
 * A negative value may be returned in case of parsing error.
 *
 */
int
gnutls_openpgp_crt_get_key_usage (gnutls_openpgp_crt_t key,
                                  unsigned int *key_usage)
{
  cdk_packet_t pkt;
  int algo = 0;

  if (!key)
    return GNUTLS_E_INVALID_REQUEST;

  *key_usage = 0;

  pkt = cdk_kbnode_find_packet (key->knode, CDK_PKT_PUBLIC_KEY);
  if (pkt && pkt->pkttype == CDK_PKT_PUBLIC_KEY)
    {
      algo = pkt->pkt.public_key->pubkey_algo;

      /* FIXME: We need to take a look at the key flags because
         RSA-E and RSA-S are obsolete. Only RSA is used
         and the flags are used to set the capabilities. */
      if (is_DSA (algo) || algo == GCRY_PK_RSA_S)
        *key_usage |= KEY_DIGITAL_SIGNATURE;
      else if (algo == GCRY_PK_RSA_E)
        *key_usage |= KEY_KEY_ENCIPHERMENT;
      else if (algo == GCRY_PK_RSA)
        *key_usage |= KEY_DIGITAL_SIGNATURE | KEY_KEY_ENCIPHERMENT;
    }

  return 0;
}
