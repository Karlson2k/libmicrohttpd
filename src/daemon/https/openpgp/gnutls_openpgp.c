/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
 *
 * Author: Timo Schulz
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

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_mpi.h"
#include "gnutls_cert.h"
#include "gnutls_datum.h"
#include "gnutls_global.h"
#include "gnutls_openpgp.h"
#include "read-file.h"
#include <gnutls_str.h>
#include <gnutls_sig.h>
#include <stdio.h>
#include <gcrypt.h>
#include <time.h>
#include <sys/stat.h>

#define OPENPGP_NAME_SIZE 256

#define datum_append(x, y, z) _gnutls_datum_append_m (x, y, z, gnutls_realloc)



static void
release_mpi_array (mpi_t * arr, size_t n)
{
  mpi_t x;

  while (arr && n--)
    {
      x = *arr;
      _gnutls_mpi_release (&x);
      *arr = NULL;
      arr++;
    }
}


/* Map an OpenCDK error type to a GnuTLS error type. */
int
_gnutls_map_cdk_rc (int rc)
{
  switch (rc)
    {
    case CDK_Success:
      return 0;
    case CDK_Too_Short:
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    case CDK_General_Error:
      return GNUTLS_E_INTERNAL_ERROR;
    case CDK_File_Error:
      return GNUTLS_E_FILE_ERROR;
    case CDK_MPI_Error:
      return GNUTLS_E_MPI_SCAN_FAILED;
    case CDK_Error_No_Key:
      return GNUTLS_E_OPENPGP_GETKEY_FAILED;
    case CDK_Armor_Error:
      return GNUTLS_E_BASE64_DECODING_ERROR;
    case CDK_Inv_Value:
      return GNUTLS_E_INVALID_REQUEST;
    default:
      return GNUTLS_E_INTERNAL_ERROR;
    }
}

static unsigned long
buftou32 (const uint8_t * buf)
{
  unsigned a;
  a = buf[0] << 24;
  a |= buf[1] << 16;
  a |= buf[2] << 8;
  a |= buf[3];
  return a;
}

static int
openpgp_pk_to_gnutls_cert (gnutls_cert * cert, cdk_pkt_pubkey_t pk)
{
  uint8_t buf[512 + 2];
  size_t nbytes;
  int algo, i;
  int rc = 0;

  if (!cert || !pk)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* GnuTLS OpenPGP does not support ELG keys */
  if (is_ELG (pk->pubkey_algo))
    {
      gnutls_assert ();
      return GNUTLS_E_UNWANTED_ALGORITHM;
    }

  algo = GNUTLS_PK_RSA;
  cert->subject_pk_algorithm = algo;
  cert->version = pk->version;
  cert->cert_type = GNUTLS_CRT_OPENPGP;

  cert->key_usage = 0;
  if (pk->pubkey_usage & CDK_KEY_USG_SIGN)
    cert->key_usage = KEY_DIGITAL_SIGNATURE;
  if (pk->pubkey_usage & CDK_KEY_USG_ENCR)
    cert->key_usage = KEY_KEY_ENCIPHERMENT;
  if (!cert->key_usage)         /* Fallback code. */
    {
      if (pk->pubkey_algo == GCRY_PK_DSA || pk->pubkey_algo == GCRY_PK_RSA_S)
        cert->key_usage = KEY_DIGITAL_SIGNATURE;
      else if (pk->pubkey_algo == GCRY_PK_RSA_E)
        cert->key_usage = KEY_KEY_ENCIPHERMENT;
      else if (pk->pubkey_algo == GCRY_PK_RSA)
        cert->key_usage = KEY_DIGITAL_SIGNATURE | KEY_KEY_ENCIPHERMENT;
    }

  cert->params_size = cdk_pk_get_npkey (pk->pubkey_algo);
  for (i = 0; i < cert->params_size; i++)
    {
      nbytes = sizeof (buf) / sizeof (buf[0]);
      cdk_pk_get_mpi (pk, i, buf, nbytes, &nbytes, NULL);
      rc = _gnutls_mpi_scan_pgp (&cert->params[i], buf, &nbytes);
      if (rc)
        {
          rc = GNUTLS_E_MPI_SCAN_FAILED;
          break;
        }
    }

  if (rc)
    release_mpi_array (cert->params, i - 1);
  return rc;
}

/*-
 * _gnutls_openpgp_raw_privkey_to_gkey - Converts an OpenPGP secret key to GnuTLS
 * @pkey: the GnuTLS private key context to store the key.
 * @raw_key: the raw data which contains the whole key packets.
 * @format: the format of the key packets.
 *
 * The RFC2440 (OpenPGP Message Format) data is converted into the
 * GnuTLS specific data which is need to perform secret key operations.
 *
 * This function can read both BASE64 and RAW keys.
 -*/
int
_gnutls_openpgp_raw_privkey_to_gkey (gnutls_privkey * pkey,
                                     const gnutls_datum_t * raw_key,
                                     gnutls_openpgp_crt_fmt_t format)
{
  cdk_kbnode_t snode = NULL;
  cdk_packet_t pkt;
  cdk_stream_t out;
  cdk_pkt_seckey_t sk = NULL;
  int pke_algo, i, j;
  size_t nbytes = 0;
  uint8_t buf[512];
  int rc = 0;

  if (!pkey || raw_key->size <= 0)
    {
      gnutls_assert ();
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  rc = cdk_stream_tmp_new (&out);
  if (rc)
    return GNUTLS_E_CERTIFICATE_ERROR;

  if (format == GNUTLS_OPENPGP_FMT_BASE64)
    {
      rc = cdk_stream_set_armor_flag (out, 0);
      if (rc)
        {
          cdk_stream_close (out);
          rc = _gnutls_map_cdk_rc (rc);
          gnutls_assert ();
          goto leave;
        }
    }

  cdk_stream_write (out, raw_key->data, raw_key->size);
  cdk_stream_seek (out, 0);

  rc = cdk_keydb_get_keyblock (out, &snode);
  cdk_stream_close (out);
  if (rc)
    {
      rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
      goto leave;
    }

  pkt = cdk_kbnode_find_packet (snode, CDK_PKT_SECRET_KEY);
  if (!pkt)
    {
      rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
      goto leave;
    }
  sk = pkt->pkt.secret_key;
  pke_algo = sk->pk->pubkey_algo;
  pkey->params_size = cdk_pk_get_npkey (pke_algo);
  for (i = 0; i < pkey->params_size; i++)
    {
      nbytes = sizeof (buf) / sizeof (buf[0]);
      cdk_pk_get_mpi (sk->pk, i, buf, nbytes, &nbytes, NULL);
      rc = _gnutls_mpi_scan_pgp (&pkey->params[i], buf, &nbytes);
      if (rc)
        {
          rc = GNUTLS_E_MPI_SCAN_FAILED;
          release_mpi_array (pkey->params, i - 1);
          goto leave;
        }
    }

  pkey->params_size += cdk_pk_get_nskey (pke_algo);
  for (j = 0; j < cdk_pk_get_nskey (pke_algo); j++, i++)
    {
      nbytes = sizeof (buf) / sizeof (buf[0]);
      cdk_sk_get_mpi (sk, j, buf, nbytes, &nbytes, NULL);
      rc = _gnutls_mpi_scan_pgp (&pkey->params[i], buf, &nbytes);
      if (rc)
        {
          rc = GNUTLS_E_MPI_SCAN_FAILED;
          release_mpi_array (pkey->params, i - 1);
          goto leave;
        }
    }

  if (is_ELG (pke_algo))
    return GNUTLS_E_UNWANTED_ALGORITHM;
  else if (is_RSA (pke_algo))
    pkey->pk_algorithm = GNUTLS_PK_RSA;

leave:
  cdk_kbnode_release (snode);
  return rc;
}


/*-
 * _gnutls_openpgp_raw_key_to_gcert - Converts raw OpenPGP data to GnuTLS certs
 * @cert: the certificate to store the data.
 * @raw: the buffer which contains the whole OpenPGP key packets.
 *
 * The RFC2440 (OpenPGP Message Format) data is converted to a GnuTLS
 * specific certificate.
 -*/
int
_gnutls_openpgp_raw_key_to_gcert (gnutls_cert * cert,
                                  const gnutls_datum_t * raw)
{
  cdk_kbnode_t knode = NULL;
  cdk_packet_t pkt = NULL;
  int rc;

  if (!cert)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  memset (cert, 0, sizeof *cert);

  rc = cdk_kbnode_read_from_mem (&knode, raw->data, raw->size);
  if (!(rc = _gnutls_map_cdk_rc (rc)))
    {
      pkt = cdk_kbnode_find_packet (knode, CDK_PKT_PUBLIC_KEY);
    }
  if (!pkt)
    {
      gnutls_assert ();
      rc = _gnutls_map_cdk_rc (rc);
    }
  if (!rc)
    rc = _gnutls_set_datum (&cert->raw, raw->data, raw->size);
  if (!rc)
    rc = openpgp_pk_to_gnutls_cert (cert, pkt->pkt.public_key);

  cdk_kbnode_release (knode);
  return rc;
}

/**
  * gnutls_certificate_set_openpgp_key - Used to set keys in a gnutls_certificate_credentials_t structure
  * @res: is an #gnutls_certificate_credentials_t structure.
  * @key: contains an openpgp public key
  * @pkey: is an openpgp private key
  *
  * This function sets a certificate/private key pair in the 
  * gnutls_certificate_credentials_t structure. This function may be called
  * more than once (in case multiple keys/certificates exist for the
  * server).
  *
  **/
int
gnutls_certificate_set_openpgp_key (gnutls_certificate_credentials_t
                                    res, gnutls_openpgp_crt_t crt,
                                    gnutls_openpgp_privkey_t pkey)
{
  int ret;

  /* this should be first */

  res->pkey = gnutls_realloc_fast (res->pkey,
                                   (res->ncerts + 1) *
                                   sizeof (gnutls_privkey));
  if (res->pkey == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = _gnutls_openpgp_privkey_to_gkey (&res->pkey[res->ncerts], pkey);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  res->cert_list = gnutls_realloc_fast (res->cert_list,
                                        (1 +
                                         res->ncerts) *
                                        sizeof (gnutls_cert *));
  if (res->cert_list == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list_length = gnutls_realloc_fast (res->cert_list_length,
                                               (1 +
                                                res->ncerts) * sizeof (int));
  if (res->cert_list_length == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list[res->ncerts] = gnutls_calloc (1, sizeof (gnutls_cert));
  if (res->cert_list[res->ncerts] == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  res->cert_list_length[res->ncerts] = 1;

  ret = _gnutls_openpgp_crt_to_gcert (res->cert_list[res->ncerts], crt);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  res->ncerts++;

  /* FIXME: Check if the keys match. */

  return 0;
}


/*-
 * gnutls_openpgp_get_key - Retrieve a key from the keyring.
 * @key: the destination context to save the key.
 * @keyring: the datum struct that contains all keyring information.
 * @attr: The attribute (keyid, fingerprint, ...).
 * @by: What attribute is used.
 *
 * This function can be used to retrieve keys by different pattern
 * from a binary or a file keyring.
 -*/
int
gnutls_openpgp_get_key (gnutls_datum_t * key,
                        gnutls_openpgp_keyring_t keyring, key_attr_t by,
                        opaque * pattern)
{
  cdk_kbnode_t knode = NULL;
  unsigned long keyid[2];
  unsigned char *buf;
  void *desc;
  size_t len;
  int rc = 0;

  if (!key || !keyring || by == KEY_ATTR_NONE)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  memset (key, 0, sizeof *key);

  if (by == KEY_ATTR_SHORT_KEYID)
    {
      keyid[0] = buftou32 (pattern);
      desc = keyid;
    }
  else if (by == KEY_ATTR_KEYID)
    {
      keyid[0] = buftou32 (pattern);
      keyid[1] = buftou32 (pattern + 4);
      desc = keyid;
    }
  else
    desc = pattern;
  rc = cdk_keydb_search_start (keyring->db, by, desc);
  if (!rc)
    rc = cdk_keydb_search (keyring->db, &knode);
  if (rc)
    {
      rc = _gnutls_map_cdk_rc (rc);
      goto leave;
    }

  if (!cdk_kbnode_find (knode, CDK_PKT_PUBLIC_KEY))
    {
      rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
      goto leave;
    }

  /* We let the function allocate the buffer to avoid
     to call the function twice. */
  rc = cdk_kbnode_write_to_mem_alloc (knode, &buf, &len);
  if (!rc)
    datum_append (key, buf, len);
  cdk_free (buf);

leave:
  cdk_kbnode_release (knode);
  return rc;
}


/* Convert the stream to a datum. In this case we use the mmap
   function to map the entire stream to a buffer. */
static int
stream_to_datum (cdk_stream_t inp, gnutls_datum_t * raw)
{
  uint8_t *buf;
  size_t buflen;

  if (!inp || !raw)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  cdk_stream_mmap (inp, &buf, &buflen);
  datum_append (raw, buf, buflen);
  cdk_free (buf);

  if (!buflen)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  return 0;
}



/**
 * gnutls_certificate_set_openpgp_key_mem - Used to set OpenPGP keys
 * @res: the destination context to save the data.
 * @cert: the datum that contains the public key.
 * @key: the datum that contains the secret key.
 *
 * This funtion is used to load OpenPGP keys into the GnuTLS credential 
 * structure.
 * It doesn't matter whether the keys are armored or not, but the files
 * should only contain one key which should not be encrypted.
 **/
int
gnutls_certificate_set_openpgp_key_mem (gnutls_certificate_credentials_t
                                        res, const gnutls_datum_t * icert,
                                        const gnutls_datum_t * ikey,
                                        gnutls_openpgp_crt_fmt_t format)
{
  gnutls_openpgp_privkey_t key;
  gnutls_openpgp_crt_t cert;
  int ret;

  ret = gnutls_openpgp_privkey_init (&key);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = gnutls_openpgp_privkey_import (key, ikey, format, NULL, 0);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_privkey_deinit (key);
      return ret;
    }

  ret = gnutls_openpgp_crt_init (&cert);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_privkey_deinit (key);
      return ret;
    }

  ret = gnutls_openpgp_crt_import (cert, icert, format);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_privkey_deinit (key);
      gnutls_openpgp_crt_deinit (cert);
      return ret;
    }


  ret = gnutls_certificate_set_openpgp_key (res, cert, key);

  gnutls_openpgp_privkey_deinit (key);
  gnutls_openpgp_crt_deinit (cert);

  return ret;
}


/**
 * gnutls_certificate_set_openpgp_key_file - Used to set OpenPGP keys
 * @res: the destination context to save the data.
 * @certfile: the file that contains the public key.
 * @keyfile: the file that contains the secret key.
 *
 * This funtion is used to load OpenPGP keys into the GnuTLS credentials structure.
 * It doesn't matter whether the keys are armored or not, but the files
 * should only contain one key which should not be encrypted.
 **/
int
gnutls_certificate_set_openpgp_key_file (gnutls_certificate_credentials_t
                                         res, const char *certfile,
                                         const char *keyfile,
                                         gnutls_openpgp_crt_fmt_t format)
{
  struct stat statbuf;
  gnutls_datum_t key, cert;
  int rc;
  size_t size;

  if (!res || !keyfile || !certfile)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (stat (certfile, &statbuf) || stat (keyfile, &statbuf))
    {
      gnutls_assert ();
      return GNUTLS_E_FILE_ERROR;
    }

  cert.data = read_binary_file (certfile, &size);
  cert.size = (unsigned int) size;
  if (cert.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_FILE_ERROR;
    }

  key.data = read_binary_file (keyfile, &size);
  key.size = (unsigned int) size;
  if (key.data == NULL)
    {
      gnutls_assert ();
      free (cert.data);
      return GNUTLS_E_FILE_ERROR;
    }

  rc = gnutls_certificate_set_openpgp_key_mem (res, &cert, &key, format);

  free (cert.data);
  free (key.data);

  if (rc < 0)
    {
      gnutls_assert ();
      return rc;
    }

  return 0;
}


int
gnutls_openpgp_count_key_names (const gnutls_datum_t * cert)
{
  cdk_kbnode_t knode, p, ctx;
  cdk_packet_t pkt;
  int nuids;

  if (cert == NULL)
    {
      gnutls_assert ();
      return 0;
    }

  if (cdk_kbnode_read_from_mem (&knode, cert->data, cert->size))
    {
      gnutls_assert ();
      return 0;
    }

  ctx = NULL;
  for (nuids = 0;;)
    {
      p = cdk_kbnode_walk (knode, &ctx, 0);
      if (!p)
        break;
      pkt = cdk_kbnode_get_packet (p);
      if (pkt->pkttype == CDK_PKT_USER_ID)
        nuids++;
    }

  cdk_kbnode_release (knode);
  return nuids;
}


/**
 * gnutls_certificate_set_openpgp_keyring_file - Sets a keyring file for OpenPGP
 * @c: A certificate credentials structure
 * @file: filename of the keyring.
 *
 * The function is used to set keyrings that will be used internally
 * by various OpenPGP functions. For example to find a key when it
 * is needed for an operations. The keyring will also be used at the
 * verification functions.
 *
 **/
int
gnutls_certificate_set_openpgp_keyring_file (gnutls_certificate_credentials_t
                                             c, const char *file,
                                             gnutls_openpgp_crt_fmt_t format)
{
  gnutls_datum_t ring;
  size_t size;
  int rc;

  if (!c || !file)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ring.data = read_binary_file (file, &size);
  ring.size = (unsigned int) size;
  if (ring.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_FILE_ERROR;
    }

  rc =
    gnutls_certificate_set_openpgp_keyring_mem (c, ring.data, ring.size,
                                                format);

  free (ring.data);

  return rc;
}

/**
 * gnutls_certificate_set_openpgp_keyring_mem - Add keyring data for OpenPGP
 * @c: A certificate credentials structure
 * @data: buffer with keyring data.
 * @dlen: length of data buffer.
 *
 * The function is used to set keyrings that will be used internally
 * by various OpenPGP functions. For example to find a key when it
 * is needed for an operations. The keyring will also be used at the
 * verification functions.
 *
 **/
int
gnutls_certificate_set_openpgp_keyring_mem (gnutls_certificate_credentials_t
                                            c, const opaque * data,
                                            size_t dlen,
                                            gnutls_openpgp_crt_fmt_t format)
{
#ifndef KEYRING_HACK
  cdk_stream_t inp;
  size_t count;
  uint8_t *buf;
  gnutls_datum ddata;
  int rc;

  ddata.data = (void *) data;
  ddata.size = dlen;

  if (!c || !data || !dlen)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  rc = gnutls_openpgp_keyring_init (&c->keyring);
  if (rc < 0)
    {
      gnutls_assert ();
      return rc;
    }

  rc = gnutls_openpgp_keyring_import (c->keyring, &ddata, format);
  if (rc < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_keyring_deinit (c->keyring);
      return rc;
    }

  return 0;
#else

  c->keyring_format = format;

  c->keyring.data = gnutls_malloc (dlen + 1);
  if (c->keyring.data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  memcpy (c->keyring.data, data, dlen);
  c->keyring.data[dlen] = 0;
  c->keyring.size = dlen;

#endif
}

/*-
 * _gnutls_openpgp_request_key - Receives a key from a database, key server etc
 * @ret - a pointer to gnutls_datum_t structure.
 * @cred - a gnutls_certificate_credentials_t structure.
 * @key_fingerprint - The keyFingerprint
 * @key_fingerprint_size - the size of the fingerprint
 *
 * Retrieves a key from a local database, keyring, or a key server. The
 * return value is locally allocated.
 *
 -*/
int
_gnutls_openpgp_request_key (gnutls_session_t session, gnutls_datum_t * ret,
                             const gnutls_certificate_credentials_t cred,
                             opaque * key_fpr, int key_fpr_size)
{
  int rc = 0;
#ifdef KEYRING_HACK
  gnutls_openpgp_keyring_t kring;
#endif

  if (!ret || !cred || !key_fpr)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (key_fpr_size != 16 && key_fpr_size != 20)
    return GNUTLS_E_HASH_FAILED;        /* only MD5 and SHA1 are supported */

#ifndef KEYRING_HACK
  rc = gnutls_openpgp_get_key (ret, cred->keyring, KEY_ATTR_FPR, key_fpr);
#else
  rc = gnutls_openpgp_keyring_init (&kring);
  if (rc < 0)
    {
      gnutls_assert ();
      return rc;
    }

  rc =
    gnutls_openpgp_keyring_import (kring, &cred->keyring,
                                   cred->keyring_format);
  if (rc < 0)
    {
      gnutls_assert ();
      gnutls_openpgp_keyring_deinit (kring);
      return rc;
    }
#endif
  if (rc >= 0)                  /* key was found */
    {
      rc = 0;
      goto error;
    }
  else
    rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;

  /* If the callback function was set, then try this one. */
  if (session->internals.openpgp_recv_key_func != NULL)
    {
      rc = session->internals.openpgp_recv_key_func (session,
                                                     key_fpr,
                                                     key_fpr_size, ret);
      if (rc < 0)
        {
          gnutls_assert ();
          rc = GNUTLS_E_OPENPGP_GETKEY_FAILED;
          goto error;
        }
    }

error:
#ifdef KEYRING_HACK
  gnutls_openpgp_keyring_deinit (kring);
#endif
  return rc;
}

/**
 * gnutls_openpgp_set_recv_key_function - Used to set a key retrieval callback for PGP keys
 * @session: a TLS session
 * @func: the callback
 *
 * This funtion will set a key retrieval function for OpenPGP keys. This
 * callback is only useful in server side, and will be used if the peer
 * sent a key fingerprint instead of a full key.
 *
 **/
void
gnutls_openpgp_set_recv_key_function (gnutls_session_t session,
                                      gnutls_openpgp_recv_key_func func)
{
  session->internals.openpgp_recv_key_func = func;
}


/* Copies a gnutls_openpgp_privkey_t to a gnutls_privkey structure. */
int
_gnutls_openpgp_privkey_to_gkey (gnutls_privkey * dest,
                                 gnutls_openpgp_privkey_t src)
{
  int i, ret;

  memset (dest, 0, sizeof (gnutls_privkey));

  for (i = 0; i < src->pkey.params_size; i++)
    {
      dest->params[i] = _gnutls_mpi_copy (src->pkey.params[i]);
      if (dest->params[i] == NULL)
        {
          gnutls_assert ();
          ret = GNUTLS_E_MEMORY_ERROR;
          goto cleanup;
        }
    }

  dest->pk_algorithm = src->pkey.pk_algorithm;
  dest->params_size = src->pkey.params_size;

  return 0;

cleanup:
  for (i = 0; i < src->pkey.params_size; i++)
    _gnutls_mpi_release (&dest->params[i]);
  return ret;
}

/* Converts a parsed gnutls_openpgp_crt_t to a gnutls_cert structure.
 */
int
_gnutls_openpgp_crt_to_gcert (gnutls_cert * gcert, gnutls_openpgp_crt_t cert)
{
  opaque *der;
  size_t der_size = 0;
  gnutls_datum_t raw;
  int ret;

  memset (gcert, 0, sizeof (gnutls_cert));
  gcert->cert_type = GNUTLS_CRT_OPENPGP;


  ret = gnutls_openpgp_crt_export (cert, GNUTLS_OPENPGP_FMT_RAW,
                                   NULL, &der_size);
  if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER)
    {
      gnutls_assert ();
      return ret;
    }

  der = gnutls_malloc (der_size);
  if (der == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = gnutls_openpgp_crt_export (cert, GNUTLS_OPENPGP_FMT_RAW,
                                   der, &der_size);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_free (der);
      return ret;
    }

  raw.data = der;
  raw.size = der_size;

  ret = _gnutls_openpgp_raw_key_to_gcert (gcert, &raw);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_free (der);
      return ret;
    }

  gnutls_free (der);

  return 0;

}


/**
 * gnutls_openpgp_privkey_sign_hash - This function will sign the given data using the private key params
 * @key: Holds the key
 * @hash: holds the data to be signed
 * @signature: will contain newly allocated signature
 *
 * This function will sign the given hash using the private key.
 *
 * Return value: In case of failure a negative value will be returned,
 * and 0 on success.
 **/
int
gnutls_openpgp_privkey_sign_hash (gnutls_openpgp_privkey_t key,
                                  const gnutls_datum_t * hash,
                                  gnutls_datum_t * signature)
{
  int result;

  if (key == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  result = _gnutls_sign (key->pkey.pk_algorithm, key->pkey.params,
                         key->pkey.params_size, hash, signature);
  if (result < 0)
    {
      gnutls_assert ();
      return result;
    }

  return 0;
}
