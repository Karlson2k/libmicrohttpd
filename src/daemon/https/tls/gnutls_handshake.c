/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
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

/* Functions that relate to the TLS handshake procedure.
 */

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "debug.h"
#include "gnutls_algorithms.h"
#include "gnutls_compress.h"
#include "gnutls_cipher.h"
#include "gnutls_buffers.h"
#include "gnutls_kx.h"
#include "gnutls_handshake.h"
#include "gnutls_num.h"
#include "gnutls_hash_int.h"
#include "gnutls_extensions.h"
#include "gnutls_supplemental.h"
#include "gnutls_auth_int.h"
#include "auth_cert.h"
#include "gnutls_cert.h"
#include "gnutls_constate.h"
#include "gnutls_record.h"
#include "gnutls_state.h"
#include "gnutls_rsa_export.h"  /* for gnutls_get_rsa_params() */
#include "auth_anon.h"          /* for gnutls_anon_server_credentials_t */
#include "gc.h"

#ifdef HANDSHAKE_DEBUG
#define ERR(x, y) _gnutls_handshake_log( "HSK[%x]: %s (%d)\n", session, x,y)
#else
#define ERR(x, y)
#endif

#define TRUE 1
#define FALSE 0

int _gnutls_server_select_comp_method (gnutls_session_t session,
                                       opaque * data, int datalen);


/* Clears the handshake hash buffers and handles.
 */
inline static void
_gnutls_handshake_hash_buffers_clear (gnutls_session_t session)
{
  _gnutls_hash_deinit (session->internals.handshake_mac_handle_md5, NULL);
  _gnutls_hash_deinit (session->internals.handshake_mac_handle_sha, NULL);
  session->internals.handshake_mac_handle_md5 = NULL;
  session->internals.handshake_mac_handle_sha = NULL;
  _gnutls_handshake_buffer_clear (session);
}

/* this will copy the required values for resuming to
 * internals, and to security_parameters.
 * this will keep as less data to security_parameters.
 */
static void
resume_copy_required_values (gnutls_session_t session)
{
  /* get the new random values */
  memcpy (session->internals.resumed_security_parameters.
          server_random,
          session->security_parameters.server_random, TLS_RANDOM_SIZE);
  memcpy (session->internals.resumed_security_parameters.
          client_random,
          session->security_parameters.client_random, TLS_RANDOM_SIZE);

  /* keep the ciphersuite and compression
   * That is because the client must see these in our
   * hello message.
   */
  memcpy (session->security_parameters.current_cipher_suite.
          suite,
          session->internals.resumed_security_parameters.
          current_cipher_suite.suite, 2);

  session->internals.compression_method =
    session->internals.resumed_security_parameters.read_compression_algorithm;
  /* or write_compression_algorithm
   * they are the same
   */

  session->security_parameters.entity =
    session->internals.resumed_security_parameters.entity;

  _gnutls_set_current_version (session,
                               session->internals.
                               resumed_security_parameters.version);

  session->security_parameters.cert_type =
    session->internals.resumed_security_parameters.cert_type;

  memcpy (session->security_parameters.session_id,
          session->internals.resumed_security_parameters.
          session_id, sizeof (session->security_parameters.session_id));
  session->security_parameters.session_id_size =
    session->internals.resumed_security_parameters.session_id_size;
}

void
_gnutls_set_server_random (gnutls_session_t session, uint8_t * rnd)
{
  memcpy (session->security_parameters.server_random, rnd, TLS_RANDOM_SIZE);
}

void
_gnutls_set_client_random (gnutls_session_t session, uint8_t * rnd)
{
  memcpy (session->security_parameters.client_random, rnd, TLS_RANDOM_SIZE);
}

/* Calculate The SSL3 Finished message */
#define SSL3_CLIENT_MSG "CLNT"
#define SSL3_SERVER_MSG "SRVR"
#define SSL_MSG_LEN 4
static int
_gnutls_ssl3_finished (gnutls_session_t session, int type, opaque * ret)
{
  const int siz = SSL_MSG_LEN;
  mac_hd_t td_md5;
  mac_hd_t td_sha;
  const char *mesg;

  td_md5 = _gnutls_hash_copy (session->internals.handshake_mac_handle_md5);
  if (td_md5 == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  td_sha = _gnutls_hash_copy (session->internals.handshake_mac_handle_sha);
  if (td_sha == NULL)
    {
      gnutls_assert ();
      _gnutls_hash_deinit (td_md5, NULL);
      return GNUTLS_E_HASH_FAILED;
    }

  if (type == GNUTLS_SERVER)
    {
      mesg = SSL3_SERVER_MSG;
    }
  else
    {
      mesg = SSL3_CLIENT_MSG;
    }

  _gnutls_hash (td_md5, mesg, siz);
  _gnutls_hash (td_sha, mesg, siz);

  _gnutls_mac_deinit_ssl3_handshake (td_md5, ret,
                                     session->security_parameters.
                                     master_secret, TLS_MASTER_SIZE);
  _gnutls_mac_deinit_ssl3_handshake (td_sha, &ret[16],
                                     session->security_parameters.
                                     master_secret, TLS_MASTER_SIZE);

  return 0;
}

/* Hash the handshake messages as required by TLS 1.0 */
#define SERVER_MSG "server finished"
#define CLIENT_MSG "client finished"
#define TLS_MSG_LEN 15
int
_gnutls_finished (gnutls_session_t session, int type, void *ret)
{
  const int siz = TLS_MSG_LEN;
  opaque concat[36];
  size_t len;
  const char *mesg;
  mac_hd_t td_md5 = NULL;
  mac_hd_t td_sha;
  gnutls_protocol_t ver = gnutls_protocol_get_version (session);

  if (ver < MHD_GNUTLS_TLS1_2)
    {
      td_md5 =
        _gnutls_hash_copy (session->internals.handshake_mac_handle_md5);
      if (td_md5 == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_HASH_FAILED;
        }
    }

  td_sha = _gnutls_hash_copy (session->internals.handshake_mac_handle_sha);
  if (td_sha == NULL)
    {
      gnutls_assert ();
      _gnutls_hash_deinit (td_md5, NULL);
      return GNUTLS_E_HASH_FAILED;
    }

  if (ver < MHD_GNUTLS_TLS1_2)
    {
      _gnutls_hash_deinit (td_md5, concat);
      _gnutls_hash_deinit (td_sha, &concat[16]);
      len = 20 + 16;
    }
  else
    {
      _gnutls_hash_deinit (td_sha, concat);
      len = 20;
    }

  if (type == GNUTLS_SERVER)
    {
      mesg = SERVER_MSG;
    }
  else
    {
      mesg = CLIENT_MSG;
    }

  return _gnutls_PRF (session, session->security_parameters.master_secret,
                      TLS_MASTER_SIZE, mesg, siz, concat, len, 12, ret);
}

/* this function will produce TLS_RANDOM_SIZE==32 bytes of random data
 * and put it to dst.
 */
int
_gnutls_tls_create_random (opaque * dst)
{
  uint32_t tim;

  /* Use weak random numbers for the most of the
   * buffer except for the first 4 that are the
   * system's time.
   */

  tim = time (NULL);
  /* generate server random value */
  _gnutls_write_uint32 (tim, dst);

  if (gc_nonce (&dst[4], TLS_RANDOM_SIZE - 4) != GC_OK)
    {
      gnutls_assert ();
      return GNUTLS_E_RANDOM_FAILED;
    }

  return 0;
}

/* returns the 0 on success or a negative value.
 */
int
_gnutls_negotiate_version (gnutls_session_t session,
                           gnutls_protocol_t adv_version)
{
  int ret;

  /* if we do not support that version  */
  if (_gnutls_version_is_supported (session, adv_version) == 0)
    {
      /* If he requested something we do not support
       * then we send him the highest we support.
       */
      ret = _gnutls_version_max (session);
      if (ret == MHD_GNUTLS_VERSION_UNKNOWN)
        {
          /* this check is not really needed.
           */
          gnutls_assert ();
          return GNUTLS_E_UNKNOWN_CIPHER_SUITE;
        }
    }
  else
    {
      ret = adv_version;
    }

  _gnutls_set_current_version (session, ret);

  return ret;
}

int
_gnutls_user_hello_func (gnutls_session session,
                         gnutls_protocol_t adv_version)
{
  int ret;

  if (session->internals.user_hello_func != NULL)
    {
      ret = session->internals.user_hello_func (session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      /* Here we need to renegotiate the version since the callee might
       * have disabled some TLS versions.
       */
      ret = _gnutls_negotiate_version (session, adv_version);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
    }
  return 0;
}

/* Read a client hello packet.
 * A client hello must be a known version client hello
 * or version 2.0 client hello (only for compatibility
 * since SSL version 2.0 is not supported).
 */
int
_gnutls_read_client_hello (gnutls_session_t session, opaque * data,
                           int datalen)
{
  uint8_t session_id_len;
  int pos = 0, ret = 0;
  uint16_t suite_size, comp_size;
  gnutls_protocol_t adv_version;
  int neg_version;
  int len = datalen;
  opaque rnd[TLS_RANDOM_SIZE], *suite_ptr, *comp_ptr;

  DECR_LEN (len, 2);

  _gnutls_handshake_log ("HSK[%x]: Client's version: %d.%d\n", session,
                         data[pos], data[pos + 1]);

  adv_version = _gnutls_version_get (data[pos], data[pos + 1]);
  set_adv_version (session, data[pos], data[pos + 1]);
  pos += 2;

  neg_version = _gnutls_negotiate_version (session, adv_version);
  if (neg_version < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* Read client random value.
   */
  DECR_LEN (len, TLS_RANDOM_SIZE);
  _gnutls_set_client_random (session, &data[pos]);
  pos += TLS_RANDOM_SIZE;

  _gnutls_tls_create_random (rnd);
  _gnutls_set_server_random (session, rnd);

  session->security_parameters.timestamp = time (NULL);

  DECR_LEN (len, 1);
  session_id_len = data[pos++];

  /* RESUME SESSION */
  if (session_id_len > TLS_MAX_SESSION_ID_SIZE)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }
  DECR_LEN (len, session_id_len);

  pos += session_id_len;

  /* TODO rm if support for resumed sessions won't be supported */
  if (0)
    {                           /* resumed! */
      resume_copy_required_values (session);
      session->internals.resumed = RESUME_TRUE;
      return _gnutls_user_hello_func (session, adv_version);
    }
  else
    {
      _gnutls_generate_session_id (session->security_parameters.
                                   session_id,
                                   &session->security_parameters.
                                   session_id_size);

      session->internals.resumed = RESUME_FALSE;
    }

  /* Remember ciphersuites for later
   */
  DECR_LEN (len, 2);
  suite_size = _gnutls_read_uint16 (&data[pos]);
  pos += 2;

  DECR_LEN (len, suite_size);
  suite_ptr = &data[pos];
  pos += suite_size;

  /* Point to the compression methods
   */
  DECR_LEN (len, 1);
  comp_size = data[pos++];      /* z is the number of compression methods */

  DECR_LEN (len, comp_size);
  comp_ptr = &data[pos];
  pos += comp_size;

  /* Parse the extensions (if any)
   */
  if (neg_version >= MHD_GNUTLS_TLS1_0)
    {
      ret = _gnutls_parse_extensions (session, EXTENSION_APPLICATION, &data[pos], len); /* len is the rest of the parsed length */
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
    }

  ret = _gnutls_user_hello_func (session, adv_version);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (neg_version >= MHD_GNUTLS_TLS1_0)
    {
      ret = _gnutls_parse_extensions (session, EXTENSION_TLS, &data[pos], len); /* len is the rest of the parsed length */
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
    }

  /* select an appropriate cipher suite
   */
  ret = _gnutls_server_select_suite (session, suite_ptr, suite_size);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* select appropriate compression method */
  ret = _gnutls_server_select_comp_method (session, comp_ptr, comp_size);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

/* here we hash all pending data.
 */
inline static int
_gnutls_handshake_hash_pending (gnutls_session_t session)
{
  size_t siz;
  int ret;
  opaque *data;

  if (session->internals.handshake_mac_handle_sha == NULL ||
      session->internals.handshake_mac_handle_md5 == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* We check if there are pending data to hash.
   */
  if ((ret = _gnutls_handshake_buffer_get_ptr (session, &data, &siz)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (siz > 0)
    {
      _gnutls_hash (session->internals.handshake_mac_handle_sha, data, siz);
      _gnutls_hash (session->internals.handshake_mac_handle_md5, data, siz);
    }

  _gnutls_handshake_buffer_empty (session);

  return 0;
}


/* This is to be called after sending CHANGE CIPHER SPEC packet
 * and initializing encryption. This is the first encrypted message
 * we send.
 */
int
_gnutls_send_finished (gnutls_session_t session, int again)
{
  uint8_t data[36];
  int ret;
  int data_size = 0;


  if (again == 0)
    {

      /* This is needed in order to hash all the required
       * messages.
       */
      if ((ret = _gnutls_handshake_hash_pending (session)) < 0)
        {
          gnutls_assert ();
          return ret;
        }

      if (gnutls_protocol_get_version (session) == MHD_GNUTLS_SSL3)
        {
          ret =
            _gnutls_ssl3_finished (session,
                                   session->security_parameters.entity, data);
          data_size = 36;
        }
      else
        {                       /* TLS 1.0 */
          ret =
            _gnutls_finished (session,
                              session->security_parameters.entity, data);
          data_size = 12;
        }

      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

    }

  ret =
    _gnutls_send_handshake (session, data, data_size,
                            GNUTLS_HANDSHAKE_FINISHED);

  return ret;
}

/* This is to be called after sending our finished message. If everything
 * went fine we have negotiated a secure connection
 */
int
_gnutls_recv_finished (gnutls_session_t session)
{
  uint8_t data[36], *vrfy;
  int data_size;
  int ret;
  int vrfysize;

  ret =
    _gnutls_recv_handshake (session, &vrfy, &vrfysize,
                            GNUTLS_HANDSHAKE_FINISHED, MANDATORY_PACKET);
  if (ret < 0)
    {
      ERR ("recv finished int", ret);
      gnutls_assert ();
      return ret;
    }


  if (gnutls_protocol_get_version (session) == MHD_GNUTLS_SSL3)
    {
      data_size = 36;
    }
  else
    {
      data_size = 12;
    }

  if (vrfysize != data_size)
    {
      gnutls_assert ();
      gnutls_free (vrfy);
      return GNUTLS_E_ERROR_IN_FINISHED_PACKET;
    }

  if (gnutls_protocol_get_version (session) == MHD_GNUTLS_SSL3)
    {
      ret =
        _gnutls_ssl3_finished (session,
                               (session->security_parameters.
                                entity + 1) % 2, data);
    }
  else
    {                           /* TLS 1.0 */
      ret =
        _gnutls_finished (session,
                          (session->security_parameters.entity +
                           1) % 2, data);
    }

  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_free (vrfy);
      return ret;
    }

  if (memcmp (vrfy, data, data_size) != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_ERROR_IN_FINISHED_PACKET;
    }
  gnutls_free (vrfy);

  return ret;
}

/* returns PK_RSA if the given cipher suite list only supports,
 * RSA algorithms, PK_DSA if DSS, and PK_ANY for both or PK_NONE for none.
 */
static int
_gnutls_server_find_pk_algos_in_ciphersuites (const opaque *
                                              data, int datalen)
{
  int j;
  gnutls_pk_algorithm_t algo = GNUTLS_PK_NONE, prev_algo = 0;
  gnutls_kx_algorithm_t kx;
  cipher_suite_st cs;

  if (datalen % 2 != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  for (j = 0; j < datalen; j += 2)
    {
      memcpy (&cs.suite, &data[j], 2);
      kx = _gnutls_cipher_suite_get_kx_algo (&cs);

      if (_gnutls_map_kx_get_cred (kx, 1) == MHD_GNUTLS_CRD_CERTIFICATE)
        {
          algo = _gnutls_map_pk_get_pk (kx);

          if (algo != prev_algo && prev_algo != 0)
            return GNUTLS_PK_ANY;
          prev_algo = algo;
        }
    }

  return algo;
}


/* This selects the best supported ciphersuite from the given ones. Then
 * it adds the suite to the session and performs some checks.
 */
int
_gnutls_server_select_suite (gnutls_session_t session, opaque * data,
                             int datalen)
{
  int x, i, j;
  cipher_suite_st *ciphers, cs;
  int retval, err;
  gnutls_pk_algorithm_t pk_algo;        /* will hold the pk algorithms
                                         * supported by the peer.
                                         */

  pk_algo = _gnutls_server_find_pk_algos_in_ciphersuites (data, datalen);

  x = _gnutls_supported_ciphersuites (session, &ciphers);
  if (x < 0)
    {                           /* the case x==0 is handled within the function. */
      gnutls_assert ();
      return x;
    }

  /* Here we remove any ciphersuite that does not conform
   * the certificate requested, or to the
   * authentication requested (e.g. SRP).
   */
  x = _gnutls_remove_unwanted_ciphersuites (session, &ciphers, x, pk_algo);
  if (x <= 0)
    {
      gnutls_assert ();
      gnutls_free (ciphers);
      if (x < 0)
        return x;
      else
        return GNUTLS_E_UNKNOWN_CIPHER_SUITE;
    }

  /* Data length should be zero mod 2 since
   * every ciphersuite is 2 bytes. (this check is needed
   * see below).
   */
  if (datalen % 2 != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }
#ifdef HANDSHAKE_DEBUG

  _gnutls_handshake_log ("HSK[%x]: Requested cipher suites: \n", session);
  for (j = 0; j < datalen; j += 2)
    {
      memcpy (&cs.suite, &data[j], 2);
      _gnutls_handshake_log ("\t%s\n", _gnutls_cipher_suite_get_name (&cs));
    }
  _gnutls_handshake_log ("HSK[%x]: Supported cipher suites: \n", session);
  for (j = 0; j < x; j++)
    _gnutls_handshake_log ("\t%s\n",
                           _gnutls_cipher_suite_get_name (&ciphers[j]));
#endif
  memset (session->security_parameters.current_cipher_suite.suite, '\0', 2);

  retval = GNUTLS_E_UNKNOWN_CIPHER_SUITE;

  for (j = 0; j < datalen; j += 2)
    {
      for (i = 0; i < x; i++)
        {
          if (memcmp (ciphers[i].suite, &data[j], 2) == 0)
            {
              memcpy (&cs.suite, &data[j], 2);

              _gnutls_handshake_log
                ("HSK[%x]: Selected cipher suite: %s\n", session,
                 _gnutls_cipher_suite_get_name (&cs));
              memcpy (session->security_parameters.current_cipher_suite.
                      suite, ciphers[i].suite, 2);
              retval = 0;
              goto finish;
            }
        }
    }

finish:
  gnutls_free (ciphers);

  if (retval != 0)
    {
      gnutls_assert ();
      return retval;
    }

  /* check if the credentials (username, public key etc.) are ok
   */
  if (_gnutls_get_kx_cred
      (session,
       _gnutls_cipher_suite_get_kx_algo (&session->security_parameters.
                                         current_cipher_suite),
       &err) == NULL && err != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }


  /* set the mod_auth_st to the appropriate struct
   * according to the KX algorithm. This is needed since all the
   * handshake functions are read from there;
   */
  session->internals.auth_struct =
    _gnutls_kx_auth_struct (_gnutls_cipher_suite_get_kx_algo
                            (&session->security_parameters.
                             current_cipher_suite));
  if (session->internals.auth_struct == NULL)
    {

      _gnutls_handshake_log
        ("HSK[%x]: Cannot find the appropriate handler for the KX algorithm\n",
         session);
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  return 0;

}


/* This selects the best supported compression method from the ones provided
 */
int
_gnutls_server_select_comp_method (gnutls_session_t session,
                                   opaque * data, int datalen)
{
  int x, i, j;
  uint8_t *comps;

  x = _gnutls_supported_compression_methods (session, &comps);
  if (x < 0)
    {
      gnutls_assert ();
      return x;
    }

  memset (&session->internals.compression_method, 0,
          sizeof (gnutls_compression_method_t));

  for (j = 0; j < datalen; j++)
    {
      for (i = 0; i < x; i++)
        {
          if (comps[i] == data[j])
            {
              gnutls_compression_method_t method =
                _gnutls_compression_get_id (comps[i]);

              session->internals.compression_method = method;
              gnutls_free (comps);

              _gnutls_handshake_log
                ("HSK[%x]: Selected Compression Method: %s\n", session,
                 gnutls_compression_get_name (session->internals.
                                              compression_method));


              return 0;
            }
        }
    }

  /* we were not able to find a compatible compression
   * algorithm
   */
  gnutls_free (comps);
  gnutls_assert ();
  return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;

}

/* This function sends an empty handshake packet. (like hello request).
 * If the previous _gnutls_send_empty_handshake() returned
 * GNUTLS_E_AGAIN or GNUTLS_E_INTERRUPTED, then it must be called again
 * (until it returns ok), with NULL parameters.
 */
int
_gnutls_send_empty_handshake (gnutls_session_t session,
                              gnutls_handshake_description_t type, int again)
{
  opaque data = 0;
  opaque *ptr;

  if (again == 0)
    ptr = &data;
  else
    ptr = NULL;

  return _gnutls_send_handshake (session, ptr, 0, type);
}


/* This function will hash the handshake message we sent. */
static int
_gnutls_handshake_hash_add_sent (gnutls_session_t session,
                                 gnutls_handshake_description_t type,
                                 opaque * dataptr, uint32_t datalen)
{
  int ret;

  if ((ret = _gnutls_handshake_hash_pending (session)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (type != GNUTLS_HANDSHAKE_HELLO_REQUEST)
    {
      _gnutls_hash (session->internals.handshake_mac_handle_sha, dataptr,
                    datalen);
      _gnutls_hash (session->internals.handshake_mac_handle_md5, dataptr,
                    datalen);
    }

  return 0;
}


/* This function sends a handshake message of type 'type' containing the
 * data specified here. If the previous _gnutls_send_handshake() returned
 * GNUTLS_E_AGAIN or GNUTLS_E_INTERRUPTED, then it must be called again
 * (until it returns ok), with NULL parameters.
 */
int
_gnutls_send_handshake (gnutls_session_t session, void *i_data,
                        uint32_t i_datasize,
                        gnutls_handshake_description_t type)
{
  int ret;
  uint8_t *data;
  uint32_t datasize;
  int pos = 0;

  if (i_data == NULL && i_datasize == 0)
    {
      /* we are resuming a previously interrupted
       * send.
       */
      ret = _gnutls_handshake_io_write_flush (session);
      return ret;

    }

  if (i_data == NULL && i_datasize > 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* first run */
  datasize = i_datasize + HANDSHAKE_HEADER_SIZE;
  data = gnutls_alloca (datasize);
  if (data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  data[pos++] = (uint8_t) type;
  _gnutls_write_uint24 (i_datasize, &data[pos]);
  pos += 3;

  if (i_datasize > 0)
    memcpy (&data[pos], i_data, i_datasize);

  /* Here we keep the handshake messages in order to hash them...
   */
  if (type != GNUTLS_HANDSHAKE_HELLO_REQUEST)
    if ((ret =
         _gnutls_handshake_hash_add_sent (session, type, data, datasize)) < 0)
      {
        gnutls_assert ();
        gnutls_afree (data);
        return ret;
      }

  session->internals.last_handshake_out = type;

  ret =
    _gnutls_handshake_io_send_int (session, GNUTLS_HANDSHAKE, type,
                                   data, datasize);

  _gnutls_handshake_log ("HSK[%x]: %s was sent [%ld bytes]\n",
                         session, _gnutls_handshake2str (type), datasize);

  gnutls_afree (data);

  return ret;
}

/* This function will read the handshake header and return it to the caller. If the
 * received handshake packet is not the one expected then it buffers the header, and
 * returns UNEXPECTED_HANDSHAKE_PACKET.
 *
 * FIXME: This function is complex.
 */
#define SSL2_HEADERS 1
static int
_gnutls_recv_handshake_header (gnutls_session_t session,
                               gnutls_handshake_description_t type,
                               gnutls_handshake_description_t * recv_type)
{
  int ret;
  uint32_t length32 = 0;
  uint8_t *dataptr = NULL;      /* for realloc */
  size_t handshake_header_size = HANDSHAKE_HEADER_SIZE;

  /* if we have data into the buffer then return them, do not read the next packet.
   * In order to return we need a full TLS handshake header, or in case of a version 2
   * packet, then we return the first byte.
   */
  if (session->internals.handshake_header_buffer.header_size ==
      handshake_header_size || (session->internals.v2_hello != 0
                                && type == GNUTLS_HANDSHAKE_CLIENT_HELLO
                                && session->internals.
                                handshake_header_buffer.packet_length > 0))
    {

      *recv_type = session->internals.handshake_header_buffer.recv_type;

      return session->internals.handshake_header_buffer.packet_length;
    }

  /* Note: SSL2_HEADERS == 1 */

  dataptr = session->internals.handshake_header_buffer.header;

  /* If we haven't already read the handshake headers.
   */
  if (session->internals.handshake_header_buffer.header_size < SSL2_HEADERS)
    {
      ret =
        _gnutls_handshake_io_recv_int (session, GNUTLS_HANDSHAKE,
                                       type, dataptr, SSL2_HEADERS);

      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      /* The case ret==0 is caught here.
       */
      if (ret != SSL2_HEADERS)
        {
          gnutls_assert ();
          return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        }
      session->internals.handshake_header_buffer.header_size = SSL2_HEADERS;
    }

  if (session->internals.v2_hello == 0
      || type != GNUTLS_HANDSHAKE_CLIENT_HELLO)
    {
      ret =
        _gnutls_handshake_io_recv_int (session, GNUTLS_HANDSHAKE,
                                       type,
                                       &dataptr[session->
                                                internals.
                                                handshake_header_buffer.
                                                header_size],
                                       HANDSHAKE_HEADER_SIZE -
                                       session->internals.
                                       handshake_header_buffer.header_size);
      if (ret <= 0)
        {
          gnutls_assert ();
          return (ret < 0) ? ret : GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        }
      if ((size_t) ret !=
          HANDSHAKE_HEADER_SIZE -
          session->internals.handshake_header_buffer.header_size)
        {
          gnutls_assert ();
          return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        }
      *recv_type = dataptr[0];

      /* we do not use DECR_LEN because we know
       * that the packet has enough data.
       */
      length32 = _gnutls_read_uint24 (&dataptr[1]);
      handshake_header_size = HANDSHAKE_HEADER_SIZE;

      _gnutls_handshake_log ("HSK[%x]: %s was received [%ld bytes]\n",
                             session, _gnutls_handshake2str (dataptr[0]),
                             length32 + HANDSHAKE_HEADER_SIZE);

    }
  else
    {                           /* v2 hello */
      length32 = session->internals.v2_hello - SSL2_HEADERS;    /* we've read the first byte */

      handshake_header_size = SSL2_HEADERS;     /* we've already read one byte */

      *recv_type = dataptr[0];

      _gnutls_handshake_log ("HSK[%x]: %s(v2) was received [%ld bytes]\n",
                             session, _gnutls_handshake2str (*recv_type),
                             length32 + handshake_header_size);

      if (*recv_type != GNUTLS_HANDSHAKE_CLIENT_HELLO)
        {                       /* it should be one or nothing */
          gnutls_assert ();
          return GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
        }
    }

  /* put the packet into the buffer */
  session->internals.handshake_header_buffer.header_size =
    handshake_header_size;
  session->internals.handshake_header_buffer.packet_length = length32;
  session->internals.handshake_header_buffer.recv_type = *recv_type;

  if (*recv_type != type)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
    }

  return length32;
}

#define _gnutls_handshake_header_buffer_clear( session) session->internals.handshake_header_buffer.header_size = 0



/* This function will hash the handshake headers and the
 * handshake data.
 */
static int
_gnutls_handshake_hash_add_recvd (gnutls_session_t session,
                                  gnutls_handshake_description_t recv_type,
                                  opaque * header, uint16_t header_size,
                                  opaque * dataptr, uint32_t datalen)
{
  int ret;

  /* The idea here is to hash the previous message we received,
   * and add the one we just received into the handshake_hash_buffer.
   */

  if ((ret = _gnutls_handshake_hash_pending (session)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* here we buffer the handshake messages - needed at Finished message */
  if (recv_type != GNUTLS_HANDSHAKE_HELLO_REQUEST)
    {

      if ((ret =
           _gnutls_handshake_buffer_put (session, header, header_size)) < 0)
        {
          gnutls_assert ();
          return ret;
        }

      if (datalen > 0)
        {
          if ((ret =
               _gnutls_handshake_buffer_put (session, dataptr, datalen)) < 0)
            {
              gnutls_assert ();
              return ret;
            }
        }
    }

  return 0;
}


/* This function will receive handshake messages of the given types,
 * and will pass the message to the right place in order to be processed.
 * E.g. for the SERVER_HELLO message (if it is expected), it will be
 * passed to _gnutls_recv_hello().
 */
int
_gnutls_recv_handshake (gnutls_session_t session, uint8_t ** data,
                        int *datalen, gnutls_handshake_description_t type,
                        Optional optional)
{
  int ret;
  uint32_t length32 = 0;
  opaque *dataptr = NULL;
  gnutls_handshake_description_t recv_type;

  ret = _gnutls_recv_handshake_header (session, type, &recv_type);
  if (ret < 0)
    {

      if (ret == GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET
          && optional == OPTIONAL_PACKET)
        {
          if (datalen != NULL)
            *datalen = 0;
          if (data != NULL)
            *data = NULL;
          return 0;             /* ok just ignore the packet */
        }

      return ret;
    }

  session->internals.last_handshake_in = recv_type;

  length32 = ret;

  if (length32 > 0)
    dataptr = gnutls_malloc (length32);
  else if (recv_type != GNUTLS_HANDSHAKE_SERVER_HELLO_DONE)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  if (dataptr == NULL && length32 > 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  if (datalen != NULL)
    *datalen = length32;

  if (length32 > 0)
    {
      ret =
        _gnutls_handshake_io_recv_int (session, GNUTLS_HANDSHAKE,
                                       type, dataptr, length32);
      if (ret <= 0)
        {
          gnutls_assert ();
          gnutls_free (dataptr);
          return (ret == 0) ? GNUTLS_E_UNEXPECTED_PACKET_LENGTH : ret;
        }
    }

  if (data != NULL && length32 > 0)
    *data = dataptr;


  ret = _gnutls_handshake_hash_add_recvd (session, recv_type,
                                          session->internals.
                                          handshake_header_buffer.header,
                                          session->internals.
                                          handshake_header_buffer.
                                          header_size, dataptr, length32);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_handshake_header_buffer_clear (session);
      return ret;
    }

  /* If we fail before this then we will reuse the handshake header
   * have have received above. if we get here the we clear the handshake
   * header we received.
   */
  _gnutls_handshake_header_buffer_clear (session);

  switch (recv_type)
    {
    case GNUTLS_HANDSHAKE_CLIENT_HELLO:
    case GNUTLS_HANDSHAKE_SERVER_HELLO:
      ret = _gnutls_recv_hello (session, dataptr, length32);
      /* dataptr is freed because the caller does not
       * need it */
      gnutls_free (dataptr);
      if (data != NULL)
        *data = NULL;
      break;
    case GNUTLS_HANDSHAKE_SERVER_HELLO_DONE:
      if (length32 == 0)
        ret = 0;
      else
        ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
      break;
    case GNUTLS_HANDSHAKE_CERTIFICATE_PKT:
    case GNUTLS_HANDSHAKE_FINISHED:
    case GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
    case GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:
    case GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST:
    case GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY:
    case GNUTLS_HANDSHAKE_SUPPLEMENTAL:
      ret = length32;
      break;
    default:
      gnutls_assert ();
      gnutls_free (dataptr);
      if (data != NULL)
        *data = NULL;
      ret = GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
    }

  return ret;
}

/* This function checks if the given cipher suite is supported, and sets it
 * to the session;
 */
static int
_gnutls_client_set_ciphersuite (gnutls_session_t session, opaque suite[2])
{
  uint8_t z;
  cipher_suite_st *cipher_suites;
  int cipher_suite_num;
  int i, err;

  z = 1;
  cipher_suite_num = _gnutls_supported_ciphersuites (session, &cipher_suites);
  if (cipher_suite_num < 0)
    {
      gnutls_assert ();
      return cipher_suite_num;
    }

  for (i = 0; i < cipher_suite_num; i++)
    {
      if (memcmp (&cipher_suites[i], suite, 2) == 0)
        {
          z = 0;
          break;
        }
    }

  gnutls_free (cipher_suites);

  if (z != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_UNKNOWN_CIPHER_SUITE;
    }

  memcpy (session->security_parameters.current_cipher_suite.suite, suite, 2);

  _gnutls_handshake_log ("HSK[%x]: Selected cipher suite: %s\n", session,
                         _gnutls_cipher_suite_get_name (&session->
                                                        security_parameters.
                                                        current_cipher_suite));


  /* check if the credentials (username, public key etc.) are ok.
   * Actually checks if they exist.
   */
  if (_gnutls_get_kx_cred
      (session, _gnutls_cipher_suite_get_kx_algo (&session->
                                                  security_parameters.
                                                  current_cipher_suite),
       &err) == NULL && err != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }


  /* set the mod_auth_st to the appropriate struct
   * according to the KX algorithm. This is needed since all the
   * handshake functions are read from there;
   */
  session->internals.auth_struct =
    _gnutls_kx_auth_struct (_gnutls_cipher_suite_get_kx_algo
                            (&session->security_parameters.
                             current_cipher_suite));

  if (session->internals.auth_struct == NULL)
    {

      _gnutls_handshake_log
        ("HSK[%x]: Cannot find the appropriate handler for the KX algorithm\n",
         session);
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }


  return 0;
}

/* This function sets the given comp method to the session.
 */
static int
_gnutls_client_set_comp_method (gnutls_session_t session, opaque comp_method)
{
  int comp_methods_num;
  uint8_t *compression_methods;
  int i;

  comp_methods_num = _gnutls_supported_compression_methods (session,
                                                            &compression_methods);
  if (comp_methods_num < 0)
    {
      gnutls_assert ();
      return comp_methods_num;
    }

  for (i = 0; i < comp_methods_num; i++)
    {
      if (compression_methods[i] == comp_method)
        {
          comp_methods_num = 0;
          break;
        }
    }

  gnutls_free (compression_methods);

  if (comp_methods_num != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
    }

  session->internals.compression_method =
    _gnutls_compression_get_id (comp_method);


  return 0;
}

/* This function returns 0 if we are resuming a session or -1 otherwise.
 * This also sets the variables in the session. Used only while reading a server
 * hello.
 */
static int
_gnutls_client_check_if_resuming (gnutls_session_t session,
                                  opaque * session_id, int session_id_len)
{
  opaque buf[2 * TLS_MAX_SESSION_ID_SIZE + 1];

  _gnutls_handshake_log ("HSK[%x]: SessionID length: %d\n", session,
                         session_id_len);
  _gnutls_handshake_log ("HSK[%x]: SessionID: %s\n", session,
                         _gnutls_bin2hex (session_id, session_id_len, buf,
                                          sizeof (buf)));

  if (session_id_len > 0 &&
      session->internals.resumed_security_parameters.session_id_size ==
      session_id_len
      && memcmp (session_id,
                 session->internals.resumed_security_parameters.
                 session_id, session_id_len) == 0)
    {
      /* resume session */
      memcpy (session->internals.
              resumed_security_parameters.server_random,
              session->security_parameters.server_random, TLS_RANDOM_SIZE);
      memcpy (session->internals.
              resumed_security_parameters.client_random,
              session->security_parameters.client_random, TLS_RANDOM_SIZE);
      session->internals.resumed = RESUME_TRUE; /* we are resuming */

      return 0;
    }
  else
    {
      /* keep the new session id */
      session->internals.resumed = RESUME_FALSE;        /* we are not resuming */
      session->security_parameters.session_id_size = session_id_len;
      memcpy (session->security_parameters.session_id,
              session_id, session_id_len);

      return -1;
    }
}


/* This function reads and parses the server hello handshake message.
 * This function also restores resumed parameters if we are resuming a
 * session.
 */
static int
_gnutls_read_server_hello (gnutls_session_t session,
                           opaque * data, int datalen)
{
  uint8_t session_id_len = 0;
  int pos = 0;
  int ret = 0;
  gnutls_protocol_t version;
  int len = datalen;

  if (datalen < 38)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  _gnutls_handshake_log ("HSK[%x]: Server's version: %d.%d\n",
                         session, data[pos], data[pos + 1]);

  DECR_LEN (len, 2);
  version = _gnutls_version_get (data[pos], data[pos + 1]);
  if (_gnutls_version_is_supported (session, version) == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
    }
  else
    {
      _gnutls_set_current_version (session, version);
    }

  pos += 2;

  DECR_LEN (len, TLS_RANDOM_SIZE);
  _gnutls_set_server_random (session, &data[pos]);
  pos += TLS_RANDOM_SIZE;


  /* Read session ID
   */
  DECR_LEN (len, 1);
  session_id_len = data[pos++];

  if (len < session_id_len)
    {
      gnutls_assert ();
      return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
    }
  DECR_LEN (len, session_id_len);


  /* check if we are resuming and set the appropriate
   * values;
   */
  if (_gnutls_client_check_if_resuming
      (session, &data[pos], session_id_len) == 0)
    return 0;
  pos += session_id_len;


  /* Check if the given cipher suite is supported and copy
   * it to the session.
   */

  DECR_LEN (len, 2);
  ret = _gnutls_client_set_ciphersuite (session, &data[pos]);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }
  pos += 2;



  /* move to compression   */
  DECR_LEN (len, 1);

  ret = _gnutls_client_set_comp_method (session, data[pos++]);
  if (ret < 0)
    {
      gnutls_assert ();
      return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
    }

  /* Parse extensions.
   */
  if (version >= MHD_GNUTLS_TLS1_0)
    {
      ret = _gnutls_parse_extensions (session, EXTENSION_ANY, &data[pos], len); /* len is the rest of the parsed length */
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
    }
  return ret;
}


/* This function copies the appropriate ciphersuites to a locally allocated buffer
 * Needed in client hello messages. Returns the new data length.
 */
static int
_gnutls_copy_ciphersuites (gnutls_session_t session,
                           opaque * ret_data, size_t ret_data_size)
{
  int ret, i;
  cipher_suite_st *cipher_suites;
  uint16_t cipher_num;
  int datalen, pos;

  ret = _gnutls_supported_ciphersuites_sorted (session, &cipher_suites);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* Here we remove any ciphersuite that does not conform
   * the certificate requested, or to the
   * authentication requested (eg SRP).
   */
  ret =
    _gnutls_remove_unwanted_ciphersuites (session, &cipher_suites, ret, -1);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_free (cipher_suites);
      return ret;
    }

  /* If no cipher suites were enabled.
   */
  if (ret == 0)
    {
      gnutls_assert ();
      gnutls_free (cipher_suites);
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  cipher_num = ret;

  cipher_num *= sizeof (uint16_t);      /* in order to get bytes */

  datalen = pos = 0;

  datalen += sizeof (uint16_t) + cipher_num;

  if ((size_t) datalen > ret_data_size)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  _gnutls_write_uint16 (cipher_num, ret_data);
  pos += 2;

  for (i = 0; i < (cipher_num / 2); i++)
    {
      memcpy (&ret_data[pos], cipher_suites[i].suite, 2);
      pos += 2;
    }
  gnutls_free (cipher_suites);

  return datalen;
}


/* This function copies the appropriate compression methods, to a locally allocated buffer
 * Needed in hello messages. Returns the new data length.
 */
static int
_gnutls_copy_comp_methods (gnutls_session_t session,
                           opaque * ret_data, size_t ret_data_size)
{
  int ret, i;
  uint8_t *compression_methods, comp_num;
  int datalen, pos;

  ret = _gnutls_supported_compression_methods (session, &compression_methods);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  comp_num = ret;

  datalen = pos = 0;
  datalen += comp_num + 1;

  if ((size_t) datalen > ret_data_size)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ret_data[pos++] = comp_num;   /* put the number of compression methods */

  for (i = 0; i < comp_num; i++)
    {
      ret_data[pos++] = compression_methods[i];
    }

  gnutls_free (compression_methods);

  return datalen;
}

/* This should be sufficient by now. It should hold all the extensions
 * plus the headers in a hello message.
 */
#define MAX_EXT_DATA_LENGTH 1024

/* This function sends the client hello handshake message.
 */
static int
_gnutls_send_client_hello (gnutls_session_t session, int again)
{
  opaque *data = NULL;
  int extdatalen;
  int pos = 0;
  int datalen = 0, ret = 0;
  opaque rnd[TLS_RANDOM_SIZE];
  gnutls_protocol_t hver;
  opaque extdata[MAX_EXT_DATA_LENGTH];

  opaque *SessionID =
    session->internals.resumed_security_parameters.session_id;
  uint8_t session_id_len =
    session->internals.resumed_security_parameters.session_id_size;

  if (SessionID == NULL)
    session_id_len = 0;
  else if (session_id_len == 0)
    SessionID = NULL;

  if (again == 0)
    {

      datalen = 2 + (session_id_len + 1) + TLS_RANDOM_SIZE;
      /* 2 for version, (4 for unix time + 28 for random bytes==TLS_RANDOM_SIZE)
       */

      data = gnutls_malloc (datalen);
      if (data == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }

      /* if we are resuming a session then we set the
       * version number to the previously established.
       */
      if (SessionID == NULL)
        hver = _gnutls_version_max (session);
      else
        {                       /* we are resuming a session */
          hver = session->internals.resumed_security_parameters.version;
        }

      if (hver == MHD_GNUTLS_VERSION_UNKNOWN || hver == 0)
        {
          gnutls_assert ();
          gnutls_free (data);
          return GNUTLS_E_INTERNAL_ERROR;
        }

      data[pos++] = _gnutls_version_get_major (hver);
      data[pos++] = _gnutls_version_get_minor (hver);

      /* Set the version we advertized as maximum
       * (RSA uses it).
       */
      _gnutls_set_adv_version (session, hver);

      /* Some old implementations do not interoperate if we send a
       * different version in the record layer.
       * It seems they prefer to read the record's version
       * as the one we actually requested.
       * The proper behaviour is to use the one in the client hello
       * handshake packet and ignore the one in the packet's record
       * header.
       */
      _gnutls_set_current_version (session, hver);

      /* In order to know when this session was initiated.
       */
      session->security_parameters.timestamp = time (NULL);

      /* Generate random data
       */
      _gnutls_tls_create_random (rnd);
      _gnutls_set_client_random (session, rnd);

      memcpy (&data[pos], rnd, TLS_RANDOM_SIZE);
      pos += TLS_RANDOM_SIZE;

      /* Copy the Session ID       */
      data[pos++] = session_id_len;

      if (session_id_len > 0)
        {
          memcpy (&data[pos], SessionID, session_id_len);
          pos += session_id_len;
        }


      /* Copy the ciphersuites.
       */
      extdatalen =
        _gnutls_copy_ciphersuites (session, extdata, sizeof (extdata));
      if (extdatalen > 0)
        {
          datalen += extdatalen;
          data = gnutls_realloc_fast (data, datalen);
          if (data == NULL)
            {
              gnutls_assert ();
              return GNUTLS_E_MEMORY_ERROR;
            }

          memcpy (&data[pos], extdata, extdatalen);
          pos += extdatalen;

        }
      else
        {
          if (extdatalen == 0)
            extdatalen = GNUTLS_E_INTERNAL_ERROR;
          gnutls_free (data);
          gnutls_assert ();
          return extdatalen;
        }


      /* Copy the compression methods.
       */
      extdatalen =
        _gnutls_copy_comp_methods (session, extdata, sizeof (extdata));
      if (extdatalen > 0)
        {
          datalen += extdatalen;
          data = gnutls_realloc_fast (data, datalen);
          if (data == NULL)
            {
              gnutls_assert ();
              return GNUTLS_E_MEMORY_ERROR;
            }

          memcpy (&data[pos], extdata, extdatalen);
          pos += extdatalen;

        }
      else
        {
          if (extdatalen == 0)
            extdatalen = GNUTLS_E_INTERNAL_ERROR;
          gnutls_free (data);
          gnutls_assert ();
          return extdatalen;
        }

      /* Generate and copy TLS extensions.
       */
      if (hver >= MHD_GNUTLS_TLS1_0)
        {
          extdatalen =
            _gnutls_gen_extensions (session, extdata, sizeof (extdata));

          if (extdatalen > 0)
            {
              datalen += extdatalen;
              data = gnutls_realloc_fast (data, datalen);
              if (data == NULL)
                {
                  gnutls_assert ();
                  return GNUTLS_E_MEMORY_ERROR;
                }

              memcpy (&data[pos], extdata, extdatalen);
            }
          else if (extdatalen < 0)
            {
              gnutls_assert ();
              gnutls_free (data);
              return extdatalen;
            }
        }
    }

  ret =
    _gnutls_send_handshake (session, data, datalen,
                            GNUTLS_HANDSHAKE_CLIENT_HELLO);
  gnutls_free (data);

  return ret;
}

static int
_gnutls_send_server_hello (gnutls_session_t session, int again)
{
  opaque *data = NULL;
  opaque extdata[MAX_EXT_DATA_LENGTH];
  int extdatalen;
  int pos = 0;
  int datalen, ret = 0;
  uint8_t comp;
  opaque *SessionID = session->security_parameters.session_id;
  uint8_t session_id_len = session->security_parameters.session_id_size;
  opaque buf[2 * TLS_MAX_SESSION_ID_SIZE + 1];

  if (SessionID == NULL)
    session_id_len = 0;

  datalen = 0;

#ifdef ENABLE_SRP
  if (IS_SRP_KX
      (_gnutls_cipher_suite_get_kx_algo
       (&session->security_parameters.current_cipher_suite)))
    {
      /* While resuming we cannot check the username extension since it is
       * not available at this point. It will be copied on connection
       * state activation.
       */
      if (session->internals.resumed == RESUME_FALSE &&
          session->security_parameters.extensions.srp_username[0] == 0)
        {
          /* The peer didn't send a valid SRP extension with the
           * SRP username. The draft requires that we send a fatal
           * alert and abort.
           */
          gnutls_assert ();
          ret = gnutls_alert_send (session, GNUTLS_AL_FATAL,
                                   GNUTLS_A_UNKNOWN_PSK_IDENTITY);
          if (ret < 0)
            {
              gnutls_assert ();
              return ret;
            }

          return GNUTLS_E_ILLEGAL_SRP_USERNAME;
        }
    }
#endif

  if (again == 0)
    {
      datalen = 2 + session_id_len + 1 + TLS_RANDOM_SIZE + 3;
      extdatalen =
        _gnutls_gen_extensions (session, extdata, sizeof (extdata));

      if (extdatalen < 0)
        {
          gnutls_assert ();
          return extdatalen;
        }

      data = gnutls_alloca (datalen + extdatalen);
      if (data == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }

      data[pos++] =
        _gnutls_version_get_major (session->security_parameters.version);
      data[pos++] =
        _gnutls_version_get_minor (session->security_parameters.version);

      memcpy (&data[pos],
              session->security_parameters.server_random, TLS_RANDOM_SIZE);
      pos += TLS_RANDOM_SIZE;

      data[pos++] = session_id_len;
      if (session_id_len > 0)
        {
          memcpy (&data[pos], SessionID, session_id_len);
        }
      pos += session_id_len;

      _gnutls_handshake_log ("HSK[%x]: SessionID: %s\n", session,
                             _gnutls_bin2hex (SessionID, session_id_len,
                                              buf, sizeof (buf)));

      memcpy (&data[pos],
              session->security_parameters.current_cipher_suite.suite, 2);
      pos += 2;

      comp =
        (uint8_t) _gnutls_compression_get_num (session->
                                               internals.compression_method);
      data[pos++] = comp;


      if (extdatalen > 0)
        {
          datalen += extdatalen;

          memcpy (&data[pos], extdata, extdatalen);
        }
    }

  ret =
    _gnutls_send_handshake (session, data, datalen,
                            GNUTLS_HANDSHAKE_SERVER_HELLO);
  gnutls_afree (data);

  return ret;
}

int
_gnutls_send_hello (gnutls_session_t session, int again)
{
  int ret;

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      ret = _gnutls_send_client_hello (session, again);

    }
  else
    {                           /* SERVER */
      ret = _gnutls_send_server_hello (session, again);
    }

  return ret;
}

/* RECEIVE A HELLO MESSAGE. This should be called from gnutls_recv_handshake_int only if a
 * hello message is expected. It uses the security_parameters.current_cipher_suite
 * and internals.compression_method.
 */
int
_gnutls_recv_hello (gnutls_session_t session, opaque * data, int datalen)
{
  int ret;

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      ret = _gnutls_read_server_hello (session, data, datalen);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
    }
  else
    {                           /* Server side reading a client hello */

      ret = _gnutls_read_client_hello (session, data, datalen);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
    }

  return ret;
}

/* The packets in gnutls_handshake (it's more broad than original TLS handshake)
 *
 *     Client                                               Server
 *
 *     ClientHello                  -------->
 *                                  <--------         ServerHello
 *
 *                                                    Certificate*
 *                                              ServerKeyExchange*
 *                                  <--------   CertificateRequest*
 *
 *                                  <--------      ServerHelloDone
 *     Certificate*
 *     ClientKeyExchange
 *     CertificateVerify*
 *     [ChangeCipherSpec]
 *     Finished                     -------->
 *                                              [ChangeCipherSpec]
 *                                  <--------             Finished
 *
 * (*): means optional packet.
 */

/**
  * gnutls_rehandshake - This function will renegotiate security parameters
  * @session: is a #gnutls_session_t structure.
  *
  * This function will renegotiate security parameters with the
  * client.  This should only be called in case of a server.
  *
  * This message informs the peer that we want to renegotiate
  * parameters (perform a handshake).
  *
  * If this function succeeds (returns 0), you must call the
  * gnutls_handshake() function in order to negotiate the new
  * parameters.
  *
  * If the client does not wish to renegotiate parameters he will
  * should with an alert message, thus the return code will be
  * %GNUTLS_E_WARNING_ALERT_RECEIVED and the alert will be
  * %GNUTLS_A_NO_RENEGOTIATION.  A client may also choose to ignore
  * this message.
  *
  * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
  *
  **/
int
gnutls_rehandshake (gnutls_session_t session)
{
  int ret;

  /* only server sends that handshake packet */
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    return GNUTLS_E_INVALID_REQUEST;

  ret =
    _gnutls_send_empty_handshake (session, GNUTLS_HANDSHAKE_HELLO_REQUEST,
                                  AGAIN (STATE50));
  STATE = STATE50;

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }
  STATE = STATE0;

  return 0;
}

inline static int
_gnutls_abort_handshake (gnutls_session_t session, int ret)
{
  if (((ret == GNUTLS_E_WARNING_ALERT_RECEIVED) &&
       (gnutls_alert_get (session) == GNUTLS_A_NO_RENEGOTIATION))
      || ret == GNUTLS_E_GOT_APPLICATION_DATA)
    return 0;

  /* this doesn't matter */
  return GNUTLS_E_INTERNAL_ERROR;
}


/* This function initialized the handshake hash session.
 * required for finished messages.
 */
inline static int
_gnutls_handshake_hash_init (gnutls_session_t session)
{

  if (session->internals.handshake_mac_handle_md5 == NULL)
    {
      session->internals.handshake_mac_handle_md5 =
        _gnutls_hash_init (MHD_GNUTLS_MAC_MD5);

      if (session->internals.handshake_mac_handle_md5 == GNUTLS_HASH_FAILED)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
    }

  if (session->internals.handshake_mac_handle_sha == NULL)
    {
      session->internals.handshake_mac_handle_sha =
        _gnutls_hash_init (MHD_GNUTLS_MAC_SHA1);
      if (session->internals.handshake_mac_handle_sha == GNUTLS_HASH_FAILED)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
    }

  return 0;
}

int
_gnutls_send_supplemental (gnutls_session_t session, int again)
{
  int ret = 0;

  _gnutls_debug_log ("EXT[%x]: Sending supplemental data\n", session);

  if (again)
    ret = _gnutls_send_handshake (session, NULL, 0,
                                  GNUTLS_HANDSHAKE_SUPPLEMENTAL);
  else
    {
      gnutls_buffer buf;
      _gnutls_buffer_init (&buf);

      ret = _gnutls_gen_supplemental (session, &buf);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      ret = _gnutls_send_handshake (session, buf.data, buf.length,
                                    GNUTLS_HANDSHAKE_SUPPLEMENTAL);
      _gnutls_buffer_clear (&buf);
    }

  return ret;
}

int
_gnutls_recv_supplemental (gnutls_session_t session)
{
  uint8_t *data = NULL;
  int datalen = 0;
  int ret;

  _gnutls_debug_log ("EXT[%x]: Expecting supplemental data\n", session);

  ret = _gnutls_recv_handshake (session, &data, &datalen,
                                GNUTLS_HANDSHAKE_SUPPLEMENTAL,
                                OPTIONAL_PACKET);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_parse_supplemental (session, data, datalen);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  gnutls_free (data);

  return ret;
}

/**
  * gnutls_handshake - This is the main function in the handshake protocol.
  * @session: is a #gnutls_session_t structure.
  *
  * This function does the handshake of the TLS/SSL protocol, and
  * initializes the TLS connection.
  *
  * This function will fail if any problem is encountered, and will
  * return a negative error code. In case of a client, if the client
  * has asked to resume a session, but the server couldn't, then a
  * full handshake will be performed.
  *
  * The non-fatal errors such as %GNUTLS_E_AGAIN and
  * %GNUTLS_E_INTERRUPTED interrupt the handshake procedure, which
  * should be later be resumed.  Call this function again, until it
  * returns 0; cf.  gnutls_record_get_direction() and
  * gnutls_error_is_fatal().
  *
  * If this function is called by a server after a rehandshake request
  * then %GNUTLS_E_GOT_APPLICATION_DATA or
  * %GNUTLS_E_WARNING_ALERT_RECEIVED may be returned.  Note that these
  * are non fatal errors, only in the specific case of a rehandshake.
  * Their meaning is that the client rejected the rehandshake request.
  *
  * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
  *
  **/
int
gnutls_handshake (gnutls_session_t session)
{
  int ret;

  if ((ret = _gnutls_handshake_hash_init (session)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      ret = _gnutls_handshake_client (session);
    }
  else
    {
      ret = _gnutls_handshake_server (session);
    }
  if (ret < 0)
    {
      /* In the case of a rehandshake abort
       * we should reset the handshake's internal state.
       */
      if (_gnutls_abort_handshake (session, ret) == 0)
        STATE = STATE0;

      return ret;
    }

  ret = _gnutls_handshake_common (session);

  if (ret < 0)
    {
      if (_gnutls_abort_handshake (session, ret) == 0)
        STATE = STATE0;

      return ret;
    }

  STATE = STATE0;

  _gnutls_handshake_io_buffer_clear (session);
  _gnutls_handshake_internal_state_clear (session);

  return 0;
}

#define IMED_RET( str, ret) do { \
	if (ret < 0) { \
		if (gnutls_error_is_fatal(ret)==0) return ret; \
		gnutls_assert(); \
		ERR( str, ret); \
		_gnutls_handshake_hash_buffers_clear(session); \
		return ret; \
	} } while (0)



/*
 * _gnutls_handshake_client
 * This function performs the client side of the handshake of the TLS/SSL protocol.
 */
int
_gnutls_handshake_client (gnutls_session_t session)
{
  int ret = 0;

#ifdef HANDSHAKE_DEBUG
  char buf[64];

  if (session->internals.resumed_security_parameters.session_id_size > 0)
    _gnutls_handshake_log ("HSK[%x]: Ask to resume: %s\n", session,
                           _gnutls_bin2hex (session->internals.
                                            resumed_security_parameters.
                                            session_id,
                                            session->internals.
                                            resumed_security_parameters.
                                            session_id_size, buf,
                                            sizeof (buf)));
#endif

  switch (STATE)
    {
    case STATE0:
    case STATE1:
      ret = _gnutls_send_hello (session, AGAIN (STATE1));
      STATE = STATE1;
      IMED_RET ("send hello", ret);

    case STATE2:
      /* receive the server hello */
      ret =
        _gnutls_recv_handshake (session, NULL, NULL,
                                GNUTLS_HANDSHAKE_SERVER_HELLO,
                                MANDATORY_PACKET);
      STATE = STATE2;
      IMED_RET ("recv hello", ret);

    case STATE70:
      if (session->security_parameters.extensions.do_recv_supplemental)
        {
          ret = _gnutls_recv_supplemental (session);
          STATE = STATE70;
          IMED_RET ("recv supplemental", ret);
        }

    case STATE3:
      /* RECV CERTIFICATE */
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret = _gnutls_recv_server_certificate (session);
      STATE = STATE3;
      IMED_RET ("recv server certificate", ret);

    case STATE4:
      /* receive the server key exchange */
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret = _gnutls_recv_server_kx_message (session);
      STATE = STATE4;
      IMED_RET ("recv server kx message", ret);

    case STATE5:
      /* receive the server certificate request - if any
       */

      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret = _gnutls_recv_server_certificate_request (session);
      STATE = STATE5;
      IMED_RET ("recv server certificate request message", ret);

    case STATE6:
      /* receive the server hello done */
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret =
          _gnutls_recv_handshake (session, NULL, NULL,
                                  GNUTLS_HANDSHAKE_SERVER_HELLO_DONE,
                                  MANDATORY_PACKET);
      STATE = STATE6;
      IMED_RET ("recv server hello done", ret);

    case STATE71:
      if (session->security_parameters.extensions.do_send_supplemental)
        {
          ret = _gnutls_send_supplemental (session, AGAIN (STATE71));
          STATE = STATE71;
          IMED_RET ("send supplemental", ret);
        }

    case STATE7:
      /* send our certificate - if any and if requested
       */
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret = _gnutls_send_client_certificate (session, AGAIN (STATE7));
      STATE = STATE7;
      IMED_RET ("send client certificate", ret);

    case STATE8:
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret = _gnutls_send_client_kx_message (session, AGAIN (STATE8));
      STATE = STATE8;
      IMED_RET ("send client kx", ret);

    case STATE9:
      /* send client certificate verify */
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret =
          _gnutls_send_client_certificate_verify (session, AGAIN (STATE9));
      STATE = STATE9;
      IMED_RET ("send client certificate verify", ret);

      STATE = STATE0;
    default:
      break;
    }


  return 0;
}

/* This function sends the final handshake packets and initializes connection
 */
static int
_gnutls_send_handshake_final (gnutls_session_t session, int init)
{
  int ret = 0;

  /* Send the CHANGE CIPHER SPEC PACKET */

  switch (STATE)
    {
    case STATE0:
    case STATE20:
      ret = _gnutls_send_change_cipher_spec (session, AGAIN (STATE20));
      STATE = STATE20;
      if (ret < 0)
        {
          ERR ("send ChangeCipherSpec", ret);
          gnutls_assert ();
          return ret;
        }

      /* Initialize the connection session (start encryption) - in case of client
       */
      if (init == TRUE)
        {
          ret = _gnutls_connection_state_init (session);
          if (ret < 0)
            {
              gnutls_assert ();
              return ret;
            }
        }

      ret = _gnutls_write_connection_state_init (session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

    case STATE21:
      /* send the finished message */
      ret = _gnutls_send_finished (session, AGAIN (STATE21));
      STATE = STATE21;
      if (ret < 0)
        {
          ERR ("send Finished", ret);
          gnutls_assert ();
          return ret;
        }

      STATE = STATE0;
    default:
      break;
    }

  return 0;
}

/* This function receives the final handshake packets
 * And executes the appropriate function to initialize the
 * read session.
 */
static int
_gnutls_recv_handshake_final (gnutls_session_t session, int init)
{
  int ret = 0;
  uint8_t ch;

  switch (STATE)
    {
    case STATE0:
    case STATE30:
      ret = _gnutls_recv_int (session, GNUTLS_CHANGE_CIPHER_SPEC, -1, &ch, 1);
      STATE = STATE30;
      if (ret <= 0)
        {
          ERR ("recv ChangeCipherSpec", ret);
          gnutls_assert ();
          return (ret < 0) ? ret : GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        }

      /* Initialize the connection session (start encryption) - in case of server */
      if (init == TRUE)
        {
          ret = _gnutls_connection_state_init (session);
          if (ret < 0)
            {
              gnutls_assert ();
              return ret;
            }
        }

      ret = _gnutls_read_connection_state_init (session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

    case STATE31:
      ret = _gnutls_recv_finished (session);
      STATE = STATE31;
      if (ret < 0)
        {
          ERR ("recv finished", ret);
          gnutls_assert ();
          return ret;
        }
      STATE = STATE0;
    default:
      break;
    }


  return 0;
}

 /*
  * _gnutls_handshake_server
  * This function does the server stuff of the handshake protocol.
  */

int
_gnutls_handshake_server (gnutls_session_t session)
{
  int ret = 0;

  switch (STATE)
    {
    case STATE0:
    case STATE1:
      ret =
        _gnutls_recv_handshake (session, NULL, NULL,
                                GNUTLS_HANDSHAKE_CLIENT_HELLO,
                                MANDATORY_PACKET);
      STATE = STATE1;
      IMED_RET ("recv hello", ret);

    case STATE2:
      ret = _gnutls_send_hello (session, AGAIN (STATE2));
      STATE = STATE2;
      IMED_RET ("send hello", ret);

    case STATE70:
      if (session->security_parameters.extensions.do_send_supplemental)
        {
          ret = _gnutls_send_supplemental (session, AGAIN (STATE70));
          STATE = STATE70;
          IMED_RET ("send supplemental data", ret);
        }

      /* SEND CERTIFICATE + KEYEXCHANGE + CERTIFICATE_REQUEST */
    case STATE3:
      /* NOTE: these should not be send if we are resuming */

      if (session->internals.resumed == RESUME_FALSE)
        ret = _gnutls_send_server_certificate (session, AGAIN (STATE3));
      STATE = STATE3;
      IMED_RET ("send server certificate", ret);

    case STATE4:
      /* send server key exchange (A) */
      if (session->internals.resumed == RESUME_FALSE)
        ret = _gnutls_send_server_kx_message (session, AGAIN (STATE4));
      STATE = STATE4;
      IMED_RET ("send server kx", ret);

    case STATE5:
      /* Send certificate request - if requested to */
      if (session->internals.resumed == RESUME_FALSE)
        ret =
          _gnutls_send_server_certificate_request (session, AGAIN (STATE5));
      STATE = STATE5;
      IMED_RET ("send server cert request", ret);

    case STATE6:
      /* send the server hello done */
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret =
          _gnutls_send_empty_handshake (session,
                                        GNUTLS_HANDSHAKE_SERVER_HELLO_DONE,
                                        AGAIN (STATE6));
      STATE = STATE6;
      IMED_RET ("send server hello done", ret);

    case STATE71:
      if (session->security_parameters.extensions.do_recv_supplemental)
        {
          ret = _gnutls_recv_supplemental (session);
          STATE = STATE71;
          IMED_RET ("recv client supplemental", ret);
        }

      /* RECV CERTIFICATE + KEYEXCHANGE + CERTIFICATE_VERIFY */
    case STATE7:
      /* receive the client certificate message */
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret = _gnutls_recv_client_certificate (session);
      STATE = STATE7;
      IMED_RET ("recv client certificate", ret);

    case STATE8:
      /* receive the client key exchange message */
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret = _gnutls_recv_client_kx_message (session);
      STATE = STATE8;
      IMED_RET ("recv client kx", ret);

    case STATE9:
      /* receive the client certificate verify message */
      if (session->internals.resumed == RESUME_FALSE)   /* if we are not resuming */
        ret = _gnutls_recv_client_certificate_verify_message (session);
      STATE = STATE9;
      IMED_RET ("recv client certificate verify", ret);

      STATE = STATE0;           /* finished thus clear session */
    default:
      break;
    }

  return 0;
}

int
_gnutls_handshake_common (gnutls_session_t session)
{
  int ret = 0;

  /* send and recv the change cipher spec and finished messages */
  if ((session->internals.resumed == RESUME_TRUE
       && session->security_parameters.entity == GNUTLS_CLIENT)
      || (session->internals.resumed == RESUME_FALSE
          && session->security_parameters.entity == GNUTLS_SERVER))
    {
      /* if we are a client resuming - or we are a server not resuming */

      ret = _gnutls_recv_handshake_final (session, TRUE);
      IMED_RET ("recv handshake final", ret);

      ret = _gnutls_send_handshake_final (session, FALSE);
      IMED_RET ("send handshake final", ret);
    }
  else
    {                           /* if we are a client not resuming - or we are a server resuming */

      ret = _gnutls_send_handshake_final (session, TRUE);
      IMED_RET ("send handshake final 2", ret);

      ret = _gnutls_recv_handshake_final (session, FALSE);
      IMED_RET ("recv handshake final 2", ret);
    }

  /* clear handshake buffer */
  _gnutls_handshake_hash_buffers_clear (session);
  return ret;

}

int
_gnutls_generate_session_id (opaque * session_id, uint8_t * len)
{
  *len = TLS_MAX_SESSION_ID_SIZE;

  if (gc_nonce (session_id, *len) != GC_OK)
    {
      gnutls_assert ();
      return GNUTLS_E_RANDOM_FAILED;
    }

  return 0;
}

int
_gnutls_recv_hello_request (gnutls_session_t session, void *data,
                            uint32_t data_size)
{
  uint8_t type;

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET;
    }
  if (data_size < 1)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }
  type = ((uint8_t *) data)[0];
  if (type == GNUTLS_HANDSHAKE_HELLO_REQUEST)
    return GNUTLS_E_REHANDSHAKE;
  else
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET;
    }
}

/* Returns 1 if the given KX has not the corresponding parameters
 * (DH or RSA) set up. Otherwise returns 0.
 */
inline static int
check_server_params (gnutls_session_t session,
                     gnutls_kx_algorithm_t kx,
                     gnutls_kx_algorithm_t * alg, int alg_size)
{
  int cred_type;
  gnutls_dh_params_t dh_params = NULL;
  gnutls_rsa_params_t rsa_params = NULL;
  int j;

  cred_type = _gnutls_map_kx_get_cred (kx, 1);

  /* Read the Diffie Hellman parameters, if any.
   */
  if (cred_type == MHD_GNUTLS_CRD_CERTIFICATE)
    {
      int delete;
      gnutls_certificate_credentials_t x509_cred =
        (gnutls_certificate_credentials_t) _gnutls_get_cred (session->key,
                                                             cred_type, NULL);

      if (x509_cred != NULL)
        {
          dh_params =
            _gnutls_get_dh_params (x509_cred->dh_params,
                                   x509_cred->params_func, session);
          rsa_params =
            _gnutls_certificate_get_rsa_params (x509_cred->rsa_params,
                                                x509_cred->params_func,
                                                session);
        }

      /* Check also if the certificate supports the
       * KX method.
       */
      delete = 1;
      for (j = 0; j < alg_size; j++)
        {
          if (alg[j] == kx)
            {
              delete = 0;
              break;
            }
        }

      if (delete == 1)
        return 1;

#ifdef ENABLE_ANON
    }
  else if (cred_type == MHD_GNUTLS_CRD_ANON)
    {
      gnutls_anon_server_credentials_t anon_cred =
        (gnutls_anon_server_credentials_t) _gnutls_get_cred (session->key,
                                                             cred_type, NULL);

      if (anon_cred != NULL)
        {
          dh_params =
            _gnutls_get_dh_params (anon_cred->dh_params,
                                   anon_cred->params_func, session);
        }
#endif
#ifdef ENABLE_PSK
    }
  else if (cred_type == MHD_GNUTLS_CRD_PSK)
    {
      gnutls_psk_server_credentials_t psk_cred =
        (gnutls_psk_server_credentials_t) _gnutls_get_cred (session->key,
                                                            cred_type, NULL);

      if (psk_cred != NULL)
        {
          dh_params =
            _gnutls_get_dh_params (psk_cred->dh_params, psk_cred->params_func,
                                   session);
        }
#endif
    }
  else
    return 0;                   /* no need for params */


  /* If the key exchange method needs RSA or DH params,
   * but they are not set then remove it.
   */
  if (_gnutls_kx_needs_rsa_params (kx) != 0)
    {
      /* needs rsa params. */
      if (_gnutls_rsa_params_to_mpi (rsa_params) == NULL)
        {
          gnutls_assert ();
          return 1;
        }
    }

  if (_gnutls_kx_needs_dh_params (kx) != 0)
    {
      /* needs DH params. */
      if (_gnutls_dh_params_to_mpi (dh_params) == NULL)
        {
          gnutls_assert ();
          return 1;
        }
    }

  return 0;
}

/* This function will remove algorithms that are not supported by
 * the requested authentication method. We remove an algorithm if
 * we have a certificate with keyUsage bits set.
 *
 * This does a more high level check than  gnutls_supported_ciphersuites(),
 * by checking certificates etc.
 */
int
_gnutls_remove_unwanted_ciphersuites (gnutls_session_t session,
                                      cipher_suite_st ** cipherSuites,
                                      int numCipherSuites,
                                      gnutls_pk_algorithm_t requested_pk_algo)
{

  int ret = 0;
  cipher_suite_st *newSuite, cs;
  int newSuiteSize = 0, i;
  gnutls_certificate_credentials_t cert_cred;
  gnutls_kx_algorithm_t kx;
  int server = session->security_parameters.entity == GNUTLS_SERVER ? 1 : 0;
  gnutls_kx_algorithm_t *alg = NULL;
  int alg_size = 0;

  /* if we should use a specific certificate,
   * we should remove all algorithms that are not supported
   * by that certificate and are on the same authentication
   * method (CERTIFICATE).
   */

  cert_cred =
    (gnutls_certificate_credentials_t) _gnutls_get_cred (session->key,
                                                         MHD_GNUTLS_CRD_CERTIFICATE,
                                                         NULL);

  /* If there are certificate credentials, find an appropriate certificate
   * or disable them;
   */
  if (session->security_parameters.entity == GNUTLS_SERVER
      && cert_cred != NULL)
    {
      ret = _gnutls_server_select_cert (session, requested_pk_algo);
      if (ret < 0)
        {
          gnutls_assert ();
          _gnutls_x509_log ("Could not find an appropriate certificate: %s\n",
                            gnutls_strerror (ret));
          cert_cred = NULL;
        }
    }

  /* get all the key exchange algorithms that are
   * supported by the X509 certificate parameters.
   */
  if ((ret =
       _gnutls_selected_cert_supported_kx (session, &alg, &alg_size)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  newSuite = gnutls_malloc (numCipherSuites * sizeof (cipher_suite_st));
  if (newSuite == NULL)
    {
      gnutls_assert ();
      gnutls_free (alg);
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* now removes ciphersuites based on the KX algorithm
   */
  for (i = 0; i < numCipherSuites; i++)
    {
      int delete = 0;

      /* finds the key exchange algorithm in
       * the ciphersuite
       */
      kx = _gnutls_cipher_suite_get_kx_algo (&(*cipherSuites)[i]);

      /* if it is defined but had no credentials
       */
      if (_gnutls_get_kx_cred (session, kx, NULL) == NULL)
        {
          delete = 1;
        }
      else
        {
          delete = 0;

          if (server)
            delete = check_server_params (session, kx, alg, alg_size);
        }

      /* These two SRP kx's are marked to require a CRD_CERTIFICATE,
         (see cred_mappings in gnutls_algorithms.c), but it also
         requires a SRP credential.  Don't use SRP kx unless we have a
         SRP credential too.  */
      if (kx == MHD_GNUTLS_KX_SRP_RSA || kx == MHD_GNUTLS_KX_SRP_DSS)
        {
          if (!_gnutls_get_cred (session->key, MHD_GNUTLS_CRD_SRP, NULL))
            delete = 1;
        }

      memcpy (&cs.suite, &(*cipherSuites)[i].suite, 2);

      if (delete == 0)
        {

          _gnutls_handshake_log ("HSK[%x]: Keeping ciphersuite: %s\n",
                                 session,
                                 _gnutls_cipher_suite_get_name (&cs));

          memcpy (newSuite[newSuiteSize].suite, (*cipherSuites)[i].suite, 2);
          newSuiteSize++;
        }
      else
        {
          _gnutls_handshake_log ("HSK[%x]: Removing ciphersuite: %s\n",
                                 session,
                                 _gnutls_cipher_suite_get_name (&cs));

        }
    }

  gnutls_free (alg);
  gnutls_free (*cipherSuites);
  *cipherSuites = newSuite;

  ret = newSuiteSize;

  return ret;

}

/**
  * gnutls_handshake_set_max_packet_length - This function will set the maximum length of a handshake message
  * @session: is a #gnutls_session_t structure.
  * @max: is the maximum number.
  *
  * This function will set the maximum size of a handshake message.
  * Handshake messages over this size are rejected.  The default value
  * is 16kb which is large enough. Set this to 0 if you do not want to
  * set an upper limit.
  *
  **/
void
gnutls_handshake_set_max_packet_length (gnutls_session_t session, size_t max)
{
  session->internals.max_handshake_data_buffer_size = max;
}

void
_gnutls_set_adv_version (gnutls_session_t session, gnutls_protocol_t ver)
{
  set_adv_version (session, _gnutls_version_get_major (ver),
                   _gnutls_version_get_minor (ver));
}

gnutls_protocol_t
_gnutls_get_adv_version (gnutls_session_t session)
{
  return _gnutls_version_get (_gnutls_get_adv_version_major (session),
                              _gnutls_get_adv_version_minor (session));
}

/**
  * gnutls_handshake_get_last_in - Returns the last handshake message received.
  * @session: is a #gnutls_session_t structure.
  *
  * This function is only useful to check where the last performed
  * handshake failed.  If the previous handshake succeed or was not
  * performed at all then no meaningful value will be returned.
  *
  * Check %gnutls_handshake_description_t in gnutls.h for the
  * available handshake descriptions.
  *
  * Returns: the last handshake message type received, a
  * %gnutls_handshake_description_t.
  **/
gnutls_handshake_description_t
gnutls_handshake_get_last_in (gnutls_session_t session)
{
  return session->internals.last_handshake_in;
}

/**
  * gnutls_handshake_get_last_out - Returns the last handshake message sent.
  * @session: is a #gnutls_session_t structure.
  *
  * This function is only useful to check where the last performed
  * handshake failed.  If the previous handshake succeed or was not
  * performed at all then no meaningful value will be returned.
  *
  * Check %gnutls_handshake_description_t in gnutls.h for the
  * available handshake descriptions.
  *
  * Returns: the last handshake message type sent, a
  * %gnutls_handshake_description_t.
  **/
gnutls_handshake_description_t
gnutls_handshake_get_last_out (gnutls_session_t session)
{
  return session->internals.last_handshake_out;
}
