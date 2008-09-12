/*
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
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

/* Functions to manipulate the session (gnutls_int.h), and some other stuff
 * are included here. The file's name is traditionally gnutls_state even if the
 * state has been renamed to session.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_auth_int.h>
#include <gnutls_num.h>
#include <gnutls_datum.h>
#include <gnutls_record.h>
#include <gnutls_handshake.h>
#include <gnutls_dh.h>
#include <gnutls_buffers.h>
#include <gnutls_state.h>
#include <auth_cert.h>
#include <auth_anon.h>
#include <gnutls_algorithms.h>
#include <gnutls_rsa_export.h>

void
_gnutls_session_cert_type_set (mhd_gtls_session_t session,
                               enum MHD_GNUTLS_CertificateType ct)
{
  session->security_parameters.cert_type = ct;
}

/**
 * gnutls_cipher_get - Returns the currently used cipher.
 * @session: is a #mhd_gtls_session_t structure.
 *
 * Returns: the currently used cipher.
 **/
enum MHD_GNUTLS_CipherAlgorithm
gnutls_cipher_get (mhd_gtls_session_t session)
{
  return session->security_parameters.read_bulk_cipher_algorithm;
}

/**
 * gnutls_certificate_type_get - Returns the currently used certificate type.
 * @session: is a #mhd_gtls_session_t structure.
 *
 * The certificate type is by default X.509, unless it is negotiated
 * as a TLS extension.
 *
 * Returns: the currently used %enum MHD_GNUTLS_CertificateType certificate
 *   type.
 **/
enum MHD_GNUTLS_CertificateType
gnutls_certificate_type_get (mhd_gtls_session_t session)
{
  return session->security_parameters.cert_type;
}

/**
 * gnutls_kx_get - Returns the key exchange algorithm.
 * @session: is a #mhd_gtls_session_t structure.
 *
 * Returns: the key exchange algorithm used in the last handshake.
 **/
enum MHD_GNUTLS_KeyExchangeAlgorithm
gnutls_kx_get (mhd_gtls_session_t session)
{
  return session->security_parameters.kx_algorithm;
}

/**
 * gnutls_mac_get - Returns the currently used mac algorithm.
 * @session: is a #mhd_gtls_session_t structure.
 *
 * Returns: the currently used mac algorithm.
 **/
enum MHD_GNUTLS_HashAlgorithm
gnutls_mac_get (mhd_gtls_session_t session)
{
  return session->security_parameters.read_mac_algorithm;
}

/**
 * gnutls_compression_get - Returns the currently used compression algorithm.
 * @session: is a #mhd_gtls_session_t structure.
 *
 * Returns: the currently used compression method.
 **/
enum MHD_GNUTLS_CompressionMethod
MHD_gtls_compression_get (mhd_gtls_session_t session)
{
  return session->security_parameters.read_compression_algorithm;
}

/* Check if the given certificate type is supported.
 * This means that it is enabled by the priority functions,
 * and a matching certificate exists.
 */
int
mhd_gtls_session_cert_type_supported (mhd_gtls_session_t session,
                                      enum MHD_GNUTLS_CertificateType
                                      cert_type)
{
  unsigned i;
  unsigned cert_found = 0;
  mhd_gtls_cert_credentials_t cred;

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      cred
        = (mhd_gtls_cert_credentials_t) mhd_gtls_get_cred (session->key,
                                                           MHD_GNUTLS_CRD_CERTIFICATE,
                                                           NULL);

      if (cred == NULL)
        return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;

      if (cred->server_get_cert_callback == NULL)
        {
          for (i = 0; i < cred->ncerts; i++)
            {
              if (cred->cert_list[i][0].cert_type == cert_type)
                {
                  cert_found = 1;
                  break;
                }
            }

          if (cert_found == 0)
            /* no certificate is of that type.
             */
            return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
        }
    }

  if (session->internals.priorities.cert_type.num_algorithms == 0 && cert_type
      == DEFAULT_CERT_TYPE)
    return 0;

  for (i = 0; i < session->internals.priorities.cert_type.num_algorithms; i++)
    {
      if (session->internals.priorities.cert_type.priority[i] == cert_type)
        {
          return 0;             /* ok */
        }
    }

  return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
}

/* this function deinitializes all the internal parameters stored
 * in a session struct.
 */
inline static void
deinit_internal_params (mhd_gtls_session_t session)
{
  if (session->internals.params.free_dh_params)
    MHD_gnutls_dh_params_deinit (session->internals.params.dh_params);

  if (session->internals.params.free_rsa_params)
    MHD_gnutls_rsa_params_deinit (session->internals.params.rsa_params);

  memset (&session->internals.params, 0, sizeof (session->internals.params));
}

/* This function will clear all the variables in internals
 * structure within the session, which depend on the current handshake.
 * This is used to allow further handshakes.
 */
void
mhd_gtls_handshake_internal_state_clear (mhd_gtls_session_t session)
{
  session->internals.extensions_sent_size = 0;

  /* by default no selected certificate */
  session->internals.proposed_record_size = DEFAULT_MAX_RECORD_SIZE;
  session->internals.adv_version_major = 0;
  session->internals.adv_version_minor = 0;
  session->internals.v2_hello = 0;
  memset (&session->internals.handshake_header_buffer, 0,
          sizeof (mhd_gtls_handshake_header_buffer_st));
  session->internals.adv_version_minor = 0;
  session->internals.adv_version_minor = 0;
  session->internals.direction = 0;

  /* use out of band data for the last
   * handshake messages received.
   */
  session->internals.last_handshake_in = -1;
  session->internals.last_handshake_out = -1;

  session->internals.resumable = RESUME_TRUE;
  _gnutls_free_datum (&session->internals.recv_buffer);

  deinit_internal_params (session);

}

#define MIN_DH_BITS 727
/**
 * MHD_gnutls_init - This function initializes the session to null (null encryption etc...).
 * @con_end: indicate if this session is to be used for server or client.
 * @session: is a pointer to a #mhd_gtls_session_t structure.
 *
 * This function initializes the current session to null. Every
 * session must be initialized before use, so internal structures can
 * be allocated.  This function allocates structures which can only
 * be free'd by calling MHD_gnutls_deinit().  Returns zero on success.
 *
 * @con_end can be one of %GNUTLS_CLIENT and %GNUTLS_SERVER.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/

/* TODO rm redundent pointer ref */
int
MHD_gnutls_init (mhd_gtls_session_t * session,
                 gnutls_connection_end_t con_end)
{
  *session = gnutls_calloc (1, sizeof (struct MHD_gtls_session_int));
  if (*session == NULL)
    return GNUTLS_E_MEMORY_ERROR;

  (*session)->security_parameters.entity = con_end;

  /* the default certificate type for TLS */
  (*session)->security_parameters.cert_type = DEFAULT_CERT_TYPE;

  /* Set the defaults for initial handshake */
  (*session)->security_parameters.read_bulk_cipher_algorithm =
    (*session)->security_parameters.write_bulk_cipher_algorithm =
    MHD_GNUTLS_CIPHER_NULL;

  (*session)->security_parameters.read_mac_algorithm =
    (*session)->security_parameters.write_mac_algorithm = MHD_GNUTLS_MAC_NULL;

  (*session)->security_parameters.read_compression_algorithm
    = MHD_GNUTLS_COMP_NULL;
  (*session)->security_parameters.write_compression_algorithm
    = MHD_GNUTLS_COMP_NULL;

  (*session)->internals.enable_private = 0;

  /* Initialize buffers */
  mhd_gtls_buffer_init (&(*session)->internals.application_data_buffer);
  mhd_gtls_buffer_init (&(*session)->internals.handshake_data_buffer);
  mhd_gtls_buffer_init (&(*session)->internals.handshake_hash_buffer);
  mhd_gtls_buffer_init (&(*session)->internals.ia_data_buffer);

  mhd_gtls_buffer_init (&(*session)->internals.record_send_buffer);
  mhd_gtls_buffer_init (&(*session)->internals.record_recv_buffer);

  mhd_gtls_buffer_init (&(*session)->internals.handshake_send_buffer);
  mhd_gtls_buffer_init (&(*session)->internals.handshake_recv_buffer);

  (*session)->key = gnutls_calloc (1, sizeof (struct mhd_gtls_key));
  if ((*session)->key == NULL)
    {
    cleanup_session:gnutls_free (*session);
      *session = NULL;
      return GNUTLS_E_MEMORY_ERROR;
    }

  (*session)->internals.expire_time = DEFAULT_EXPIRE_TIME;      /* one hour default */

  MHD_gnutls_dh_set_prime_bits ((*session), MIN_DH_BITS);

  MHD_gnutls_transport_set_lowat ((*session), DEFAULT_LOWAT);   /* the default for tcp */

  MHD_gnutls_handshake_set_max_packet_length ((*session),
                                              MAX_HANDSHAKE_PACKET_SIZE);

  /* Allocate a minimum size for recv_data
   * This is allocated in order to avoid small messages, making
   * the receive procedure slow.
   */
  (*session)->internals.record_recv_buffer.data
    = gnutls_malloc (INITIAL_RECV_BUFFER_SIZE);
  if ((*session)->internals.record_recv_buffer.data == NULL)
    {
      gnutls_free ((*session)->key);
      goto cleanup_session;
    }

  /* set the socket pointers to -1; */
  (*session)->internals.transport_recv_ptr = (gnutls_transport_ptr_t) - 1;
  (*session)->internals.transport_send_ptr = (gnutls_transport_ptr_t) - 1;

  /* set the default maximum record size for TLS
   */
  (*session)->security_parameters.max_record_recv_size
    = DEFAULT_MAX_RECORD_SIZE;
  (*session)->security_parameters.max_record_send_size
    = DEFAULT_MAX_RECORD_SIZE;

  /* everything else not initialized here is initialized
   * as NULL or 0. This is why calloc is used.
   */

  mhd_gtls_handshake_internal_state_clear (*session);

  return 0;
}

/* returns RESUME_FALSE or RESUME_TRUE.
 */
int
mhd_gtls_session_is_resumable (mhd_gtls_session_t session)
{
  return session->internals.resumable;
}

/**
 * MHD_gnutls_deinit - This function clears all buffers associated with a session
 * @session: is a #mhd_gtls_session_t structure.
 *
 * This function clears all buffers associated with the @session.
 * This function will also remove session data from the session
 * database if the session was terminated abnormally.
 **/
void
MHD_gnutls_deinit (mhd_gtls_session_t session)
{

  if (session == NULL)
    return;

  /* remove auth info firstly */
  mhd_gtls_free_auth_info (session);

  mhd_gtls_handshake_internal_state_clear (session);
  _gnutls_handshake_io_buffer_clear (session);

  _gnutls_free_datum (&session->connection_state.read_mac_secret);
  _gnutls_free_datum (&session->connection_state.write_mac_secret);

  mhd_gtls_buffer_clear (&session->internals.ia_data_buffer);
  mhd_gtls_buffer_clear (&session->internals.handshake_hash_buffer);
  mhd_gtls_buffer_clear (&session->internals.handshake_data_buffer);
  mhd_gtls_buffer_clear (&session->internals.application_data_buffer);
  mhd_gtls_buffer_clear (&session->internals.record_recv_buffer);
  mhd_gtls_buffer_clear (&session->internals.record_send_buffer);

  MHD_gnutls_credentials_clear (session);
  mhd_gtls_selected_certs_deinit (session);

  if (session->connection_state.read_cipher_state != NULL)
    mhd_gnutls_cipher_deinit (session->connection_state.read_cipher_state);
  if (session->connection_state.write_cipher_state != NULL)
    mhd_gnutls_cipher_deinit (session->connection_state.write_cipher_state);

  if (session->connection_state.read_compression_state != NULL)
    mhd_gtls_comp_deinit (session->connection_state.read_compression_state,
                          1);
  if (session->connection_state.write_compression_state != NULL)
    mhd_gtls_comp_deinit (session->connection_state.write_compression_state,
                          0);

  _gnutls_free_datum (&session->cipher_specs.server_write_mac_secret);
  _gnutls_free_datum (&session->cipher_specs.client_write_mac_secret);
  _gnutls_free_datum (&session->cipher_specs.server_write_IV);
  _gnutls_free_datum (&session->cipher_specs.client_write_IV);
  _gnutls_free_datum (&session->cipher_specs.server_write_key);
  _gnutls_free_datum (&session->cipher_specs.client_write_key);

  if (session->key != NULL)
    {
      mhd_gtls_mpi_release (&session->key->KEY);
      mhd_gtls_mpi_release (&session->key->client_Y);
      mhd_gtls_mpi_release (&session->key->client_p);
      mhd_gtls_mpi_release (&session->key->client_g);

      mhd_gtls_mpi_release (&session->key->u);
      mhd_gtls_mpi_release (&session->key->a);
      mhd_gtls_mpi_release (&session->key->x);
      mhd_gtls_mpi_release (&session->key->A);
      mhd_gtls_mpi_release (&session->key->B);
      mhd_gtls_mpi_release (&session->key->b);

      /* RSA */
      mhd_gtls_mpi_release (&session->key->rsa[0]);
      mhd_gtls_mpi_release (&session->key->rsa[1]);

      mhd_gtls_mpi_release (&session->key->dh_secret);
      gnutls_free (session->key);

      session->key = NULL;
    }

  gnutls_free (session->internals.srp_username);

  if (session->internals.srp_password)
    {
      memset (session->internals.srp_password, 0,
              strlen (session->internals.srp_password));
      gnutls_free (session->internals.srp_password);
    }

  memset (session, 0, sizeof (struct MHD_gtls_session_int));
  gnutls_free (session);
}

/* Returns the minimum prime bits that are acceptable.
 */
int
mhd_gtls_dh_get_allowed_prime_bits (mhd_gtls_session_t session)
{
  return session->internals.dh_prime_bits;
}

int
mhd_gtls_dh_set_peer_public (mhd_gtls_session_t session, mpi_t public)
{
  mhd_gtls_dh_info_st *dh;
  int ret;

  switch (MHD_gtls_auth_get_type (session))
    {
    case MHD_GNUTLS_CRD_ANON:
      {
        mhd_anon_auth_info_t info;
        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;

        dh = &info->dh;
        break;
      }
    case MHD_GNUTLS_CRD_CERTIFICATE:
      {
        cert_auth_info_t info;

        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;

        dh = &info->dh;
        break;
      }
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ret = mhd_gtls_mpi_dprint_lz (&dh->public_key, public);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}

int
mhd_gtls_dh_set_secret_bits (mhd_gtls_session_t session, unsigned bits)
{
  switch (MHD_gtls_auth_get_type (session))
    {
    case MHD_GNUTLS_CRD_ANON:
      {
        mhd_anon_auth_info_t info;
        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;
        info->dh.secret_bits = bits;
        break;
      }
    case MHD_GNUTLS_CRD_CERTIFICATE:
      {
        cert_auth_info_t info;

        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;

        info->dh.secret_bits = bits;
        break;
    default:
        gnutls_assert ();
        return GNUTLS_E_INTERNAL_ERROR;
      }
    }

  return 0;
}

/* This function will set in the auth info structure the
 * RSA exponent and the modulus.
 */
int
mhd_gtls_rsa_export_set_pubkey (mhd_gtls_session_t session,
                                mpi_t exponent, mpi_t modulus)
{
  cert_auth_info_t info;
  int ret;

  info = mhd_gtls_get_auth_info (session);
  if (info == NULL)
    return GNUTLS_E_INTERNAL_ERROR;

  ret = mhd_gtls_mpi_dprint_lz (&info->rsa_export.modulus, modulus);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = mhd_gtls_mpi_dprint_lz (&info->rsa_export.exponent, exponent);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (&info->rsa_export.modulus);
      return ret;
    }

  return 0;
}

/* Sets the prime and the generator in the auth info structure.
 */
int
mhd_gtls_dh_set_group (mhd_gtls_session_t session, mpi_t gen, mpi_t prime)
{
  mhd_gtls_dh_info_st *dh;
  int ret;

  switch (MHD_gtls_auth_get_type (session))
    {
    case MHD_GNUTLS_CRD_ANON:
      {
        mhd_anon_auth_info_t info;
        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;

        dh = &info->dh;
        break;
      }
    case MHD_GNUTLS_CRD_CERTIFICATE:
      {
        cert_auth_info_t info;

        info = mhd_gtls_get_auth_info (session);
        if (info == NULL)
          return GNUTLS_E_INTERNAL_ERROR;

        dh = &info->dh;
        break;
      }
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* prime
   */
  ret = mhd_gtls_mpi_dprint_lz (&dh->prime, prime);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* generator
   */
  ret = mhd_gtls_mpi_dprint_lz (&dh->generator, gen);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (&dh->prime);
      return ret;
    }

  return 0;
}

/**
 * MHD_gnutls_certificate_send_x509_rdn_sequence - This function will order gnutls to send or not the x.509 rdn sequence
 * @session: is a pointer to a #mhd_gtls_session_t structure.
 * @status: is 0 or 1
 *
 * If status is non zero, this function will order gnutls not to send
 * the rdnSequence in the certificate request message. That is the
 * server will not advertize it's trusted CAs to the peer. If status
 * is zero then the default behaviour will take effect, which is to
 * advertize the server's trusted CAs.
 *
 * This function has no effect in clients, and in authentication
 * methods other than certificate with X.509 certificates.
 **/
void
MHD_gnutls_certificate_send_x509_rdn_sequence (mhd_gtls_session_t session,
                                               int status)
{
  session->internals.ignore_rdn_sequence = status;
}

/*-
 * _gnutls_record_set_default_version - Used to set the default version for the first record packet
 * @session: is a #mhd_gtls_session_t structure.
 * @major: is a tls major version
 * @minor: is a tls minor version
 *
 * This function sets the default version that we will use in the first
 * record packet (client hello). This function is only useful to people
 * that know TLS internals and want to debug other implementations.
 *
 -*/
void
_gnutls_record_set_default_version (mhd_gtls_session_t session,
                                    unsigned char major, unsigned char minor)
{
  session->internals.default_record_version[0] = major;
  session->internals.default_record_version[1] = minor;
}

/**
 * MHD_gtls_handshake_set_private_extensions - Used to enable the private cipher suites
 * @session: is a #mhd_gtls_session_t structure.
 * @allow: is an integer (0 or 1)
 *
 * This function will enable or disable the use of private cipher
 * suites (the ones that start with 0xFF).  By default or if @allow
 * is 0 then these cipher suites will not be advertized nor used.
 *
 * Unless this function is called with the option to allow (1), then
 * no compression algorithms, like LZO.  That is because these
 * algorithms are not yet defined in any RFC or even internet draft.
 *
 * Enabling the private ciphersuites when talking to other than
 * gnutls servers and clients may cause interoperability problems.
 **/
void
MHD_gtls_handshake_set_private_extensions (mhd_gtls_session_t session,
                                           int allow)
{
  session->internals.enable_private = allow;
}

inline static int
_gnutls_cal_PRF_A (enum MHD_GNUTLS_HashAlgorithm algorithm,
                   const void *secret,
                   int secret_size,
                   const void *seed, int seed_size, void *result)
{
  mac_hd_t td1;

  td1 = mhd_gtls_hmac_init (algorithm, secret, secret_size);
  if (td1 == GNUTLS_MAC_FAILED)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  mhd_gnutls_hash (td1, seed, seed_size);
  mhd_gnutls_hmac_deinit (td1, result);

  return 0;
}

#define MAX_SEED_SIZE 200

/* Produces "total_bytes" bytes using the hash algorithm specified.
 * (used in the PRF function)
 */
static int
_gnutls_P_hash (enum MHD_GNUTLS_HashAlgorithm algorithm,
                const opaque * secret,
                int secret_size,
                const opaque * seed,
                int seed_size, int total_bytes, opaque * ret)
{

  mac_hd_t td2;
  int i, times, how, blocksize, A_size;
  opaque final[20], Atmp[MAX_SEED_SIZE];
  int output_bytes, result;

  if (seed_size > MAX_SEED_SIZE || total_bytes <= 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  blocksize = mhd_gnutls_hash_get_algo_len (algorithm);

  output_bytes = 0;
  do
    {
      output_bytes += blocksize;
    }
  while (output_bytes < total_bytes);

  /* calculate A(0) */

  memcpy (Atmp, seed, seed_size);
  A_size = seed_size;

  times = output_bytes / blocksize;

  for (i = 0; i < times; i++)
    {
      td2 = mhd_gtls_hmac_init (algorithm, secret, secret_size);
      if (td2 == GNUTLS_MAC_FAILED)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }

      /* here we calculate A(i+1) */
      if ((result = _gnutls_cal_PRF_A (algorithm, secret, secret_size, Atmp,
                                       A_size, Atmp)) < 0)
        {
          gnutls_assert ();
          mhd_gnutls_hmac_deinit (td2, final);
          return result;
        }

      A_size = blocksize;

      mhd_gnutls_hash (td2, Atmp, A_size);
      mhd_gnutls_hash (td2, seed, seed_size);
      mhd_gnutls_hmac_deinit (td2, final);

      if ((1 + i) * blocksize < total_bytes)
        {
          how = blocksize;
        }
      else
        {
          how = total_bytes - (i) * blocksize;
        }

      if (how > 0)
        {
          memcpy (&ret[i * blocksize], final, how);
        }
    }

  return 0;
}

/* Xor's two buffers and puts the output in the first one.
 */
inline static void
_gnutls_xor (opaque * o1, opaque * o2, int length)
{
  int i;
  for (i = 0; i < length; i++)
    {
      o1[i] ^= o2[i];
    }
}

#define MAX_PRF_BYTES 200

/* The PRF function expands a given secret
 * needed by the TLS specification. ret must have a least total_bytes
 * available.
 */
int
mhd_gtls_PRF (mhd_gtls_session_t session,
              const opaque * secret,
              int secret_size,
              const char *label,
              int label_size,
              const opaque * seed, int seed_size, int total_bytes, void *ret)
{
  int l_s, s_seed_size;
  const opaque *s1, *s2;
  opaque s_seed[MAX_SEED_SIZE];
  opaque o1[MAX_PRF_BYTES], o2[MAX_PRF_BYTES];
  int result;
  enum MHD_GNUTLS_Protocol ver = MHD_gnutls_protocol_get_version (session);

  if (total_bytes > MAX_PRF_BYTES)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }
  /* label+seed = s_seed */
  s_seed_size = seed_size + label_size;

  if (s_seed_size > MAX_SEED_SIZE)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  memcpy (s_seed, label, label_size);
  memcpy (&s_seed[label_size], seed, seed_size);

  if (ver >= MHD_GNUTLS_PROTOCOL_TLS1_2)
    {
      result =
        _gnutls_P_hash (MHD_GNUTLS_MAC_SHA1, secret, secret_size, s_seed,
                        s_seed_size, total_bytes, ret);
      if (result < 0)
        {
          gnutls_assert ();
          return result;
        }
    }
  else
    {
      l_s = secret_size / 2;

      s1 = &secret[0];
      s2 = &secret[l_s];

      if (secret_size % 2 != 0)
        {
          l_s++;
        }

      result =
        _gnutls_P_hash (MHD_GNUTLS_MAC_MD5, s1, l_s, s_seed, s_seed_size,
                        total_bytes, o1);
      if (result < 0)
        {
          gnutls_assert ();
          return result;
        }

      result =
        _gnutls_P_hash (MHD_GNUTLS_MAC_SHA1, s2, l_s, s_seed, s_seed_size,
                        total_bytes, o2);
      if (result < 0)
        {
          gnutls_assert ();
          return result;
        }

      _gnutls_xor (o1, o2, total_bytes);

      memcpy (ret, o1, total_bytes);
    }

  return 0;                     /* ok */

}

/**
 * MHD_gnutls_prf_raw - access the TLS PRF directly
 * @session: is a #mhd_gtls_session_t structure.
 * @label_size: length of the @label variable.
 * @label: label used in PRF computation, typically a short string.
 * @seed_size: length of the @seed variable.
 * @seed: optional extra data to seed the PRF with.
 * @outsize: size of pre-allocated output buffer to hold the output.
 * @out: pre-allocate buffer to hold the generated data.
 *
 * Apply the TLS Pseudo-Random-Function (PRF) using the master secret
 * on some data.
 *
 * The @label variable usually contain a string denoting the purpose
 * for the generated data.  The @seed usually contain data such as the
 * client and server random, perhaps together with some additional
 * data that is added to guarantee uniqueness of the output for a
 * particular purpose.
 *
 * Because the output is not guaranteed to be unique for a particular
 * session unless @seed include the client random and server random
 * fields (the PRF would output the same data on another connection
 * resumed from the first one), it is not recommended to use this
 * function directly.  The MHD_gnutls_prf() function seed the PRF with the
 * client and server random fields directly, and is recommended if you
 * want to generate pseudo random data unique for each session.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
MHD_gnutls_prf_raw (mhd_gtls_session_t session,
                    size_t label_size,
                    const char *label,
                    size_t seed_size, const char *seed, size_t outsize,
                    char *out)
{
  int ret;

  ret = mhd_gtls_PRF (session, session->security_parameters.master_secret,
                      TLS_MASTER_SIZE, label, label_size, (opaque *) seed,
                      seed_size, outsize, out);

  return ret;
}

/**
 * MHD_gnutls_prf - derive pseudo-random data using the TLS PRF
 * @session: is a #mhd_gtls_session_t structure.
 * @label_size: length of the @label variable.
 * @label: label used in PRF computation, typically a short string.
 * @server_random_first: non-0 if server random field should be first in seed
 * @extra_size: length of the @extra variable.
 * @extra: optional extra data to seed the PRF with.
 * @outsize: size of pre-allocated output buffer to hold the output.
 * @out: pre-allocate buffer to hold the generated data.
 *
 * Apply the TLS Pseudo-Random-Function (PRF) using the master secret
 * on some data, seeded with the client and server random fields.
 *
 * The @label variable usually contain a string denoting the purpose
 * for the generated data.  The @server_random_first indicate whether
 * the client random field or the server random field should be first
 * in the seed.  Non-0 indicate that the server random field is first,
 * 0 that the client random field is first.
 *
 * The @extra variable can be used to add more data to the seed, after
 * the random variables.  It can be used to tie make sure the
 * generated output is strongly connected to some additional data
 * (e.g., a string used in user authentication).
 *
 * The output is placed in *@OUT, which must be pre-allocated.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, or an error code.
 **/
int
MHD_gnutls_prf (mhd_gtls_session_t session,
                size_t label_size,
                const char *label,
                int server_random_first,
                size_t extra_size, const char *extra, size_t outsize,
                char *out)
{
  int ret;
  opaque *seed;
  size_t seedsize = 2 * TLS_RANDOM_SIZE + extra_size;

  seed = gnutls_malloc (seedsize);
  if (!seed)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  memcpy (seed,
          server_random_first ? session->security_parameters.server_random
          : session->security_parameters.client_random, TLS_RANDOM_SIZE);
  memcpy (seed + TLS_RANDOM_SIZE,
          server_random_first ? session->security_parameters.client_random
          : session->security_parameters.server_random, TLS_RANDOM_SIZE);

  memcpy (seed + 2 * TLS_RANDOM_SIZE, extra, extra_size);

  ret = mhd_gtls_PRF (session, session->security_parameters.master_secret,
                      TLS_MASTER_SIZE, label, label_size, seed, seedsize,
                      outsize, out);

  gnutls_free (seed);

  return ret;
}

/**
 * MHD_gtls_session_get_client_random - get the session's client random value
 * @session: is a #mhd_gtls_session_t structure.
 *
 * Return a pointer to the 32-byte client random field used in the
 * session.  The pointer must not be modified or deallocated.
 *
 * If a client random value has not yet been established, the output
 * will be garbage; in particular, a %NULL return value should not be
 * expected.
 *
 * Returns: pointer to client random data.
 **/
const void *
MHD_gtls_session_get_client_random (mhd_gtls_session_t session)
{
  return (char *) session->security_parameters.client_random;
}

/**
 * MHD_gtls_session_get_server_random - get the session's server random value
 * @session: is a #mhd_gtls_session_t structure.
 *
 * Return a pointer to the 32-byte server random field used in the
 * session.  The pointer must not be modified or deallocated.
 *
 * If a server random value has not yet been established, the output
 * will be garbage; in particular, a %NULL return value should not be
 * expected.
 *
 * Returns: pointer to server random data.
 **/
const void *
MHD_gtls_session_get_server_random (mhd_gtls_session_t session)
{
  return (char *) session->security_parameters.server_random;
}

/**
 * MHD_gtls_session_get_master_secret - get the session's master secret value
 * @session: is a #mhd_gtls_session_t structure.
 *
 * Return a pointer to the 48-byte master secret in the session.  The
 * pointer must not be modified or deallocated.
 *
 * If a master secret value has not yet been established, the output
 * will be garbage; in particular, a %NULL return value should not be
 * expected.
 *
 * Consider using MHD_gnutls_prf() rather than extracting the master
 * secret and use it to derive further data.
 *
 * Returns: pointer to master secret data.
 **/
const void *
MHD_gtls_session_get_master_secret (mhd_gtls_session_t session)
{
  return (char *) session->security_parameters.master_secret;
}

/**
 * MHD_gtls_session_is_resumed - Used to check whether this session is a resumed one
 * @session: is a #mhd_gtls_session_t structure.
 *
 * Returns: non zero if this session is resumed, or a zero if this is
 * a new session.
 **/
int
MHD_gtls_session_is_resumed (mhd_gtls_session_t session)
{
#if MHD_DEBUG_TLS
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      if (session->security_parameters.session_id_size > 0
          && session->security_parameters.session_id_size
          == session->internals.resumed_security_parameters.session_id_size
          && memcmp (session->security_parameters.session_id,
                     session->internals.resumed_security_parameters.
                     session_id,
                     session->security_parameters.session_id_size) == 0)
        return 1;
    }
  else
#endif
    {
      if (session->internals.resumed == RESUME_TRUE)
        return 1;
    }

  return 0;
}

/*-
 * mhd_gtls_session_is_export - Used to check whether this session is of export grade
 * @session: is a #mhd_gtls_session_t structure.
 *
 * This function will return non zero if this session is of export grade.
 *
 -*/
int
mhd_gtls_session_is_export (mhd_gtls_session_t session)
{
  enum MHD_GNUTLS_CipherAlgorithm cipher;

  cipher =
    mhd_gtls_cipher_suite_get_cipher_algo (&session->security_parameters.
                                           current_cipher_suite);

  if (mhd_gtls_cipher_get_export_flag (cipher) != 0)
    return 1;

  return 0;
}

/**
 * MHD_gtls_session_get_ptr - Used to get the user pointer from the session structure
 * @session: is a #mhd_gtls_session_t structure.
 *
 * Returns: the user given pointer from the session structure.  This
 * is the pointer set with MHD_gnutls_session_set_ptr().
 **/
void *
MHD_gtls_session_get_ptr (mhd_gtls_session_t session)
{
  return session->internals.user_ptr;
}

/**
 * MHD_gnutls_session_set_ptr - Used to set the user pointer to the session structure
 * @session: is a #mhd_gtls_session_t structure.
 * @ptr: is the user pointer
 *
 * This function will set (associate) the user given pointer to the
 * session structure.  This is pointer can be accessed with
 * MHD_gtls_session_get_ptr().
 **/
void
MHD_gnutls_session_set_ptr (mhd_gtls_session_t session, void *ptr)
{
  session->internals.user_ptr = ptr;
}

/**
 * MHD_gnutls_record_get_direction - This function will return the direction of the last interrupted function call
 * @session: is a #mhd_gtls_session_t structure.
 *
 * This function provides information about the internals of the
 * record protocol and is only useful if a prior gnutls function call
 * (e.g.  MHD_gnutls_handshake()) was interrupted for some reason, that
 * is, if a function returned %GNUTLS_E_INTERRUPTED or
 * %GNUTLS_E_AGAIN.  In such a case, you might want to call select()
 * or poll() before calling the interrupted gnutls function again.
 * To tell you whether a file descriptor should be selected for
 * either reading or writing, MHD_gnutls_record_get_direction() returns 0
 * if the interrupted function was trying to read data, and 1 if it
 * was trying to write data.
 *
 * Returns: 0 if trying to read data, 1 if trying to write data.
 **/
int
MHD_gnutls_record_get_direction (mhd_gtls_session_t session)
{
  return session->internals.direction;
}

/*-
 * _gnutls_rsa_pms_set_version - Sets a version to be used at the RSA PMS
 * @session: is a #mhd_gtls_session_t structure.
 * @major: is the major version to use
 * @minor: is the minor version to use
 *
 * This function will set the given version number to be used at the
 * RSA PMS secret. This is only useful to clients, which want to
 * test server's capabilities.
 *
 -*/
void
_gnutls_rsa_pms_set_version (mhd_gtls_session_t session,
                             unsigned char major, unsigned char minor)
{
  session->internals.rsa_pms_version[0] = major;
  session->internals.rsa_pms_version[1] = minor;
}

/**
 * MHD_gnutls_handshake_set_post_client_hello_function - This function will a callback to be called after the client hello is received
 * @res: is a mhd_gtls_anon_server_credentials_t structure
 * @func: is the function to be called
 *
 * This function will set a callback to be called after the client
 * hello has been received (callback valid in server side only). This
 * allows the server to adjust settings based on received extensions.
 *
 * Those settings could be ciphersuites, requesting certificate, or
 * anything else except for version negotiation (this is done before
 * the hello message is parsed).
 *
 * This callback must return 0 on success or a gnutls error code to
 * terminate the handshake.
 *
 * NOTE: You should not use this function to terminate the handshake
 * based on client input unless you know what you are doing. Before
 * the handshake is finished there is no way to know if there is a
 * man-in-the-middle attack being performed.
 *
 **/
void
MHD_gnutls_handshake_set_post_client_hello_function (mhd_gtls_session_t
                                                     session,
                                                     gnutls_handshake_post_client_hello_func
                                                     func)
{
  session->internals.user_hello_func = func;
}
