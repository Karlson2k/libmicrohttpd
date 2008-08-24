/* -*- c -*-
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 *
 */

/* This file contains the types and prototypes for all the
 * high level functionality of gnutls main library. For the
 * extra functionality (which is under the GNU GPL license) check
 * the gnutls/extra.h header. The openssl compatibility layer is
 * in gnutls/openssl.h.
 *
 * The low level cipher functionality is in libgcrypt. Check
 * gcrypt.h
 */

#ifndef GNUTLS_H
#define GNUTLS_H

#ifdef __cplusplus
extern "C"
{
#endif

#define LIBGNUTLS_VERSION "2.2.3"

/* Get size_t. */
#include <stddef.h>

#define GNUTLS_CIPHER_RIJNDAEL_128_CBC GNUTLS_CIPHER_AES_128_CBC
#define GNUTLS_CIPHER_RIJNDAEL_256_CBC GNUTLS_CIPHER_AES_256_CBC
#define GNUTLS_CIPHER_RIJNDAEL_CBC GNUTLS_CIPHER_AES_128_CBC
#define GNUTLS_CIPHER_ARCFOUR GNUTLS_CIPHER_ARCFOUR_128

#define GNUTLS_MAX_SESSION_ID 32
#define TLS_MASTER_SIZE 48
#define TLS_RANDOM_SIZE 32

#include "microhttpd.h"

  typedef enum
  {
    GNUTLS_PARAMS_RSA_EXPORT = 1,
    GNUTLS_PARAMS_DH
  } gnutls_params_type_t;

  /* exported for other gnutls headers. This is the maximum number of
   * algorithms (ciphers, kx or macs).
   */
#define GNUTLS_MAX_ALGORITHM_NUM 16
#define GNUTLS_COMP_ZLIB GNUTLS_COMP_DEFLATE

  typedef enum
  {
    GNUTLS_SERVER = 1,
    GNUTLS_CLIENT
  } gnutls_connection_end_t;

  typedef enum
  {
    GNUTLS_AL_WARNING = 1,
    GNUTLS_AL_FATAL
  } gnutls_alert_level_t;

  typedef enum
  {
    GNUTLS_A_CLOSE_NOTIFY,
    GNUTLS_A_UNEXPECTED_MESSAGE = 10,
    GNUTLS_A_BAD_RECORD_MAC = 20,
    GNUTLS_A_DECRYPTION_FAILED,
    GNUTLS_A_RECORD_OVERFLOW,
    GNUTLS_A_DECOMPRESSION_FAILURE = 30,
    GNUTLS_A_HANDSHAKE_FAILURE = 40,
    GNUTLS_A_SSL3_NO_CERTIFICATE = 41,
    GNUTLS_A_BAD_CERTIFICATE = 42,
    GNUTLS_A_UNSUPPORTED_CERTIFICATE,
    GNUTLS_A_CERTIFICATE_REVOKED,
    GNUTLS_A_CERTIFICATE_EXPIRED,
    GNUTLS_A_CERTIFICATE_UNKNOWN,
    GNUTLS_A_ILLEGAL_PARAMETER,
    GNUTLS_A_UNKNOWN_CA,
    GNUTLS_A_ACCESS_DENIED,
    GNUTLS_A_DECODE_ERROR = 50,
    GNUTLS_A_DECRYPT_ERROR,
    GNUTLS_A_EXPORT_RESTRICTION = 60,
    GNUTLS_A_PROTOCOL_VERSION = 70,
    GNUTLS_A_INSUFFICIENT_SECURITY,
    GNUTLS_A_INTERNAL_ERROR = 80,
    GNUTLS_A_USER_CANCELED = 90,
    GNUTLS_A_NO_RENEGOTIATION = 100,
    GNUTLS_A_UNSUPPORTED_EXTENSION = 110,
    GNUTLS_A_CERTIFICATE_UNOBTAINABLE = 111,
    GNUTLS_A_UNRECOGNIZED_NAME = 112,
    GNUTLS_A_UNKNOWN_PSK_IDENTITY = 115,
  } gnutls_alert_description_t;

  typedef enum
  { GNUTLS_HANDSHAKE_HELLO_REQUEST = 0,
    GNUTLS_HANDSHAKE_CLIENT_HELLO = 1,
    GNUTLS_HANDSHAKE_SERVER_HELLO = 2,
    GNUTLS_HANDSHAKE_CERTIFICATE_PKT = 11,
    GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12,
    GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST = 13,
    GNUTLS_HANDSHAKE_SERVER_HELLO_DONE = 14,
    GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY = 15,
    GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16,
    GNUTLS_HANDSHAKE_FINISHED = 20,
    GNUTLS_HANDSHAKE_SUPPLEMENTAL = 23
  } gnutls_handshake_description_t;

  typedef enum
  {
    GNUTLS_CERT_INVALID = 2,    /* will be set if the certificate
                                 * was not verified.
                                 */
    GNUTLS_CERT_REVOKED = 32,   /* in X.509 this will be set only if CRLs are checked
                                 */

    /* Those are extra information about the verification
     * process. Will be set only if the certificate was
     * not verified.
     */
    GNUTLS_CERT_SIGNER_NOT_FOUND = 64,
    GNUTLS_CERT_SIGNER_NOT_CA = 128,
    GNUTLS_CERT_INSECURE_ALGORITHM = 256
  } gnutls_certificate_status_t;

  typedef enum
  {
    GNUTLS_CERT_IGNORE,
    GNUTLS_CERT_REQUEST = 1,
    GNUTLS_CERT_REQUIRE
  } gnutls_certificate_request_t;

  typedef enum
  {
    GNUTLS_SHUT_RDWR = 0,
    GNUTLS_SHUT_WR = 1
  } gnutls_close_request_t;

  typedef enum
  {
    GNUTLS_X509_FMT_DER,
    GNUTLS_X509_FMT_PEM
  } gnutls_x509_crt_fmt_t;

  typedef enum
  {
    GNUTLS_SIGN_UNKNOWN = 0,
    GNUTLS_SIGN_RSA_SHA1 = 1,
    GNUTLS_SIGN_DSA_SHA1,
    GNUTLS_SIGN_RSA_MD5,
    GNUTLS_SIGN_RSA_MD2,
    GNUTLS_SIGN_RSA_RMD160,
    GNUTLS_SIGN_RSA_SHA256,
    GNUTLS_SIGN_RSA_SHA384,
    GNUTLS_SIGN_RSA_SHA512
  } gnutls_sign_algorithm_t;

/* If you want to change this, then also change the define in
 * gnutls_int.h, and recompile.
 */
  typedef void *gnutls_transport_ptr_t;

  struct MHD_gtls_session_int;
  typedef struct MHD_gtls_session_int *mhd_gtls_session_t;

  struct MHD_gtls_dh_params_int;
  typedef struct MHD_gtls_dh_params_int *mhd_gtls_dh_params_t;

  struct MHD_gtls_x509_privkey_int;     /* XXX ugly. */
  typedef struct MHD_gtls_x509_privkey_int *mhd_gtls_rsa_params_t;      /* XXX ugly. */

  struct MHD_gtls_priority_st;
  typedef struct MHD_gtls_priority_st *gnutls_priority_t;

  typedef struct
  {
    unsigned char *data;
    unsigned int size;
  } gnutls_datum_t;


  typedef struct gnutls_params_st
  {
    gnutls_params_type_t type;
    union params
    {
      mhd_gtls_dh_params_t dh;
      mhd_gtls_rsa_params_t rsa_export;
    } params;
    int deinit;
  } gnutls_params_st;

  typedef int gnutls_params_function (mhd_gtls_session_t,
                                      gnutls_params_type_t,
                                      gnutls_params_st *);

/* internal functions */
  int MHD_gnutls_global_init (void);
  void MHD_gnutls_global_deinit (void);

  int MHD_gnutls_init (mhd_gtls_session_t * session,
                       gnutls_connection_end_t con_end);
  void MHD_gnutls_deinit (mhd_gtls_session_t session);

  int MHD_gnutls_bye (mhd_gtls_session_t session, gnutls_close_request_t how);
  int MHD_gnutls_handshake (mhd_gtls_session_t session);
  int MHD_gnutls_rehandshake (mhd_gtls_session_t session);
  gnutls_alert_description_t gnutls_alert_get (mhd_gtls_session_t session);
  int MHD_gnutls_alert_send (mhd_gtls_session_t session,
                             gnutls_alert_level_t level,
                             gnutls_alert_description_t desc);
  int MHD_gnutls_alert_send_appropriate (mhd_gtls_session_t session, int err);
  const char *MHD_gnutls_alert_get_name (gnutls_alert_description_t alert);

//  enum MHD_GNUTLS_CipherAlgorithm gnutls_cipher_get (mhd_gtls_session_t session);
//  enum MHD_GNUTLS_KeyExchangeAlgorithm gnutls_kx_get (mhd_gtls_session_t session);
//  enum MHD_GNUTLS_HashAlgorithm gnutls_mac_get (mhd_gtls_session_t session);
//  enum MHD_GNUTLS_CompressionMethod gnutls_compression_get (mhd_gtls_session_t
//                                                      session);
//  enum MHD_GNUTLS_CertificateType gnutls_certificate_type_get (mhd_gtls_session_t
//                                                         session);

  size_t MHD_gnutls_cipher_get_key_size (enum MHD_GNUTLS_CipherAlgorithm
                                         algorithm);
  size_t MHD_gnutls_mac_get_key_size (enum MHD_GNUTLS_HashAlgorithm
                                      algorithm);

/* the name of the specified algorithms */
  const char *MHD_gnutls_cipher_get_name (enum MHD_GNUTLS_CipherAlgorithm
                                          algorithm);
  const char *MHD_gnutls_mac_get_name (enum MHD_GNUTLS_HashAlgorithm
                                       algorithm);
  const char *MHD_gnutls_compression_get_name (enum
                                               MHD_GNUTLS_CompressionMethod
                                               algorithm);
  const char *MHD_gnutls_kx_get_name (enum MHD_GNUTLS_KeyExchangeAlgorithm
                                      algorithm);
  const char *MHD_gnutls_certificate_type_get_name (enum
                                                    MHD_GNUTLS_CertificateType
                                                    type);

  enum MHD_GNUTLS_HashAlgorithm MHD_gtls_mac_get_id (const char *name);
  enum MHD_GNUTLS_CompressionMethod MHD_gtls_compression_get_id (const char
                                                                 *name);
  enum MHD_GNUTLS_CipherAlgorithm MHD_gtls_cipher_get_id (const char *name);
  enum MHD_GNUTLS_KeyExchangeAlgorithm MHD_gtls_kx_get_id (const char *name);
  enum MHD_GNUTLS_Protocol MHD_gtls_protocol_get_id (const char *name);
  enum MHD_GNUTLS_CertificateType MHD_gtls_certificate_type_get_id (const char
                                                                    *name);

  /* list supported algorithms */
  const enum MHD_GNUTLS_CipherAlgorithm *MHD_gtls_cipher_list (void);
  const enum MHD_GNUTLS_HashAlgorithm *MHD_gtls_mac_list (void);
  const enum MHD_GNUTLS_CompressionMethod *MHD_gtls_compression_list (void);
  const enum MHD_GNUTLS_Protocol *MHD_gtls_protocol_list (void);
  const enum MHD_GNUTLS_CertificateType
    *MHD_gtls_certificate_type_list (void);
  const enum MHD_GNUTLS_KeyExchangeAlgorithm *MHD_gtls_kx_list (void);

  /* error functions */
  int MHD_gtls_error_is_fatal (int error);
  int MHD_gtls_error_to_alert (int err, int *level);
  void MHD_gtls_perror (int error);
  const char *MHD_gtls_strerror (int error);

  void MHD_gtls_handshake_set_private_extensions (mhd_gtls_session_t session,
                                                  int allow);
    gnutls_handshake_description_t
    MHD_gtls_handshake_get_last_out (mhd_gtls_session_t session);
    gnutls_handshake_description_t
    MHD_gtls_handshake_get_last_in (mhd_gtls_session_t session);

/*
 * Record layer functions.
 */
  ssize_t MHD_gnutls_record_send (mhd_gtls_session_t session,
                                  const void *data, size_t sizeofdata);
  ssize_t MHD_gnutls_record_recv (mhd_gtls_session_t session, void *data,
                                  size_t sizeofdata);

  /* provides extra compatibility */
  void MHD_gtls_record_disable_padding (mhd_gtls_session_t session);
  size_t MHD_gtls_record_check_pending (mhd_gtls_session_t session);

  int MHD_gnutls_record_get_direction (mhd_gtls_session_t session);
  size_t MHD_gnutls_record_get_max_size (mhd_gtls_session_t session);
  ssize_t MHD_gnutls_record_set_max_size (mhd_gtls_session_t session,
                                          size_t size);


  int MHD_gnutls_prf (mhd_gtls_session_t session,
                      size_t label_size, const char *label,
                      int server_random_first,
                      size_t extra_size, const char *extra,
                      size_t outsize, char *out);

  int MHD_gnutls_prf_raw (mhd_gtls_session_t session,
                          size_t label_size, const char *label,
                          size_t seed_size, const char *seed,
                          size_t outsize, char *out);

/*
 * TLS Extensions
 */
  typedef enum
  {
    GNUTLS_NAME_DNS = 1
  } gnutls_server_name_type_t;

  int MHD_gnutls_server_name_set (mhd_gtls_session_t session,
                                  gnutls_server_name_type_t type,
                                  const void *name, size_t name_length);

  int MHD_gnutls_server_name_get (mhd_gtls_session_t session,
                                  void *data, size_t * data_length,
                                  unsigned int *type, unsigned int indx);

  /* Opaque PRF Input
   * http://tools.ietf.org/id/draft-rescorla-tls-opaque-prf-input-00.txt
   */

  void
    MHD_gtls_oprfi_enable_client (mhd_gtls_session_t session,
                                  size_t len, unsigned char *data);

  typedef int (*gnutls_oprfi_callback_func) (mhd_gtls_session_t session,
                                             void *userdata,
                                             size_t oprfi_len,
                                             const unsigned char *in_oprfi,
                                             unsigned char *out_oprfi);

  void
    MHD_gtls_oprfi_enable_server (mhd_gtls_session_t session,
                                  gnutls_oprfi_callback_func cb,
                                  void *userdata);

  /* Supplemental data, RFC 4680. */
  typedef enum
  {
    GNUTLS_SUPPLEMENTAL_USER_MAPPING_DATA = 0
  } gnutls_supplemental_data_format_type_t;

  const char *MHD_gtls_supplemental_get_name
    (gnutls_supplemental_data_format_type_t type);

  int MHD_gnutls_cipher_set_priority (mhd_gtls_session_t session,
                                      const int *list);
  int MHD_gnutls_mac_set_priority (mhd_gtls_session_t session,
                                   const int *list);
  int MHD_gnutls_compression_set_priority (mhd_gtls_session_t session,
                                           const int *list);
  int MHD_gnutls_kx_set_priority (mhd_gtls_session_t session,
                                  const int *list);
  int MHD_gnutls_protocol_set_priority (mhd_gtls_session_t session,
                                        const int *list);
  int MHD_gnutls_certificate_type_set_priority (mhd_gtls_session_t session,
                                                const int *list);

  int MHD_tls_set_default_priority (gnutls_priority_t *, const char *priority,
                                    const char **err_pos);
  void MHD_gnutls_priority_deinit (gnutls_priority_t);

  int MHD_gnutls_priority_set (mhd_gtls_session_t session, gnutls_priority_t);
  int MHD_gnutls_priority_set_direct (mhd_gtls_session_t session,
                                      const char *priority,
                                      const char **err_pos);

/* get the currently used protocol version */
  enum MHD_GNUTLS_Protocol MHD_gnutls_protocol_get_version (mhd_gtls_session_t
                                                            session);

  const char *MHD_gnutls_protocol_get_name (enum MHD_GNUTLS_Protocol version);

/*
 * get/set session
 */
//  int gnutls_session_set_data (mhd_gtls_session_t session,
//                               const void *session_data,
//                               size_t session_data_size);
//  int gnutls_session_get_data (mhd_gtls_session_t session, void *session_data,
//                               size_t * session_data_size);
//  int gnutls_session_get_data2 (mhd_gtls_session_t session,
//                                gnutls_datum_t * data);

  int MHD_gtls_session_get_id (mhd_gtls_session_t session, void *session_id,
                               size_t * session_id_size);

/* returns security values.
 * Do not use them unless you know what you're doing.
 */
  const void *MHD_gtls_session_get_server_random (mhd_gtls_session_t session);
  const void *MHD_gtls_session_get_client_random (mhd_gtls_session_t session);
  const void *MHD_gtls_session_get_master_secret (mhd_gtls_session_t session);

  int MHD_gtls_session_is_resumed (mhd_gtls_session_t session);

  typedef int (*gnutls_handshake_post_client_hello_func) (mhd_gtls_session_t);
  void
    MHD_gnutls_handshake_set_post_client_hello_function (mhd_gtls_session_t,
                                                         gnutls_handshake_post_client_hello_func);

  void MHD_gnutls_handshake_set_max_packet_length (mhd_gtls_session_t session,
                                                   size_t max);

/*
 * Functions for setting/clearing credentials
 */
  void MHD_gnutls_credentials_clear (mhd_gtls_session_t session);

/*
 * cred is a structure defined by the kx algorithm
 */
  int MHD_gnutls_credentials_set (mhd_gtls_session_t session,
                                  enum MHD_GNUTLS_CredentialsType type,
                                  void *cred);

/* Credential structures - used in MHD_gnutls_credentials_set(); */
  struct mhd_gtls_certificate_credentials_st;
  typedef struct mhd_gtls_certificate_credentials_st
    *mhd_gtls_cert_credentials_t;
  typedef mhd_gtls_cert_credentials_t mhd_gtls_cert_server_credentials;
  typedef mhd_gtls_cert_credentials_t mhd_gtls_cert_client_credentials;

  typedef struct mhd_gtls_anon_server_credentials_st
    *mhd_gtls_anon_server_credentials_t;
  typedef struct mhd_gtls_anon_client_credentials_st
    *mhd_gtls_anon_client_credentials_t;

  void
    MHD_gnutls_anon_free_server_credentials
    (mhd_gtls_anon_server_credentials_t sc);
  int
    MHD_gnutls_anon_allocate_server_credentials
    (mhd_gtls_anon_server_credentials_t * sc);

  void
    MHD_gnutls_anon_set_server_dh_params (mhd_gtls_anon_server_credentials_t
                                          res,
                                          mhd_gtls_dh_params_t dh_params);

  void
    MHD_gnutls_anon_set_server_params_function
    (mhd_gtls_anon_server_credentials_t res, gnutls_params_function * func);

  void
    MHD_gnutls_anon_free_client_credentials
    (mhd_gtls_anon_client_credentials_t sc);
  int
    MHD_gnutls_anon_allocate_client_credentials
    (mhd_gtls_anon_client_credentials_t * sc);

  void MHD_gnutls_certificate_free_credentials (mhd_gtls_cert_credentials_t
                                                sc);
  int
    MHD_gnutls_certificate_allocate_credentials (mhd_gtls_cert_credentials_t
                                                 * res);

  void MHD_gnutls_certificate_free_keys (mhd_gtls_cert_credentials_t sc);
  void MHD_gnutls_certificate_free_cas (mhd_gtls_cert_credentials_t sc);
  void MHD_gnutls_certificate_free_ca_names (mhd_gtls_cert_credentials_t sc);
  void MHD_gnutls_certificate_free_crls (mhd_gtls_cert_credentials_t sc);

  void MHD_gnutls_certificate_set_dh_params (mhd_gtls_cert_credentials_t res,
                                             mhd_gtls_dh_params_t dh_params);
  void
    MHD_gnutls_certificate_set_rsa_export_params (mhd_gtls_cert_credentials_t
                                                  res,
                                                  mhd_gtls_rsa_params_t
                                                  rsa_params);
  void MHD_gnutls_certificate_set_verify_flags (mhd_gtls_cert_credentials_t
                                                res, unsigned int flags);
  void MHD_gnutls_certificate_set_verify_limits (mhd_gtls_cert_credentials_t
                                                 res, unsigned int max_bits,
                                                 unsigned int max_depth);

  int MHD_gnutls_certificate_set_x509_trust_file (mhd_gtls_cert_credentials_t
                                                  res, const char *CAFILE,
                                                  gnutls_x509_crt_fmt_t type);
  int MHD_gnutls_certificate_set_x509_trust_mem (mhd_gtls_cert_credentials_t
                                                 res,
                                                 const gnutls_datum_t * CA,
                                                 gnutls_x509_crt_fmt_t type);

  int MHD_gnutls_certificate_set_x509_crl_file (mhd_gtls_cert_credentials_t
                                                res, const char *crlfile,
                                                gnutls_x509_crt_fmt_t type);
  int MHD_gnutls_certificate_set_x509_crl_mem (mhd_gtls_cert_credentials_t
                                               res,
                                               const gnutls_datum_t * CRL,
                                               gnutls_x509_crt_fmt_t type);

  /*
   * CERTFILE is an x509 certificate in PEM form.
   * KEYFILE is a pkcs-1 private key in PEM form (for RSA keys).
   */
  int MHD_gnutls_certificate_set_x509_key_file (mhd_gtls_cert_credentials_t
                                                res, const char *CERTFILE,
                                                const char *KEYFILE,
                                                gnutls_x509_crt_fmt_t type);
  int MHD_gnutls_certificate_set_x509_key_mem (mhd_gtls_cert_credentials_t
                                               res,
                                               const gnutls_datum_t * CERT,
                                               const gnutls_datum_t * KEY,
                                               gnutls_x509_crt_fmt_t type);

  void MHD_gnutls_certificate_send_x509_rdn_sequence (mhd_gtls_session_t
                                                      session, int status);

/*
 * New functions to allow setting already parsed X.509 stuff.
 */
  struct MHD_gtls_x509_privkey_int;
  typedef struct MHD_gtls_x509_privkey_int *gnutls_x509_privkey_t;

  struct gnutls_x509_crl_int;
  typedef struct gnutls_x509_crl_int *gnutls_x509_crl_t;

  struct gnutls_x509_crt_int;
  typedef struct gnutls_x509_crt_int *gnutls_x509_crt_t;

//  int gnutls_certificate_set_x509_key (mhd_gtls_cert_credentials_t res,
//                                       gnutls_x509_crt_t * cert_list,
//                                       int cert_list_size,
//                                       gnutls_x509_privkey_t key);
//  int gnutls_certificate_set_x509_trust (mhd_gtls_cert_credentials_t res,
//                                         gnutls_x509_crt_t * ca_list,
//                                         int ca_list_size);
//  int gnutls_certificate_set_x509_crl (mhd_gtls_cert_credentials_t res,
//                                       gnutls_x509_crl_t * crl_list,
//                                       int crl_list_size);

/* global state functions
 */


  typedef void *(*gnutls_alloc_function) (size_t);
  typedef void *(*gnutls_calloc_function) (size_t, size_t);
  typedef int (*gnutls_is_secure_function) (const void *);
  typedef void (*gnutls_free_function) (void *);
  typedef void *(*gnutls_realloc_function) (void *, size_t);

  extern void
    MHD_gtls_global_set_mem_functions (gnutls_alloc_function gt_alloc_func,
                                       gnutls_alloc_function
                                       gt_secure_alloc_func,
                                       gnutls_is_secure_function
                                       gt_is_secure_func,
                                       gnutls_realloc_function
                                       gt_realloc_func,
                                       gnutls_free_function gt_free_func);

/* For use in callbacks */
  extern gnutls_alloc_function gnutls_malloc;
  extern gnutls_alloc_function gnutls_secure_malloc;
  extern gnutls_realloc_function gnutls_realloc;
  extern gnutls_calloc_function gnutls_calloc;
  extern gnutls_free_function gnutls_free;

  extern char *(*gnutls_strdup) (const char *);

  typedef void (*gnutls_log_func) (int, const char *);
  void MHD_gtls_global_set_log_function (gnutls_log_func log_func);
  void MHD_gtls_global_set_log_level (int level);

/*
 * Diffie Hellman parameter handling.
 */
  int MHD_gnutls_dh_params_init (mhd_gtls_dh_params_t * dh_params);
  void MHD_gnutls_dh_params_deinit (mhd_gtls_dh_params_t dh_params);
  int MHD_gnutls_dh_params_generate2 (mhd_gtls_dh_params_t params,
                                      unsigned int bits);


/* RSA params */
  int MHD_gnutls_rsa_params_init (mhd_gtls_rsa_params_t * rsa_params);
  void MHD_gnutls_rsa_params_deinit (mhd_gtls_rsa_params_t rsa_params);
  int MHD_gnutls_rsa_params_generate2 (mhd_gtls_rsa_params_t params,
                                       unsigned int bits);


/*
 * Session stuff
 */
  typedef ssize_t (*mhd_gtls_pull_func) (gnutls_transport_ptr_t, void *,
                                         size_t);
  typedef ssize_t (*mhd_gtls_push_func) (gnutls_transport_ptr_t, const void *,
                                         size_t);
  void MHD_gnutls_transport_set_ptr (mhd_gtls_session_t session,
                                     gnutls_transport_ptr_t ptr);
  void MHD_gnutls_transport_set_ptr2 (mhd_gtls_session_t session,
                                      gnutls_transport_ptr_t recv_ptr,
                                      gnutls_transport_ptr_t send_ptr);

  void MHD_gnutls_transport_set_lowat (mhd_gtls_session_t session, int num);


  void MHD_gnutls_transport_set_push_function (mhd_gtls_session_t session,
                                               mhd_gtls_push_func push_func);
  void MHD_gnutls_transport_set_pull_function (mhd_gtls_session_t session,
                                               mhd_gtls_pull_func pull_func);

  void MHD_gnutls_transport_set_errno (mhd_gtls_session_t session, int err);
  void MHD_gnutls_transport_set_global_errno (int err);

/*
 * session specific
 */
  void MHD_gnutls_session_set_ptr (mhd_gtls_session_t session, void *ptr);
  void *MHD_gtls_session_get_ptr (mhd_gtls_session_t session);

/*
 * this function returns the hash of the given data.
 */
  int MHD_gnutls_fingerprint (enum MHD_GNUTLS_HashAlgorithm algo,
                              const gnutls_datum_t * data, void *result,
                              size_t * result_size);

/*
 *  SRP
 */
//  typedef struct gnutls_srp_server_credentials_st
//    *gnutls_srp_server_credentials_t;
//  typedef struct gnutls_srp_client_credentials_st
//    *gnutls_srp_client_credentials_t;
//
//  void gnutls_srp_free_client_credentials (gnutls_srp_client_credentials_t
//                                           sc);
//  int gnutls_srp_allocate_client_credentials (gnutls_srp_client_credentials_t
//                                              * sc);
//  int gnutls_srp_set_client_credentials (gnutls_srp_client_credentials_t res,
//                                         const char *username,
//                                         const char *password);
//
//  void gnutls_srp_free_server_credentials (gnutls_srp_server_credentials_t
//                                           sc);
//  int gnutls_srp_allocate_server_credentials (gnutls_srp_server_credentials_t
//                                              * sc);
//  int gnutls_srp_set_server_credentials_file (gnutls_srp_server_credentials_t
//                                              res, const char *password_file,
//                                              const char *password_conf_file);
//
//  const char *gnutls_srp_server_get_username (mhd_gtls_session_t session);
//
//  extern int gnutls_srp_verifier (const char *username,
//                                  const char *password,
//                                  const gnutls_datum_t * salt,
//                                  const gnutls_datum_t * generator,
//                                  const gnutls_datum_t * prime,
//                                  gnutls_datum_t * res);
//
///* The static parameters defined in draft-ietf-tls-srp-05
// * Those should be used as input to gnutls_srp_verifier().
// */
//  extern const gnutls_datum_t gnutls_srp_2048_group_prime;
//  extern const gnutls_datum_t gnutls_srp_2048_group_generator;
//
//  extern const gnutls_datum_t gnutls_srp_1536_group_prime;
//  extern const gnutls_datum_t gnutls_srp_1536_group_generator;
//
//  extern const gnutls_datum_t gnutls_srp_1024_group_prime;
//  extern const gnutls_datum_t gnutls_srp_1024_group_generator;
//
//  typedef int gnutls_srp_server_credentials_function (mhd_gtls_session_t,
//                                                      const char *username,
//                                                      gnutls_datum_t * salt,
//                                                      gnutls_datum_t *
//                                                      verifier,
//                                                      gnutls_datum_t *
//                                                      generator,
//                                                      gnutls_datum_t * prime);
//  void
//    gnutls_srp_set_server_credentials_function
//    (gnutls_srp_server_credentials_t cred,
//     gnutls_srp_server_credentials_function * func);
//
//  typedef int gnutls_srp_client_credentials_function (mhd_gtls_session_t,
//                                                      char **, char **);
//  void
//    gnutls_srp_set_client_credentials_function
//    (gnutls_srp_client_credentials_t cred,
//     gnutls_srp_client_credentials_function * func);
//
//  int gnutls_srp_base64_encode (const gnutls_datum_t * data, char *result,
//                                size_t * result_size);
//  int gnutls_srp_base64_encode_alloc (const gnutls_datum_t * data,
//                                      gnutls_datum_t * result);
//
//  int gnutls_srp_base64_decode (const gnutls_datum_t * b64_data, char *result,
//                                size_t * result_size);
//  int gnutls_srp_base64_decode_alloc (const gnutls_datum_t * b64_data,
//                                      gnutls_datum_t * result);

/*
 * PSK stuff
 */
//  typedef struct gnutls_psk_server_credentials_st
//    *gnutls_psk_server_credentials_t;
//  typedef struct gnutls_psk_client_credentials_st
//    *gnutls_psk_client_credentials_t;
//
//  typedef enum gnutls_psk_key_flags
//  {
//    GNUTLS_PSK_KEY_RAW = 0,
//    GNUTLS_PSK_KEY_HEX
//  } gnutls_psk_key_flags;
//
//  void gnutls_psk_free_client_credentials (gnutls_psk_client_credentials_t
//                                           sc);
//  int gnutls_psk_allocate_client_credentials (gnutls_psk_client_credentials_t
//                                              * sc);
//  int gnutls_psk_set_client_credentials (gnutls_psk_client_credentials_t res,
//                                         const char *username,
//                                         const gnutls_datum_t * key,
//                                         gnutls_psk_key_flags format);
//
//  void gnutls_psk_free_server_credentials (gnutls_psk_server_credentials_t
//                                           sc);
//  int gnutls_psk_allocate_server_credentials (gnutls_psk_server_credentials_t
//                                              * sc);
//  int gnutls_psk_set_server_credentials_file (gnutls_psk_server_credentials_t
//                                              res, const char *password_file);
//
//  const char *gnutls_psk_server_get_username (mhd_gtls_session_t session);
//
//  typedef int gnutls_psk_server_credentials_function (mhd_gtls_session_t,
//                                                      const char *username,
//                                                      gnutls_datum_t * key);
//  void
//    gnutls_psk_set_server_credentials_function
//    (gnutls_psk_server_credentials_t cred,
//     gnutls_psk_server_credentials_function * func);
//
//  typedef int gnutls_psk_client_credentials_function (mhd_gtls_session_t,
//                                                      char **username,
//                                                      gnutls_datum_t * key);
//  void
//    gnutls_psk_set_client_credentials_function
//    (gnutls_psk_client_credentials_t cred,
//     gnutls_psk_client_credentials_function * func);
//
//  int gnutls_hex_encode (const gnutls_datum_t * data, char *result,
//                         size_t * result_size);
//  int gnutls_hex_decode (const gnutls_datum_t * hex_data, char *result,
//                         size_t * result_size);
//
//  void gnutls_psk_set_server_dh_params (gnutls_psk_server_credentials_t res,
//                                        mhd_gtls_dh_params_t dh_params);
//
//  void gnutls_psk_set_server_params_function (gnutls_psk_server_credentials_t
//                                              res,
//                                              gnutls_params_function * func);

  typedef enum gnutls_x509_subject_alt_name_t
  {
    GNUTLS_SAN_DNSNAME = 1,
    GNUTLS_SAN_RFC822NAME,
    GNUTLS_SAN_URI,
    GNUTLS_SAN_IPADDRESS,
    GNUTLS_SAN_OTHERNAME,
    GNUTLS_SAN_DN,
    /* The following are "virtual" subject alternative name types, in
       that they are represented by an otherName value and an OID.
       Used by gnutls_x509_crt_get_subject_alt_othername_oid().  */
    GNUTLS_SAN_OTHERNAME_XMPP = 1000
  } gnutls_x509_subject_alt_name_t;

  typedef struct gnutls_retr_st
  {
    enum MHD_GNUTLS_CertificateType type;
    union cert
    {
      gnutls_x509_crt_t *x509;
    } cert;
    unsigned int ncerts;

    union key
    {
      gnutls_x509_privkey_t x509;
    } key;

    unsigned int deinit_all;    /* if non zero all keys will be deinited */
  } gnutls_retr_st;

  typedef int gnutls_certificate_client_retrieve_function (mhd_gtls_session_t,
                                                           const
                                                           gnutls_datum_t *
                                                           req_ca_rdn,
                                                           int nreqs,
                                                           const
                                                           enum
                                                           MHD_GNUTLS_PublicKeyAlgorithm
                                                           *pk_algos,
                                                           int
                                                           pk_algos_length,
                                                           gnutls_retr_st *);

  typedef int gnutls_certificate_server_retrieve_function (mhd_gtls_session_t,
                                                           gnutls_retr_st *);

  /*
   * Functions that allow auth_info_t structures handling
   */
  enum MHD_GNUTLS_CredentialsType MHD_gtls_auth_get_type (mhd_gtls_session_t
                                                          session);
  enum MHD_GNUTLS_CredentialsType
    MHD_gtls_auth_server_get_type (mhd_gtls_session_t session);
  enum MHD_GNUTLS_CredentialsType
    MHD_gtls_auth_client_get_type (mhd_gtls_session_t session);

  /*
   * DH
   */
  void MHD_gnutls_dh_set_prime_bits (mhd_gtls_session_t session,
                                     unsigned int bits);
  int MHD_gnutls_dh_get_secret_bits (mhd_gtls_session_t session);
  int MHD_gnutls_dh_get_peers_public_bits (mhd_gtls_session_t session);
  int MHD_gnutls_dh_get_prime_bits (mhd_gtls_session_t session);

  int MHD_gnutls_dh_get_group (mhd_gtls_session_t session,
                               gnutls_datum_t * raw_gen,
                               gnutls_datum_t * raw_prime);
  int MHD_gnutls_dh_get_pubkey (mhd_gtls_session_t session,
                                gnutls_datum_t * raw_key);

  /*
   * RSA
   */
  int MHD_gtls_rsa_export_get_pubkey (mhd_gtls_session_t session,
                                      gnutls_datum_t * exponent,
                                      gnutls_datum_t * modulus);
  int MHD_gtls_rsa_export_get_modulus_bits (mhd_gtls_session_t session);

  /* External signing callback.  Experimental. */
  typedef int (*gnutls_sign_func) (mhd_gtls_session_t session,
                                   void *userdata,
                                   enum MHD_GNUTLS_CertificateType cert_type,
                                   const gnutls_datum_t * cert,
                                   const gnutls_datum_t * hash,
                                   gnutls_datum_t * signature);

  void MHD_gtls_sign_callback_set (mhd_gtls_session_t session,
                                   gnutls_sign_func sign_func,
                                   void *userdata);
    gnutls_sign_func MHD_gtls_sign_callback_get (mhd_gtls_session_t session,
                                                 void **userdata);

  /* These are set on the credentials structure.
   */
  void MHD_gtls_certificate_client_set_retrieve_function
    (mhd_gtls_cert_credentials_t cred,
     gnutls_certificate_client_retrieve_function * func);
  void MHD_gtls_certificate_server_set_retrieve_function
    (mhd_gtls_cert_credentials_t cred,
     gnutls_certificate_server_retrieve_function * func);

  void MHD_gtls_certificate_server_set_request (mhd_gtls_session_t session,
                                                gnutls_certificate_request_t
                                                req);

  /* get data from the session */
  const gnutls_datum_t *MHD_gtls_certificate_get_peers (mhd_gtls_session_t
                                                        session,
                                                        unsigned int
                                                        *list_size);
  const gnutls_datum_t *MHD_gtls_certificate_get_ours (mhd_gtls_session_t
                                                       session);

  time_t MHD_gtls_certificate_activation_time_peers (mhd_gtls_session_t
                                                     session);
  time_t MHD_gtls_certificate_expiration_time_peers (mhd_gtls_session_t
                                                     session);

  int MHD_gtls_certificate_client_get_request_status (mhd_gtls_session_t
                                                      session);
  int MHD_gtls_certificate_verify_peers2 (mhd_gtls_session_t session,
                                          unsigned int *status);

  /* this is obsolete (?). */
  int MHD_gtls_certificate_verify_peers (mhd_gtls_session_t session);

  int MHD_gtls_pem_base64_encode (const char *msg,
                                  const gnutls_datum_t * data, char *result,
                                  size_t * result_size);
  int MHD_gtls_pem_base64_decode (const char *header,
                                  const gnutls_datum_t * b64_data,
                                  unsigned char *result,
                                  size_t * result_size);

  int MHD_gtls_pem_base64_encode_alloc (const char *msg,
                                        const gnutls_datum_t * data,
                                        gnutls_datum_t * result);
  int MHD_gtls_pem_base64_decode_alloc (const char *header,
                                        const gnutls_datum_t * b64_data,
                                        gnutls_datum_t * result);

  //  void
  //    gnutls_certificate_set_params_function (mhd_gtls_cert_credentials_t
  //                                            res,
  //                                            gnutls_params_function * func);
  //  void gnutls_anon_set_params_function (mhd_gtls_anon_server_credentials_t res,
  //                                        gnutls_params_function * func);
  //  void gnutls_psk_set_params_function (gnutls_psk_server_credentials_t res,
  //                                       gnutls_params_function * func);


  /* key_usage will be an OR of the following values: */
  /* when the key is to be used for signing: */
#define GNUTLS_KEY_DIGITAL_SIGNATURE	128
#define GNUTLS_KEY_NON_REPUDIATION	64
  /* when the key is to be used for encryption: */
#define GNUTLS_KEY_KEY_ENCIPHERMENT	32
#define GNUTLS_KEY_DATA_ENCIPHERMENT	16
#define GNUTLS_KEY_KEY_AGREEMENT	8
#define GNUTLS_KEY_KEY_CERT_SIGN	4
#define GNUTLS_KEY_CRL_SIGN		2
#define GNUTLS_KEY_ENCIPHER_ONLY	1
#define GNUTLS_KEY_DECIPHER_ONLY	32768

  /*
   * Error codes. TLS alert mapping shown in comments.
   */
#define GNUTLS_E_SUCCESS 0
#define	GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM -3
#define	GNUTLS_E_UNKNOWN_CIPHER_TYPE -6
#define	GNUTLS_E_LARGE_PACKET -7
#define GNUTLS_E_UNSUPPORTED_VERSION_PACKET -8  /* GNUTLS_A_PROTOCOL_VERSION */
#define GNUTLS_E_UNEXPECTED_PACKET_LENGTH -9    /* GNUTLS_A_RECORD_OVERFLOW */
#define GNUTLS_E_INVALID_SESSION -10
#define GNUTLS_E_FATAL_ALERT_RECEIVED -12
#define GNUTLS_E_UNEXPECTED_PACKET -15  /* GNUTLS_A_UNEXPECTED_MESSAGE */
#define GNUTLS_E_WARNING_ALERT_RECEIVED -16
#define GNUTLS_E_ERROR_IN_FINISHED_PACKET -18
#define GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET -19
#define	GNUTLS_E_UNKNOWN_CIPHER_SUITE -21       /* GNUTLS_A_HANDSHAKE_FAILURE */
#define	GNUTLS_E_UNWANTED_ALGORITHM -22
#define	GNUTLS_E_MPI_SCAN_FAILED -23
#define GNUTLS_E_DECRYPTION_FAILED -24  /* GNUTLS_A_DECRYPTION_FAILED, GNUTLS_A_BAD_RECORD_MAC */
#define GNUTLS_E_MEMORY_ERROR -25
#define GNUTLS_E_DECOMPRESSION_FAILED -26       /* GNUTLS_A_DECOMPRESSION_FAILURE */
#define GNUTLS_E_COMPRESSION_FAILED -27
#define GNUTLS_E_AGAIN -28
#define GNUTLS_E_EXPIRED -29
#define GNUTLS_E_DB_ERROR -30
#define GNUTLS_E_SRP_PWD_ERROR -31
#define GNUTLS_E_INSUFFICIENT_CREDENTIALS -32
#define GNUTLS_E_INSUFICIENT_CREDENTIALS GNUTLS_E_INSUFFICIENT_CREDENTIALS      /* for backwards compatibility only */
#define GNUTLS_E_INSUFFICIENT_CRED GNUTLS_E_INSUFFICIENT_CREDENTIALS
#define GNUTLS_E_INSUFICIENT_CRED GNUTLS_E_INSUFFICIENT_CREDENTIALS     /* for backwards compatibility only */

#define GNUTLS_E_HASH_FAILED -33
#define GNUTLS_E_BASE64_DECODING_ERROR -34

#define	GNUTLS_E_MPI_PRINT_FAILED -35
#define GNUTLS_E_REHANDSHAKE -37        /* GNUTLS_A_NO_RENEGOTIATION */
#define GNUTLS_E_GOT_APPLICATION_DATA -38
#define GNUTLS_E_RECORD_LIMIT_REACHED -39
#define GNUTLS_E_ENCRYPTION_FAILED -40

#define GNUTLS_E_PK_ENCRYPTION_FAILED -44
#define GNUTLS_E_PK_DECRYPTION_FAILED -45
#define GNUTLS_E_PK_SIGN_FAILED -46
#define GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION -47
#define GNUTLS_E_KEY_USAGE_VIOLATION -48
#define GNUTLS_E_NO_CERTIFICATE_FOUND -49       /* GNUTLS_A_BAD_CERTIFICATE */
#define GNUTLS_E_INVALID_REQUEST -50
#define GNUTLS_E_SHORT_MEMORY_BUFFER -51
#define GNUTLS_E_INTERRUPTED -52
#define GNUTLS_E_PUSH_ERROR -53
#define GNUTLS_E_PULL_ERROR -54
#define GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER -55 /* GNUTLS_A_ILLEGAL_PARAMETER */
#define GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE -56
#define GNUTLS_E_PKCS1_WRONG_PAD -57
#define GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION -58
#define GNUTLS_E_INTERNAL_ERROR -59
#define GNUTLS_E_DH_PRIME_UNACCEPTABLE -63
#define GNUTLS_E_FILE_ERROR -64
#define GNUTLS_E_TOO_MANY_EMPTY_PACKETS -78
#define GNUTLS_E_UNKNOWN_PK_ALGORITHM -80


  /* returned if libextra functionality was requested but
   * gnutls_global_init_extra() was not called.
   */
#define GNUTLS_E_INIT_LIBEXTRA -82
#define GNUTLS_E_LIBRARY_VERSION_MISMATCH -83


  /* returned if you need to generate temporary RSA
   * parameters. These are needed for export cipher suites.
   */
#define GNUTLS_E_NO_TEMPORARY_RSA_PARAMS -84

#define GNUTLS_E_LZO_INIT_FAILED -85
#define GNUTLS_E_NO_COMPRESSION_ALGORITHMS -86
#define GNUTLS_E_NO_CIPHER_SUITES -87

#define GNUTLS_E_PK_SIG_VERIFY_FAILED -89

#define GNUTLS_E_ILLEGAL_SRP_USERNAME -90
#define GNUTLS_E_SRP_PWD_PARSING_ERROR -91
#define GNUTLS_E_NO_TEMPORARY_DH_PARAMS -93

  /* For certificate and key stuff
   */
#define GNUTLS_E_ASN1_ELEMENT_NOT_FOUND -67
#define GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND -68
#define GNUTLS_E_ASN1_DER_ERROR -69
#define GNUTLS_E_ASN1_VALUE_NOT_FOUND -70
#define GNUTLS_E_ASN1_GENERIC_ERROR -71
#define GNUTLS_E_ASN1_VALUE_NOT_VALID -72
#define GNUTLS_E_ASN1_TAG_ERROR -73
#define GNUTLS_E_ASN1_TAG_IMPLICIT -74
#define GNUTLS_E_ASN1_TYPE_ANY_ERROR -75
#define GNUTLS_E_ASN1_SYNTAX_ERROR -76
#define GNUTLS_E_ASN1_DER_OVERFLOW -77
#define GNUTLS_E_CERTIFICATE_ERROR -43
#define GNUTLS_E_X509_CERTIFICATE_ERROR GNUTLS_E_CERTIFICATE_ERROR
#define GNUTLS_E_CERTIFICATE_KEY_MISMATCH -60
#define GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE -61       /* GNUTLS_A_UNSUPPORTED_CERTIFICATE */
#define GNUTLS_E_X509_UNKNOWN_SAN -62
#define GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE -95
#define GNUTLS_E_UNKNOWN_HASH_ALGORITHM -96
#define GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE -97
#define GNUTLS_E_UNKNOWN_PKCS_BAG_TYPE -98
#define GNUTLS_E_INVALID_PASSWORD -99
#define GNUTLS_E_MAC_VERIFY_FAILED -100 /* for PKCS #12 MAC */
#define GNUTLS_E_CONSTRAINT_ERROR -101

#define GNUTLS_E_WARNING_IA_IPHF_RECEIVED -102
#define GNUTLS_E_WARNING_IA_FPHF_RECEIVED -103

#define GNUTLS_E_IA_VERIFY_FAILED -104

#define GNUTLS_E_UNKNOWN_ALGORITHM -105

#define GNUTLS_E_BASE64_ENCODING_ERROR -201
#define GNUTLS_E_INCOMPATIBLE_GCRYPT_LIBRARY -202       /* obsolete */
#define GNUTLS_E_INCOMPATIBLE_CRYPTO_LIBRARY -202
#define GNUTLS_E_INCOMPATIBLE_LIBTASN1_LIBRARY -203

#define GNUTLS_E_X509_UNSUPPORTED_OID -205

#define GNUTLS_E_RANDOM_FAILED -206
#define GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR -207


#define GNUTLS_E_UNIMPLEMENTED_FEATURE -1250

#define GNUTLS_E_APPLICATION_ERROR_MAX -65000
#define GNUTLS_E_APPLICATION_ERROR_MIN -65500

#ifdef __cplusplus
}
#endif

#endif                          /* GNUTLS_H */
