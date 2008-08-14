/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 Free Software Foundation
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

#ifndef GNUTLS_INT_H
#define GNUTLS_INT_H

#include <defines.h>

#include "gnutls.h"
#include "extra.h"
#include "microhttpd.h"

#include "gnutls_mem.h"

/* FIXME: delete this once opencdk has reentrant keyring functions
 */
#define KEYRING_HACK

#define MAX(X,Y) ((X) > (Y) ? (X) : (Y));

#define MAX32 4294967295
#define MAX24 16777215
#define MAX16 65535

/* The size of a handshake message should not
 * be larger than this value.
 */
#define MAX_HANDSHAKE_PACKET_SIZE 48*1024

#define TLS_RANDOM_SIZE 32
#define TLS_MAX_SESSION_ID_SIZE 32
#define TLS_MASTER_SIZE 48

/* The maximum digest size of hash algorithms.
 */
#define MAX_HASH_SIZE 64

#define MAX_LOG_SIZE 1024	/* maximum size of log message */
#define MAX_SRP_USERNAME 128
#define MAX_SERVER_NAME_SIZE 128

/* we can receive up to MAX_EXT_TYPES extensions.
 */
#define MAX_EXT_TYPES 64

/* The initial size of the receive
 * buffer size. This will grow if larger
 * packets are received.
 */
#define INITIAL_RECV_BUFFER_SIZE 256

/* the default for TCP */
#define DEFAULT_LOWAT 1

/* expire time for resuming sessions */
#define DEFAULT_EXPIRE_TIME 3600

/* the maximum size of encrypted packets */
#define DEFAULT_MAX_RECORD_SIZE 16384
#define RECORD_HEADER_SIZE 5
#define MAX_RECORD_SEND_SIZE (size_t)session->security_parameters.max_record_send_size
#define MAX_RECORD_RECV_SIZE (size_t)session->security_parameters.max_record_recv_size
#define MAX_PAD_SIZE 255
#define EXTRA_COMP_SIZE 2048
#define MAX_RECORD_OVERHEAD MAX_PAD_SIZE+EXTRA_COMP_SIZE
#define MAX_RECV_SIZE MAX_RECORD_OVERHEAD+MAX_RECORD_RECV_SIZE+RECORD_HEADER_SIZE

#define HANDSHAKE_HEADER_SIZE 4

/* defaults for verification functions
 */
#define DEFAULT_VERIFY_DEPTH 32
#define DEFAULT_VERIFY_BITS 16*1024

#define DECR_LEN(len, x) do { len-=x; if (len<0) {gnutls_assert(); return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;} } while (0)
#define DECR_LENGTH_RET(len, x, RET) do { len-=x; if (len<0) {gnutls_assert(); return RET;} } while (0)
#define DECR_LENGTH_COM(len, x, COM) do { len-=x; if (len<0) {gnutls_assert(); COM;} } while (0)

#define HASH2MAC(x) ((gnutls_mac_algorithm_t)x)

/* TODO rm */
/* Additional cast to bring void* to a type castable to int. */
#define GNUTLS_POINTER_TO_INT_CAST (long)

#define GNUTLS_POINTER_TO_INT(_) ((int) GNUTLS_POINTER_TO_INT_CAST (_))
#define GNUTLS_INT_TO_POINTER(_) ((void*) GNUTLS_POINTER_TO_INT_CAST (_))

typedef unsigned char opaque;
typedef struct
  {
    opaque pint[3];
  } uint24;

#include <gnutls_mpi.h>

typedef enum change_cipher_spec_t
  {
    GNUTLS_TYPE_CHANGE_CIPHER_SPEC = 1
  } change_cipher_spec_t;

typedef enum handshake_state_t
  {
    STATE0 = 0, STATE1, STATE2,
    STATE3, STATE4, STATE5,
    STATE6, STATE7, STATE8, STATE9, STATE20 = 20, STATE21,
    STATE30 = 30, STATE31, STATE50 = 50, STATE60 = 60, STATE61, STATE62,
    STATE70, STATE71
  } handshake_state_t;

#include <gnutls_str.h>

typedef mhd_gtls_string mhd_gtls_buffer;

#define mhd_gtls_buffer_init(buf) mhd_gtls_string_init(buf, gnutls_malloc, gnutls_realloc, gnutls_free);
#define mhd_gtls_buffer_clear mhd_gtls_string_clear
#define mhd_gtls_buffer_append mhd_gtls_string_append_data

/* This is the maximum number of algorithms (ciphers or macs etc).
 * keep it synced with GNUTLS_MAX_ALGORITHM_NUM in gnutls.h
 */
#define MAX_ALGOS 16

#define MAX_CIPHERSUITES 256

typedef enum extensions_t
  { GNUTLS_EXTENSION_SERVER_NAME = 0,
    GNUTLS_EXTENSION_MAX_RECORD_SIZE = 1,
    GNUTLS_EXTENSION_CERT_TYPE = 9,
#ifdef ENABLE_OPRFI
    GNUTLS_EXTENSION_OPAQUE_PRF_INPUT = ENABLE_OPRFI,
#endif
    GNUTLS_EXTENSION_SRP = 12,
    GNUTLS_EXTENSION_INNER_APPLICATION = 37703
  } extensions_t;

typedef enum
  { CIPHER_STREAM, CIPHER_BLOCK} cipher_type_t;

typedef enum valid_session_t
  { VALID_TRUE, VALID_FALSE} valid_session_t;
typedef enum resumable_session_t
  { RESUME_TRUE,
    RESUME_FALSE
  } resumable_session_t;

/* Record Protocol */
typedef enum content_type_t
  {
    GNUTLS_CHANGE_CIPHER_SPEC = 20, GNUTLS_ALERT,
    GNUTLS_HANDSHAKE, GNUTLS_APPLICATION_DATA,
    GNUTLS_INNER_APPLICATION = 24
  } content_type_t;

#define GNUTLS_PK_ANY (gnutls_pk_algorithm_t)-1
#define GNUTLS_PK_NONE (gnutls_pk_algorithm_t)-2

/* STATE (stop) */

typedef void (*LOG_FUNC)(int,
                         const char *);

/* Store & Retrieve functions defines:  */
typedef struct mhd_gtls_auth_cred_st
  {
    gnutls_credentials_type_t algorithm;

    /* the type of credentials depends on algorithm
     */
    void *credentials;
    struct mhd_gtls_auth_cred_st *next;
  } auth_cred_st;

struct mhd_gtls_key
  {
    /* For DH KX */
    gnutls_datum_t key;
    mpi_t KEY;
    mpi_t client_Y;
    mpi_t client_g;
    mpi_t client_p;
    mpi_t dh_secret;
    /* for SRP */
    mpi_t A;
    mpi_t B;
    mpi_t u;
    mpi_t b;
    mpi_t a;
    mpi_t x;
    /* RSA: e, m
     */
    mpi_t rsa[2];

    /* this is used to hold the peers authentication data
     */
    /* auth_info_t structures SHOULD NOT contain malloced
     * elements. Check gnutls_session_pack.c, and gnutls_auth.c.
     * Rememember that this should be calloced!
     */
    void *auth_info;
    gnutls_credentials_type_t auth_info_type;
    int auth_info_size; /* needed in order to store to db for restoring
     */
    uint8_t crypt_algo;

    auth_cred_st *cred; /* used to specify keys/certificates etc */

    int certificate_requested;
  /* some ciphersuites use this
   * to provide client authentication.
   * 1 if client auth was requested
   * by the peer, 0 otherwise
   *** In case of a server this
   * holds 1 if we should wait
   * for a client certificate verify
   */
  };
typedef struct mhd_gtls_key * mhd_gtls_key_st;

/* STATE (cont) */
#include <gnutls_hash_int.h>
#include <gnutls_cipher_int.h>
#include <gnutls_compress_int.h>
#include <gnutls_cert.h>

typedef struct
  {
    uint8_t suite[2];
  } cipher_suite_st;

/* This structure holds parameters got from TLS extension
 * mechanism. (some extensions may hold parameters in auth_info_t
 * structures also - see SRP).
 */
typedef struct
  {
    opaque name[MAX_SERVER_NAME_SIZE];
    unsigned name_length;
    gnutls_server_name_type_t type;
  } server_name_st;

#define MAX_SERVER_NAME_EXTENSIONS 3
typedef struct
  {
    server_name_st server_names[MAX_SERVER_NAME_EXTENSIONS];
    /* limit server_name extensions */
    unsigned server_names_size;

    opaque srp_username[MAX_SRP_USERNAME + 1];

    /* TLS/IA data. */
    int gnutls_ia_enable, gnutls_ia_peer_enable;
    int gnutls_ia_allowskip, gnutls_ia_peer_allowskip;

    /* Used by extensions that enable supplemental data. */
    int do_recv_supplemental, do_send_supplemental;

    /* Opaque PRF input. */
    gnutls_oprfi_callback_func oprfi_cb;
    void *oprfi_userdata;
    opaque *oprfi_client;
    uint16_t oprfi_client_len;
    opaque *oprfi_server;
    uint16_t oprfi_server_len;
  } mhd_gtls_ext_st;

/* This flag indicates for an extension whether
 * it is useful to application level or TLS level only.
 * This is used to parse the application level extensions
 * before the user_hello callback is called.
 */
typedef enum tls_ext_parse_type_t
  {
    EXTENSION_ANY,
    EXTENSION_APPLICATION,
    EXTENSION_TLS
  } mhd_gtls_ext_parse_type_t;

/* auth_info_t structures now MAY contain malloced
 * elements.
 */

/* This structure and auth_info_t, are stored in the resume database,
 * and are restored, in case of resume.
 * Holds all the required parameters to resume the current
 * session.
 */

/* if you add anything in Security_Parameters struct, then
 * also modify CPY_COMMON in gnutls_constate.c
 */

/* Note that the security parameters structure is set up after the
 * handshake has finished. The only value you may depend on while
 * the handshake is in progress is the cipher suite value.
 */
typedef struct
  {
    gnutls_connection_end_t entity;
    gnutls_kx_algorithm_t kx_algorithm;
    /* we've got separate write/read bulk/macs because
     * there is a time in handshake where the peer has
     * null cipher and we don't
     */
    gnutls_cipher_algorithm_t read_bulk_cipher_algorithm;
    gnutls_mac_algorithm_t read_mac_algorithm;
    gnutls_compression_method_t read_compression_algorithm;

    gnutls_cipher_algorithm_t write_bulk_cipher_algorithm;
    gnutls_mac_algorithm_t write_mac_algorithm;
    gnutls_compression_method_t write_compression_algorithm;

    /* this is the ciphersuite we are going to use
     * moved here from internals in order to be restored
     * on resume;
     */
    cipher_suite_st current_cipher_suite;
    opaque master_secret[TLS_MASTER_SIZE];
    opaque client_random[TLS_RANDOM_SIZE];
    opaque server_random[TLS_RANDOM_SIZE];
    opaque session_id[TLS_MAX_SESSION_ID_SIZE];
    uint8_t session_id_size;
    time_t timestamp;
    mhd_gtls_ext_st extensions;

    /* The send size is the one requested by the programmer.
     * The recv size is the one negotiated with the peer.
     */
    uint16_t max_record_send_size;
    uint16_t max_record_recv_size;
    /* holds the negotiated certificate type */
    gnutls_certificate_type_t cert_type;
    gnutls_protocol_t version; /* moved here */
    /* For TLS/IA.  XXX: Move to IA credential? */
    opaque inner_secret[TLS_MASTER_SIZE];
  } mhd_gtls_security_param_st;

/* This structure holds the generated keys
 */
typedef struct
  {
    gnutls_datum_t server_write_mac_secret;
    gnutls_datum_t client_write_mac_secret;
    gnutls_datum_t server_write_IV;
    gnutls_datum_t client_write_IV;
    gnutls_datum_t server_write_key;
    gnutls_datum_t client_write_key;
    int generated_keys; /* zero if keys have not
     * been generated. Non zero
     * otherwise.
     */
  } mhd_gtls_cipher_specs_st;

typedef struct
  {
    cipher_hd_t write_cipher_state;
    cipher_hd_t read_cipher_state;
    comp_hd_t read_compression_state;
    comp_hd_t write_compression_state;
    gnutls_datum_t read_mac_secret;
    gnutls_datum_t write_mac_secret;
    uint64 read_sequence_number;
    uint64 write_sequence_number;
  } mhd_gtls_conn_stat_st;

typedef struct
  {
    unsigned int priority[MAX_ALGOS];
    unsigned int num_algorithms;
  } mhd_gtls_priority_st;

/* For the external api */
struct MHD_gtls_priority_st
  {
    mhd_gtls_priority_st cipher;
    mhd_gtls_priority_st mac;
    mhd_gtls_priority_st kx;
    mhd_gtls_priority_st compression;
    mhd_gtls_priority_st protocol;

    /* certificate type : x509, OpenPGP, etc. */
    mhd_gtls_priority_st cert_type;

    /* to disable record padding */
    int no_padding;
  };

/* DH and RSA parameters types.
 */
typedef struct MHD_gtls_dh_params_int
  {
    /* [0] is the prime, [1] is the generator.
     */
    mpi_t params[2];
  } mhd_gtls_dh_params_st;

typedef struct
  {
    mhd_gtls_dh_params_t dh_params;
    int free_dh_params;
    mhd_gtls_rsa_params_t rsa_params;
    int free_rsa_params;
  } mhd_gtls_internal_params_st;

typedef struct
  {
    opaque header[HANDSHAKE_HEADER_SIZE];
    /* this holds the number of bytes in the handshake_header[] */
    size_t header_size;
    /* this holds the length of the handshake packet */
    size_t packet_length;
    gnutls_handshake_description_t recv_type;
  } mhd_gtls_handshake_header_buffer_st;

typedef struct
  {
    mhd_gtls_buffer application_data_buffer; /* holds data to be delivered to application layer */
    mhd_gtls_buffer handshake_hash_buffer; /* used to keep the last received handshake
     * message */
    mac_hd_t handshake_mac_handle_sha; /* hash of the handshake messages */
    mac_hd_t handshake_mac_handle_md5; /* hash of the handshake messages */

    mhd_gtls_buffer handshake_data_buffer; /* this is a buffer that holds the current handshake message */
    mhd_gtls_buffer ia_data_buffer; /* holds inner application data (TLS/IA) */
    resumable_session_t resumable; /* TRUE or FALSE - if we can resume that session */
    handshake_state_t handshake_state; /* holds
     * a number which indicates where
     * the handshake procedure has been
     * interrupted. If it is 0 then
     * no interruption has happened.
     */

    valid_session_t valid_connection; /* true or FALSE - if this session is valid */

    int may_not_read; /* if it's 0 then we can read/write, otherwise it's forbiden to read/write
     */
    int may_not_write;
    int read_eof; /* non-zero if we have received a closure alert. */

    int last_alert; /* last alert received */
    int last_alert_level; /* last alert level */

    /* The last handshake messages sent or received.
     */
    int last_handshake_in;
    int last_handshake_out;

    /* this is the compression method we are going to use */
    gnutls_compression_method_t compression_method;

    /* priorities */
    struct MHD_gtls_priority_st priorities;

    /* resumed session */
    resumable_session_t resumed; /* RESUME_TRUE or FALSE - if we are resuming a session */
    mhd_gtls_security_param_st resumed_security_parameters;

    /* sockets internals */
    int lowat;

    /* These buffers are used in the handshake
     * protocol only. freed using _gnutls_handshake_io_buffer_clear();
     */
    mhd_gtls_buffer handshake_send_buffer;
    size_t handshake_send_buffer_prev_size;
    content_type_t handshake_send_buffer_type;
    gnutls_handshake_description_t handshake_send_buffer_htype;
    content_type_t handshake_recv_buffer_type;
    gnutls_handshake_description_t handshake_recv_buffer_htype;
    mhd_gtls_buffer handshake_recv_buffer;

    /* this buffer holds a record packet -mostly used for
     * non blocking IO.
     */
    mhd_gtls_buffer record_recv_buffer;
    mhd_gtls_buffer record_send_buffer; /* holds cached data
     * for the gnutls_io_write_buffered()
     * function.
     */
    size_t record_send_buffer_prev_size; /* holds the
     * data written in the previous runs.
     */
    size_t record_send_buffer_user_size; /* holds the
     * size of the user specified data to
     * send.
     */

    /* 0 if no peeked data was kept, 1 otherwise.
     */
    int have_peeked_data;

    int expire_time; /* after expire_time seconds this session will expire */
    struct mhd_gtls_mod_auth_st_int *auth_struct; /* used in handshake packets and KX algorithms */

    /* TODO rm */
    int v2_hello; /* 0 if the client hello is v3+.
     * non-zero if we got a v2 hello.
     */
    /* keeps the headers of the handshake packet
     */
    mhd_gtls_handshake_header_buffer_st handshake_header_buffer;

    /* this is the highest version available
     * to the peer. (advertized version).
     * This is obtained by the Handshake Client Hello
     * message. (some implementations read the Record version)
     */
    uint8_t adv_version_major;
    uint8_t adv_version_minor;

    /* if this is non zero a certificate request message
     * will be sent to the client. - only if the ciphersuite
     * supports it.
     */
    int send_cert_req;

    /* bits to use for DHE and DHA
     * use _gnutls_dh_get_prime_bits() and MHD_gnutls_dh_set_prime_bits()
     * to access it.
     */
    uint16_t dh_prime_bits;

    size_t max_handshake_data_buffer_size;

    /* PUSH & PULL functions.
     */
    mhd_gtls_pull_func _gnutls_pull_func;
    mhd_gtls_push_func _gnutls_push_func;
    /* Holds the first argument of PUSH and PULL
     * functions;
     */
    gnutls_transport_ptr_t transport_recv_ptr;
    gnutls_transport_ptr_t transport_send_ptr;

    /* post client hello callback (server side only)
     */
    gnutls_handshake_post_client_hello_func user_hello_func;

    /* Holds the record size requested by the
     * user.
     */
    uint16_t proposed_record_size;

    /* holds the selected certificate and key.
     * use mhd_gtls_selected_certs_deinit() and mhd_gtls_selected_certs_set()
     * to change them.
     */
    gnutls_cert *selected_cert_list;
    int selected_cert_list_length;
    gnutls_privkey *selected_key;
    int selected_need_free;

    /* holds the extensions we sent to the peer
     * (in case of a client)
     */
    uint16_t extensions_sent[MAX_EXT_TYPES];
    uint16_t extensions_sent_size;

    /* is 0 if we are to send the whole PGP key, or non zero
     * if the fingerprint is to be sent.
     */
    int pgp_fingerprint;

    /* This holds the default version that our first
     * record packet will have. */
    opaque default_record_version[2];

    int cbc_protection_hack;

    void *user_ptr;

    int enable_private; /* non zero to
     * enable cipher suites
     * which have 0xFF status.
     */

    /* Holds 0 if the last called function was interrupted while
     * receiving, and non zero otherwise.
     */
    int direction;

    /* If non zero the server will not advertize the CA's he
     * trusts (do not send an RDN sequence).
     */
    int ignore_rdn_sequence;

    /* This is used to set an arbitary version in the RSA
     * PMS secret. Can be used by clients to test whether the
     * server checks that version. (** only used in gnutls-cli-debug)
     */
    opaque rsa_pms_version[2];

    char *srp_username;
    char *srp_password;

    /* Here we cache the DH or RSA parameters got from the
     * credentials structure, or from a callback. That is to
     * minimize external calls.
     */
    mhd_gtls_internal_params_st params;

    /* This buffer is used by the record recv functions,
     * as a temporary store buffer.
     */
    gnutls_datum_t recv_buffer;

    /* To avoid using global variables, and especially on Windows where
     * the application may use a different errno variable than GnuTLS,
     * it is possible to use MHD_gnutls_transport_set_errno to set a
     * session-specific errno variable in the user-replaceable push/pull
     * functions.  This value is used by the send/recv functions.  (The
     * strange name of this variable is because 'errno' is typically
     * #define'd.)
     */
    int errnum;

    /* Function used to perform public-key signing operation during
     handshake.  Used by gnutls_sig.c:_gnutls_tls_sign(), see also
     MHD_gtls_sign_callback_set(). */
    gnutls_sign_func sign_func;
    void *sign_func_userdata;

  /* If you add anything here, check mhd_gtls_handshake_internal_state_clear().
   */
  } mhd_gtls_internals_st;

struct MHD_gtls_session_int
  {
    mhd_gtls_security_param_st security_parameters;
    mhd_gtls_cipher_specs_st cipher_specs;
    mhd_gtls_conn_stat_st connection_state;
    mhd_gtls_internals_st internals;
    mhd_gtls_key_st key;
  };

/* functions */
void mhd_gtls_set_current_version(mhd_gtls_session_t session,
                                 gnutls_protocol_t version);

void mhd_gtls_free_auth_info(mhd_gtls_session_t session);

/* These two macros return the advertized TLS version of
 * the peer.
 */
#define _gnutls_get_adv_version_major( session) \
	session->internals.adv_version_major

#define _gnutls_get_adv_version_minor( session) \
	session->internals.adv_version_minor

#define set_adv_version( session, major, minor) \
	session->internals.adv_version_major = major; \
	session->internals.adv_version_minor = minor

void mhd_gtls_set_adv_version(mhd_gtls_session_t,
                             gnutls_protocol_t);
gnutls_protocol_t mhd_gtls_get_adv_version(mhd_gtls_session_t);

#endif /* GNUTLS_INT_H */
