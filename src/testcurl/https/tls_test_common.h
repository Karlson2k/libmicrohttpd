/*
 This file is part of libmicrohttpd
 Copyright (C) 2007 Christian Grothoff

 libmicrohttpd is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published
 by the Free Software Foundation; either version 2, or (at your
 option) any later version.

 libmicrohttpd is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with libmicrohttpd; see the file COPYING.  If not, write to the
 Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 Boston, MA 02110-1301, USA.
 */

#ifndef TLS_TEST_COMMON_H_
#define TLS_TEST_COMMON_H_

#include "platform.h"
#include "microhttpd.h"
#include <curl/curl.h>
#include <sys/stat.h>
#include <limits.h>
#include <gnutls/gnutls.h>

#ifndef CURL_VERSION_BITS
#define CURL_VERSION_BITS(x,y,z) ((x) << 16 | (y) << 8 | (z))
#endif /* ! CURL_VERSION_BITS */
#ifndef CURL_AT_LEAST_VERSION
#define CURL_AT_LEAST_VERSION(x,y,z) \
  (LIBCURL_VERSION_NUM >= CURL_VERSION_BITS (x, y, z))
#endif /* ! CURL_AT_LEAST_VERSION */

#define test_data "Hello World\n"
#define ca_cert_file_name SRCDIR "/test-ca.crt"

#define EMPTY_PAGE \
  "<html><head><title>Empty page</title></head><body>Empty page</body></html>"
#define PAGE_NOT_FOUND \
  "<html><head><title>File not found</title></head><body>File not found</body></html>"

#define MHD_E_MEM "Error: memory error\n"
#define MHD_E_SERVER_INIT "Error: failed to start server\n"
#define MHD_E_TEST_FILE_CREAT "Error: failed to setup test file\n"
#define MHD_E_CERT_FILE_CREAT "Error: failed to setup test certificate\n"
#define MHD_E_KEY_FILE_CREAT "Error: failed to setup test certificate\n"
#define MHD_E_FAILED_TO_CONNECT \
  "Error: server connection could not be established\n"

#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro) / sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */


/* The local copy if GnuTLS IDs to avoid long #ifdefs list with various
 * GnuTLS versions */
/**
 * The list of know (at the moment of writing) GnuTLS IDs of TLS versions.
 * Can be safely casted to/from @a gnutls_protocol_t.
 */
enum know_gnutls_tls_id
{
  KNOWN_BAD = 0,       /**< No TLS */
  KNOWN_TLS_SSLv3 = 1, /**< GNUTLS_SSL3 */
  KNOWN_TLS_V1_0 =  2, /**< GNUTLS_TLS1_0 */
  KNOWN_TLS_V1_1 =  3, /**< GNUTLS_TLS1_1 */
  KNOWN_TLS_V1_2 =  4, /**< GNUTLS_TLS1_2 */
  KNOWN_TLS_V1_3 =  5, /**< GNUTLS_TLS1_3 */
  KNOWN_TLS_MIN = KNOWN_TLS_SSLv3, /**< Minimum valid value */
  KNOWN_TLS_MAX = KNOWN_TLS_V1_3   /**< Maximum valid value */
};

#define KNOW_TLS_IDS_COUNT 6 /* KNOWN_TLS_MAX + 1 */
/**
 * Map @a know_gnutls_tls_ids values to printable names.
 */
extern const char *tls_names[KNOW_TLS_IDS_COUNT];

/**
 * Map @a know_gnutls_tls_ids values to GnuTLS priorities strings.
 */
extern const char *priorities_map[KNOW_TLS_IDS_COUNT];

/**
 * Map @a know_gnutls_tls_ids values to libcurl @a CURLOPT_SSLVERSION value.
 */
extern const long libcurl_tls_vers_map[KNOW_TLS_IDS_COUNT];

#if CURL_AT_LEAST_VERSION (7,54,0)
/**
 * Map @a know_gnutls_tls_ids values to libcurl @a CURLOPT_SSLVERSION value
 * for maximum supported TLS version.
 */
extern const long libcurl_tls_max_vers_map[KNOW_TLS_IDS_COUNT];
#endif /* CURL_AT_LEAST_VERSION(7,54,0) */

struct https_test_data
{
  void *cls;
  uint16_t port;
  const char *cipher_suite;
  int proto_version;
};

struct CBC
{
  char *buf;
  size_t pos;
  size_t size;
};

int
curl_tls_is_gnutls (void);

int
curl_tls_is_openssl (void);

int
curl_tls_is_nss (void);

int
curl_tls_is_schannel (void);

int
curl_tls_is_sectransport (void);

/**
 * perform cURL request for file
 */
unsigned int
test_daemon_get (void *cls,
                 const char *cipher_suite, int proto_version,
                 uint16_t port, int ver_peer);

void
print_test_result (unsigned int test_outcome,
                   const char *test_name);

size_t
copyBuffer (void *ptr, size_t size, size_t nmemb, void *ctx);

enum MHD_Result
http_ahc (void *cls, struct MHD_Connection *connection,
          const char *url, const char *method, const char *upload_data,
          const char *version, size_t *upload_data_size, void **req_cls);

enum MHD_Result
http_dummy_ahc (void *cls, struct MHD_Connection *connection,
                const char *url, const char *method, const char *upload_data,
                const char *version, size_t *upload_data_size,
                void **req_cls);


/**
 * compile test URI
 *
 * @param[out] uri - char buffer into which the url is compiled
 * @param uri_len number of bytes available in @a url
 * @param port port to use for the test
 * @return 1 on error
 */
unsigned int
gen_test_uri (char *uri,
              size_t uri_len,
              uint16_t port);

CURLcode
send_curl_req (char *url,
               struct CBC *cbc,
               const char *cipher_suite,
               int proto_version);

unsigned int
test_https_transfer (void *cls,
                     uint16_t port,
                     const char *cipher_suite,
                     int proto_version);

unsigned int
setup_session (gnutls_session_t *session,
               gnutls_certificate_credentials_t *xcred);

unsigned int
teardown_session (gnutls_session_t session,
                  gnutls_certificate_credentials_t xcred);

unsigned int
test_wrap (const char *test_name, unsigned int
           (*test_function)(void *cls, uint16_t port, const char *cipher_suite,
                            int proto_version), void *cls,
           uint16_t port,
           unsigned int daemon_flags, const char *cipher_suite,
           int proto_version, ...);

int testsuite_curl_global_init (void);

#endif /* TLS_TEST_COMMON_H_ */
