/*
  This file is part of libmicrohttpd
  (C) 2007, 2010 Christian Grothoff
  
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
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.
*/

/**
 * @file tls_daemon_options_test.c
 * @brief  Testcase for libmicrohttpd HTTPS GET operations
 * @author Sagie Amir
 */

#include "platform.h"
#include "microhttpd.h"
#include <sys/stat.h>
#include <limits.h>
#include <gcrypt.h>
#include "tls_test_common.h"

extern const char srv_key_pem[];
extern const char srv_self_signed_cert_pem[];

int curl_check_version (const char *req_version, ...);

/**
 * test server refuses to negotiate connections with unsupported protocol versions
 *
 */
/* TODO rm test_fd */
int
test_unmatching_ssl_version (void * cls, char *cipher_suite,
                             int curl_req_ssl_version)
{
  struct CBC cbc;
  if (NULL == (cbc.buf = malloc (sizeof (char) * 256)))
    {
      fprintf (stderr, "Error: failed to allocate: %s\n",
               strerror (errno));
      return -1;
    }
  cbc.size = 256;
  cbc.pos = 0;

  char url[255];
  if (gen_test_file_url (url, DEAMON_TEST_PORT))
    {
      free (cbc.buf);
      return -1;
    }

  /* assert daemon *rejected* request */
  if (CURLE_OK ==
      send_curl_req (url, &cbc, cipher_suite, curl_req_ssl_version))
    {
      free (cbc.buf);
      return -1;
    }

  free (cbc.buf);
  return 0;
}

/* setup a temporary transfer test file */
int
main (int argc, char *const *argv)
{
  unsigned int errorCount = 0;

  int daemon_flags =
    MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL | MHD_USE_DEBUG;
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
  if (curl_check_version (MHD_REQ_CURL_VERSION))
    {
      return -1;
    }

  if (0 != curl_global_init (CURL_GLOBAL_ALL))
    {
      fprintf (stderr, "Error: %s\n", strerror (errno));
      return -1;
    }
  errorCount +=
    test_wrap ("TLS1.0-AES-SHA1",
	       &test_https_transfer, NULL, daemon_flags,
	       "AES128-SHA1",
	       CURL_SSLVERSION_TLSv1,
	       MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
	       MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
	       MHD_OPTION_HTTPS_PRIORITIES, "NONE:+VERS-TLS1.0:+AES-128-CBC:+SHA1:+RSA:+COMP-NULL",
	       MHD_OPTION_END);
  errorCount +=
    test_wrap ("TLS1.0-AES-SHA1",
	       &test_https_transfer, NULL, daemon_flags,
	       "AES128-SHA1",
	       CURL_SSLVERSION_SSLv3,
	       MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
	       MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
	       MHD_OPTION_HTTPS_PRIORITIES, "NONE:+VERS-SSL3.0:+AES-128-CBC:+SHA1:+RSA:+COMP-NULL",
	       MHD_OPTION_END);

  errorCount +=
    test_wrap ("SSL3.0-AES-SHA1",
	       &test_https_transfer, NULL, daemon_flags,
	       "AES128-SHA1",
	       CURL_SSLVERSION_SSLv3,
	       MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
	       MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
	       MHD_OPTION_HTTPS_PRIORITIES, "NONE:+VERS-SSL3.0:+AES-128-CBC:+SHA1:+RSA:+COMP-NULL",
	       MHD_OPTION_END);
#if 0
  /* manual inspection of the handshake suggests that CURL will
     request TLSv1, we send back "SSL3" and CURL takes it *despite*
     being configured to speak SSL3-only.  Notably, the other way
     round (have curl request SSL3, respond with TLSv1 only)
     is properly refused by CURL.  Either way, this does NOT seem
     to be a bug in MHD/gnuTLS but rather in CURL; hence this
     test is commented out here... */
  errorCount +=
    test_wrap ("unmatching version: SSL3 vs. TLS", &test_unmatching_ssl_version,
               NULL, daemon_flags, "AES256-SHA", CURL_SSLVERSION_TLSv1,
               MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
               MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
               MHD_OPTION_CIPHER_ALGORITHM, "SSL3", MHD_OPTION_END);
#endif

  errorCount +=
    test_wrap ("TLS1.0 vs SSL3",
	       &test_unmatching_ssl_version, NULL, daemon_flags,
	       "AES256-SHA",
	       CURL_SSLVERSION_SSLv3,
	       MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
	       MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
	       MHD_OPTION_HTTPS_PRIORITIES, "NONE:+VERS-TLS1.0:+AES-256-CBC:+SHA1:+RSA:+COMP-NULL",
	       MHD_OPTION_END);
  curl_global_cleanup ();

  return errorCount != 0;
}
