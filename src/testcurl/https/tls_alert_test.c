/*
 This file is part of libmicrohttpd
 (C) 2007 Christian Grothoff

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
 * @file mhds_get_test.c
 * @brief  Testcase for libmicrohttpd HTTPS GET operations
 * @author Sagie Amir
 */

#include "config.h"
#include "plibc.h"
#include "microhttpsd.h"
#include <errno.h>

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>


#define MHD_E_MEM "Error: memory error\n"
#define MHD_E_SERVER_INIT "Error: failed to start server\n"

#include "gnutls_int.h"
#include "gnutls_datum.h"
#include "tls_test_keys.h"

extern int curl_check_version (const char *req_version, ...);

const char *ca_cert_file_name = "ca_cert_pem";
const char *test_file_name = "https_test_file";
const char test_file_data[] = "Hello World\n";

struct CBC
{
  char *buf;
  size_t pos;
  size_t size;
};

static int
file_reader (void *cls, size_t pos, char *buf, int max)
{
  FILE *file = cls;
  fseek (file, pos, SEEK_SET);
  return fread (buf, 1, max, file);
}

/* HTTP access handler call back */
static int
http_ahc (void *cls, struct MHD_Connection *connection,
          const char *url, const char *method, const char *upload_data,
          const char *version, unsigned int *upload_data_size, void **ptr)
{
  return 0;
}

static int
test_alert_response ()
{
  int sd, ret;
  char *err_pos;
  struct sockaddr_in sa;
  gnutls_priority_t priority_cache;
  gnutls_session_t session;
  gnutls_certificate_credentials_t xcred;

  gnutls_global_init ();

  gnutls_datum_t key;
  gnutls_datum_t cert;

  gnutls_certificate_allocate_credentials (&xcred);

  _gnutls_set_datum_m (&key, srv_key_pem, strlen (srv_key_pem), &malloc);
  _gnutls_set_datum_m (&cert, srv_self_signed_cert_pem,
                       strlen (srv_self_signed_cert_pem), &malloc);

  gnutls_certificate_set_x509_key_mem (xcred, &cert, &key,
                                       GNUTLS_X509_FMT_PEM);

  ret = gnutls_priority_init (&priority_cache,
                              "NONE:+VERS-TLS1.0:+AES-256-CBC:+RSA:+SHA1:+COMP-NULL",
                              &err_pos);
  if (ret < 0)
    {
      // ...
    }

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);

  sd = socket (AF_INET, SOCK_STREAM, 0);
  memset (&sa, '\0', sizeof (struct sockaddr_in));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (42433);
  inet_pton (AF_INET, "127.0.0.1", &sa.sin_addr);

  ret = connect (sd, &sa, sizeof (struct sockaddr_in));

  if (ret < 0)
    {
      // ...
    }

  ret = gnutls_handshake (session);

  if (ret < 0)
    {
      // ...
    }

  gnutls_alert_send (session, GNUTLS_AL_FATAL, GNUTLS_A_CLOSE_NOTIFY);

  /* check server responds with a 'close-notify' */
  _gnutls_recv_int (session, GNUTLS_ALERT, GNUTLS_HANDSHAKE_FINISHED, 0, 0);

  /* CLOSE_NOTIFY */
  if (session->internals.last_alert != GNUTLS_A_CLOSE_NOTIFY)
    {
      return -1;
    }

  close (sd);

  gnutls_deinit (session);

  gnutls_certificate_free_credentials (xcred);

  gnutls_global_deinit ();

  return 0;

}

int
main (int argc, char *const *argv)
{
  int ret, errorCount = 0;;
  struct MHD_Daemon *d;

  if (curl_check_version (MHD_REQ_CURL_VERSION, MHD_REQ_CURL_SSL_VERSION))
    {
      return -1;
    }

  d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL |
                        MHD_USE_DEBUG, 42433,
                        NULL, NULL, &http_ahc, NULL,
                        MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
                        MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
                        MHD_OPTION_END);

  if (d == NULL)
    {
      fprintf (stderr, MHD_E_SERVER_INIT);
      return -1;
    }

  errorCount += test_alert_response ();

  if (errorCount != 0)
    fprintf (stderr, "Error (code: %u)\n", errorCount);

  MHD_stop_daemon (d);
  return errorCount != 0;
}
