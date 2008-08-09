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
 * @brief: daemon TLS alert response test-case
 *
 * @author Sagie Amir
 */

#include "platform.h"
#include "microhttpd.h"
#include "gnutls_int.h"
#include "gnutls_datum.h"
#include "gnutls_record.h"
#include "tls_test_keys.h"

#define MHD_E_MEM "Error: memory error\n"
#define MHD_E_SERVER_INIT "Error: failed to start server\n"
#define MHD_E_FAILED_TO_CONNECT "Error: server connection could not be established\n"

const char *ca_cert_file_name = "ca_cert_pem";
const char *test_file_name = "https_test_file";
const char test_file_data[] = "Hello World\n";

struct CBC
{
  char *buf;
  size_t pos;
  size_t size;
};

/* HTTP access handler call back */
static int
http_ahc (void *cls, struct MHD_Connection *connection,
          const char *url, const char *method, const char *upload_data,
          const char *version, unsigned int *upload_data_size, void **ptr)
{
  return 0;
}

static int
setup (gnutls_session_t * session,
       gnutls_datum_t * key,
       gnutls_datum_t * cert, gnutls_certificate_credentials_t * xcred)
{
  int ret;
  const char ** err_pos;

  gnutls_certificate_allocate_credentials (xcred);

  _gnutls_set_datum_m (key, srv_key_pem, strlen (srv_key_pem), &malloc);
  _gnutls_set_datum_m (cert, srv_self_signed_cert_pem,
                       strlen (srv_self_signed_cert_pem), &malloc);

  gnutls_certificate_set_x509_key_mem (*xcred, cert, key,
                                       GNUTLS_X509_FMT_PEM);

  gnutls_init (session, GNUTLS_CLIENT);
  ret = gnutls_priority_set_direct (*session, "PERFORMANCE", err_pos);
  if (ret < 0)
    {
      return -1;
    }

  gnutls_credentials_set (*session, MHD_GNUTLS_CRD_CERTIFICATE, xcred);
  return 0;
}

static int
teardown (gnutls_session_t session,
          gnutls_datum_t * key,
          gnutls_datum_t * cert, gnutls_certificate_credentials_t xcred)
{

  _gnutls_free_datum_m (key, free);
  _gnutls_free_datum_m (cert, free);

  gnutls_deinit (session);

  gnutls_certificate_free_credentials (xcred);
  return 0;
}

/*
 * assert server closes connection upon receiving a
 * close notify alert message.
 *
 * @param session: an initialized TLS session
 */
static int
test_alert_close_notify (gnutls_session_t session)
{
  int sd, ret;
  struct sockaddr_in sa;

  sd = socket (AF_INET, SOCK_STREAM, 0);
  memset (&sa, '\0', sizeof (struct sockaddr_in));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (42433);
  inet_pton (AF_INET, "127.0.0.1", &sa.sin_addr);

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

  ret = connect (sd, &sa, sizeof (struct sockaddr_in));

  if (ret < 0)
    {
      fprintf (stderr, "Error: %s)\n", MHD_E_FAILED_TO_CONNECT);
      return -1;
    }

  ret = gnutls_handshake (session);
  if (ret < 0)
    {
      return -1;
    }

  gnutls_alert_send (session, GNUTLS_AL_FATAL, GNUTLS_A_CLOSE_NOTIFY);

  /* check server responds with a 'close-notify' */
  _gnutls_recv_int (session, GNUTLS_ALERT, GNUTLS_HANDSHAKE_FINISHED, 0, 0);

  close (sd);
  /* CLOSE_NOTIFY */
  if (session->internals.last_alert != GNUTLS_A_CLOSE_NOTIFY)
    {
      return -1;
    }

  return 0;
}

/*
 * assert server closes connection upon receiving a
 * fatal unexpected_message alert.
 *
 * @param session: an initialized TLS session
 */
static int
test_alert_unexpected_message (gnutls_session_t session)
{
  int sd, ret;
  struct sockaddr_in sa;

  sd = socket (AF_INET, SOCK_STREAM, 0);
  memset (&sa, '\0', sizeof (struct sockaddr_in));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (42433);
  inet_pton (AF_INET, "127.0.0.1", &sa.sin_addr);

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

  ret = connect (sd, &sa, sizeof (struct sockaddr_in));

  if (ret < 0)
    {
      fprintf (stderr, "Error: %s)\n", MHD_E_FAILED_TO_CONNECT);
      return -1;
    }

  ret = gnutls_handshake (session);
  if (ret < 0)
    {
      return -1;
    }

  gnutls_alert_send (session, GNUTLS_AL_FATAL, GNUTLS_A_UNEXPECTED_MESSAGE);
  usleep (100);

  /* TODO better RST trigger */
  if (send (sd, "", 1, 0) == 0)
    {
      return -1;
    }

  close (sd);
  return 0;
}

int
main (int argc, char *const *argv)
{
  int errorCount = 0;;
  struct MHD_Daemon *d;
  gnutls_session_t session;
  gnutls_datum_t key;
  gnutls_datum_t cert;
  gnutls_certificate_credentials_t xcred;

  gnutls_global_init ();
  gnutls_global_set_log_level (11);

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

  setup (&session, &key, &cert, &xcred);
  errorCount += test_alert_close_notify (session);
  teardown (session, &key, &cert, xcred);

  setup (&session, &key, &cert, &xcred);
  errorCount += test_alert_unexpected_message (session);
  teardown (session, &key, &cert, xcred);

  if (errorCount != 0)
    fprintf (stderr, "Failed test: %s.\n", argv[0]);

  MHD_stop_daemon (d);
  gnutls_global_deinit ();

  return errorCount != 0;
}
