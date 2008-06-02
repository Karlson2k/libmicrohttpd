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
 * @file https_server_example.c
 * @brief a simple https file server using TLS.
 * 
 * This example assumes the existence of a private key file named "key.pem"
 * and a server certificate file named "cert.pem". File path for these should be
 * provided as command-line arguments. 'certtool' may be used to generate these if
 * missing. 
 * 
 * Access server with your browser of choice or with curl : 
 * 
 *   curl --insecure --tlsv1 --ciphers AES256-SHA <url>
 * 
 * @author LV-426
 */

#include "config.h"
#include <microhttpd.h>
#include "internal.h"

#include <stdlib.h>
#ifndef MINGW
#include <unistd.h>
#endif
#include <string.h>
#include <stdio.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h>

#define BUF_SIZE 1024
#define MAX_URL_LEN 255

#define KEYFILE "key.pem"
#define CERTFILE "cert.pem"

// TODO remove if unused
#define CAFILE "ca.pem"
#define CRLFILE "crl.pem"

#define PAGE_NOT_FOUND "<html><head><title>File not found</title></head><body>File not found</body></html>"

gnutls_session_t
initialize_tls_session (struct MHD_Connection *connection)
{
  gnutls_session_t session;

  gnutls_init (&session, GNUTLS_SERVER);

  /* sets cipher priorities */
  gnutls_priority_set (session, connection->daemon->priority_cache);

  /* set needed credentials for certificate authentication. */
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE,
                          connection->daemon->x509_cret);

  return session;
}

static int
file_reader (void *cls, size_t pos, char *buf, int max)
{
  FILE *file = cls;

  fseek (file, pos, SEEK_SET);
  return fread (buf, 1, max, file);
}

/* HTTPS access handler call back */
static int
https_ahc (void *cls,
           struct MHD_Connection *connection,
           const char *url,
           const char *method,
           const char *upload_data,
           const char *version, unsigned int *upload_data_size, void **ptr)
{
  /* loopback HTTP socket */
  int loopback_sd, err;
  ssize_t ret;
  struct sockaddr_in servaddr4;
  const struct sockaddr *servaddr;
  struct sockaddr_in loopback_sa;
  socklen_t addrlen;

  gnutls_session_t session;
  static int aptr;
  struct MHD_Response *response;
  char buffer[BUF_SIZE];

  printf ("accepted connection from %d\n", connection->addr->sin_addr);

  session = initialize_tls_session (connection);

  gnutls_transport_set_ptr (session, connection->socket_fd);

  ret = gnutls_handshake (session);

  if (ret < 0)
    {
      /* set connection as closed */
      connection->socket_fd = 1;
      gnutls_deinit (session);
      fprintf (stderr, "*** Handshake has failed (%s)\n\n",
               gnutls_strerror (ret));
      return MHD_NO;
    }

  printf ("TLS Handshake completed\n");
  connection->state = MHDS_HANDSHAKE_COMPLETE;

  /* initialize loopback socket */
  loopback_sd = socket (AF_INET, SOCK_STREAM, 0);
  memset (&loopback_sa, '\0', sizeof (loopback_sa));
  loopback_sa.sin_family = AF_INET;

  // TODO solve magic number issue - the http's daemons port must be shared with the https daemon - rosolve data sharing point
  loopback_sa.sin_port = htons (50000);
  inet_pton (AF_INET, "127.0.0.1", &loopback_sa.sin_addr);

  /* connect loopback socket */
  err = connect (loopback_sd, (struct sockaddr *) &loopback_sa,
                 sizeof (loopback_sa));
  if (err < 0)
    {
      // TODO err handle
      fprintf (stderr, "Error : failed to create TLS loopback socket\n");
      exit (1);
    }

  /* 
   * This loop pipes data received through the TLS tunnel into the loopback connection.  
   * message encryption/decryption is acheived via 'gnutls_record_send' & gnutls_record_recv calls.
   */
  memset (buffer, 0, BUF_SIZE);
  if (gnutls_record_recv (session, buffer, BUF_SIZE) < 0)
    {
      fprintf (stderr, "\n*** Received corrupted "
               "data(%d). Closing the connection.\n\n", ret);
      connection->socket_fd = -1;
      gnutls_deinit (session);
      return MHD_NO;
    }

  if (write (loopback_sd, buffer, BUF_SIZE) < 0)
    {
      printf ("failed to write to TLS loopback socket\n");
      connection->socket_fd = -1;
      gnutls_deinit (session);
      return MHD_NO;
    }

  for (;;)
    {
      memset (buffer, 0, BUF_SIZE);

      ret = read (loopback_sd, buffer, BUF_SIZE);

      if (ret < 0)
        {
          printf ("failed to read from TLS loopback socket\n");
          break;
        }

      if (ret == 0)
        {
          break;
        }

      /* echo data back to the client */
      ret = gnutls_record_send (session, buffer, ret);
      if (ret < 0)
        {
          printf ("failed to write to TLS socket\n");
          break;
        }
    }
  /* mark connection as closed */
  connection->socket_fd = -1;
  gnutls_deinit (session);

  return MHD_YES;
}

/* HTTP access handler call back */
static int
http_ahc (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *upload_data,
          const char *version, unsigned int *upload_data_size, void **ptr)
{
  static int aptr;
  static char full_url[MAX_URL_LEN];
  struct MHD_Response *response;
  int ret;
  FILE *file;
  struct stat buf;

  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
    return MHD_NO;              /* unexpected method */
  if (&aptr != *ptr)
    {
      /* do never respond on first call */
      *ptr = &aptr;
      return MHD_YES;
    }
  *ptr = NULL;                  /* reset when done */

  /* assemble full url */
  strcpy (full_url, connection->daemon->doc_root);
  strncat (full_url, url,
           MAX_URL_LEN - strlen (connection->daemon->doc_root) - 1);

  file = fopen (full_url, "r");
  if (file == NULL)
    {
      response = MHD_create_response_from_data (strlen (PAGE_NOT_FOUND),
                                                (void *) PAGE_NOT_FOUND,
                                                MHD_NO, MHD_NO);
      ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
      MHD_destroy_response (response);
    }
  else
    {
      stat (&url[1], &buf);
      response = MHD_create_response_from_callback (buf.st_size, 32 * 1024,     /* 32k PAGE_NOT_FOUND size */
                                                    &file_reader, file,
                                                    (MHD_ContentReaderFreeCallback)
                                                    & fclose);
      ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
      MHD_destroy_response (response);
    }
  return ret;
}

int
main (int argc, char *const *argv)
{
  char keyfile[255] = KEYFILE;
  char certfile[255] = CERTFILE;
  struct MHD_Daemon *HTTP_daemon;
  struct MHD_Daemon *TLS_daemon;

  /* look for HTTPS arguments */
  if (argc < 5)
    {
      printf
        ("Usage : %s HTTP-PORT SECONDS-TO-RUN HTTPS-PORT X.509_FILE_PATH\n",
         argv[0]);
      return 1;
    }

  // TODO check if this is truly necessary -  disallow usage of the blocking /dev/random */
  // gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  HTTP_daemon =
    MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG,
                      atoi (argv[1]), NULL, NULL, &http_ahc, MHD_OPTION_END);

  if (HTTP_daemon == NULL)
    {
      printf ("Error: failed to start HTTP_daemon");
      return 1;
    }

  TLS_daemon = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_DEBUG
                                 | MHD_USE_SSL, atoi (argv[3]),
                                 NULL,
                                 NULL, &https_ahc,
                                 NULL, MHD_OPTION_CONNECTION_TIMEOUT, 256,
                                 MHD_OPTION_HTTPS_KEY_PATH, argv[4],
                                 MHD_OPTION_HTTPS_CERT_PATH, argv[4],
                                 MHD_OPTION_END);

  if (TLS_daemon == NULL)
    {
      printf ("Error: failed to start TLS_daemon");
      return 1;
    }

  sleep (atoi (argv[2]));

  MHD_stop_daemon (HTTP_daemon);

  MHD_stop_daemon (TLS_daemon);

  return 0;
}
