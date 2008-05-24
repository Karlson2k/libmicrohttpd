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
 * @brief a simple echo server using TLS. echo input from client until 'exit' message is received. 
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

#define DH_BITS 1024
#define MAX_BUF 1024
/* server credintials */
gnutls_anon_server_credentials_t anoncred;

/* server Diffie-Hellman parameters */
static gnutls_dh_params_t dh_params;


/* Generate Diffie Hellman parameters - for use with DHE kx algorithms. */
static int
generate_dh_params (void)
{

  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_generate2 (dh_params, DH_BITS);
  return 0;
}

gnutls_session_t
initialize_tls_session (void)
{
  gnutls_session_t session;

  gnutls_init (&session, GNUTLS_SERVER);

  gnutls_priority_set_direct (session, "NORMAL:+ANON-DH", NULL);

  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

  gnutls_dh_set_prime_bits (session, DH_BITS);

  return session;
}

/* Accept Policy Callback */
static int
TLS_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *upload_data,
          const char *version, unsigned int *upload_data_size, void **ptr)
{
  gnutls_session_t session;
  static int aptr;
  struct MHD_Response *response;
  char buffer[MAX_BUF + 1];
  int ret;

  printf ("accepted connection from %d\n", connection->addr->sin_addr);

  session = initialize_tls_session ();

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

  /* simple echo loop. message encryption/decryption is acheived through 'gnutls_record_send'
   *  & gnutls_record_recv calls. */
  for (;;)
    {
      memset (buffer, 0, MAX_BUF + 1);
      ret = gnutls_record_recv (session, buffer, MAX_BUF);

      if (ret < 0)
        {
          fprintf (stderr, "\n*** Received corrupted "
                   "data(%d). Closing the connection.\n\n", ret);
          break;
        }
      else if (ret >= 0)
        {
          if (strcmp (buffer, "exit") == 0)
            {
              printf ("\n- Peer has closed the GNUTLS connection\n");
              break;
            }
          else
            {
              /* echo data back to the client */
              gnutls_record_send (session, buffer, strlen (buffer));
            }
        }
    }
  printf ("\n");

  /* mark connection as closed */
  connection->socket_fd = -1;

  gnutls_deinit (session);

  return ret;
}

int
main (int argc, char *const *argv)
{
  struct MHD_Daemon *daemon;
  struct MHD_Daemon *TLS_daemon;

  /* look for HTTPS port argument */
  if (argc < 4)
    {
      printf ("Usage : %s HTTP-PORT SECONDS-TO-RUN HTTPS-PORT\n", argv[0]);
      return 1;
    }

  gnutls_global_init ();

  gnutls_anon_allocate_server_credentials (&anoncred);

  generate_dh_params ();

  gnutls_anon_set_server_dh_params (anoncred, dh_params);

  TLS_daemon = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION
                                  | MHD_USE_DEBUG | MHD_USE_SSL,
                                  atoi (argv[3]), NULL, NULL, &TLS_echo, NULL,
                                  MHD_OPTION_END);

  if (TLS_daemon == NULL)
    return 1;
  sleep (atoi (argv[2]));

  MHD_stop_daemon (daemon);

  gnutls_anon_free_server_credentials (anoncred);

  gnutls_global_deinit ();
  return 0;
}
