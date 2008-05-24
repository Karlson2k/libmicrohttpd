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
 * @file https_echo_client.c
 * @brief a simple echo client to use in conjuction with the echo TLS server. 
 * @author LV-426
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

#define MAX_BUF 1024
#define SA struct sockaddr
#define MSG "GET / HTTP/1.0\r\n\r\n"

extern int tcp_connect (void);
extern void tcp_close (int sd);

int
main (int argc, char **argv)
{
  int ret, sd, ii, err;
  gnutls_session_t session;
  char buffer[MAX_BUF + 1];
  gnutls_anon_client_credentials_t anoncred;

  struct sockaddr_in servaddr4;
  const struct sockaddr *servaddr;
  struct sockaddr_in sa;
  socklen_t addrlen;

  if (argc < 2)
    {
      printf ("Usage : %s SERVER-PORT\n", argv[0]);
      return 1;
    }

  gnutls_global_init ();

  gnutls_anon_allocate_client_credentials (&anoncred);

  /* Initialize TLS session */
  gnutls_init (&session, GNUTLS_CLIENT);

  /* Use default priorities */
  gnutls_priority_set_direct (session, "PERFORMANCE:+ANON-DH:!ARCFOUR-128",
                              NULL);

  /* put the anonymous credentials to the current session */
  gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

  sd = socket (AF_INET, SOCK_STREAM, 0);
  memset (&sa, '\0', sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (atoi (argv[1]));
  inet_pton (AF_INET, "127.0.0.1", &sa.sin_addr);

  /* connect to the peer */
  err = connect (sd, (struct sockaddr *) &sa, sizeof (sa));
  if (err < 0)
    {
      fprintf (stderr, "Connect error\n");
      exit (1);
    }

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

  /* Perform the TLS handshake */
  ret = gnutls_handshake (session);

  if (ret < 0)
    {
      fprintf (stderr, "*** Handshake failed\n");
      gnutls_perror (ret);
      goto end;
    }
  else
    {
      printf ("- Handshake was completed\n");
    }

  for (;;)
    {
       /**/ scanf ("%s", buffer);

      if (strcmp (buffer, "exit") == 0)
        {
          gnutls_record_send (session, buffer, strlen (MSG));
          break;
        }
      gnutls_record_send (session, buffer, strlen (MSG));

      ret = gnutls_record_recv (session, buffer, MAX_BUF);
      if (ret == 0)
        {
          printf ("- Peer has closed the TLS connection\n");
          goto end;
        }
      else if (ret < 0)
        {
          fprintf (stderr, "*** Error: %s\n", gnutls_strerror (ret));
          break;
        }

      printf ("- Received %d bytes: ", ret);
      for (ii = 0; ii < ret; ii++)
        {
          fputc (buffer[ii], stdout);
        }
      fputs ("\n", stdout);
    }

end:

  shutdown (sd, SHUT_RDWR);
  close (sd);

  gnutls_deinit (session);

  gnutls_anon_free_client_credentials (anoncred);

  gnutls_global_deinit ();

  return 0;
}
