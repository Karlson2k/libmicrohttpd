/*
     This file is part of libmicrohttpd
     Copyright (C) 2016 Christian Grothoff

     libmicrohttpd is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
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

/**
 * @file test_upgrade_ssl.c
 * @brief  Testcase for libmicrohttpd upgrading a connection
 * @author Christian Grothoff
 */

#include "platform.h"
#include "microhttpd.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifndef WINDOWS
#include <unistd.h>
#endif

#include <pthread.h>
#include "mhd_sockets.h"
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif /* HAVE_NETINET_IP_H */
#include "mhd_sockets.h"
#include "test_upgrade_common.c"

#include "../testcurl/https/tls_test_keys.h"


/**
 * Fork child that connects via OpenSSL to our @a port.  Allows us to
 * talk to our port over a socket in @a sp without having to worry
 * about TLS.
 *
 * @param location where the socket is returned
 * @return -1 on error, otherwise PID of SSL child process
 */
static pid_t
openssl_connect (int *sock,
                 uint16_t port)
{
  pid_t chld;
  int sp[2];
  char destination[30];

  if (0 != socketpair (AF_UNIX,
                       SOCK_STREAM,
                       0,
                       sp))
    return -1;
  chld = fork ();
  if (0 != chld)
    {
      *sock = sp[1];
      MHD_socket_close_chk_ (sp[0]);
      return chld;
    }
  MHD_socket_close_chk_ (sp[1]);
  (void) close (0);
  (void) close (1);
  dup2 (sp[0], 0);
  dup2 (sp[0], 1);
  MHD_socket_close_chk_ (sp[0]);
  sprintf (destination,
           "localhost:%u",
           (unsigned int) port);
  execlp ("openssl",
          "openssl",
          "s_client",
          "-connect",
          destination,
          "-verify",
          "0",
          (char *) NULL);
  _exit (1);
}


/**
 * Test upgrading a connection.
 *
 * @param flags which event loop style should be tested
 * @param pool size of the thread pool, 0 to disable
 */
static int
test_upgrade (int flags,
              unsigned int pool)
{
  struct MHD_Daemon *d;
  MHD_socket sock;
  pid_t pid;

  done = 0;
  if (0 == (flags & MHD_USE_THREAD_PER_CONNECTION))
    flags |= MHD_USE_SUSPEND_RESUME;
  d = MHD_start_daemon (flags | MHD_USE_DEBUG | MHD_USE_TLS,
                        1080,
                        NULL, NULL,
                        &ahc_upgrade, NULL,
                        MHD_OPTION_URI_LOG_CALLBACK, &log_cb, NULL,
                        MHD_OPTION_NOTIFY_COMPLETED, &notify_completed_cb, NULL,
                        MHD_OPTION_NOTIFY_CONNECTION, &notify_connection_cb, NULL,
                        MHD_OPTION_HTTPS_MEM_KEY, srv_signed_key_pem,
                        MHD_OPTION_HTTPS_MEM_CERT, srv_signed_cert_pem,
                        MHD_OPTION_THREAD_POOL_SIZE, pool,
                        MHD_OPTION_END);
  if (NULL == d)
    return 2;
  if (-1 == (pid = openssl_connect (&sock, 1080)))
    {
      MHD_stop_daemon (d);
      return 4;
    }

  pthread_create (&pt_client,
                  NULL,
                  &run_usock_client,
                  &sock);
  if (0 == (flags & (MHD_USE_SELECT_INTERNALLY |
                     MHD_USE_THREAD_PER_CONNECTION)) )
    run_mhd_loop (d, flags);
  pthread_join (pt_client,
                NULL);
  if (0 == (flags & (MHD_USE_SELECT_INTERNALLY |
                     MHD_USE_THREAD_PER_CONNECTION)) )
    run_mhd_loop (d, flags);
  pthread_join (pt,
                NULL);
  waitpid (pid,
           NULL,
           0);
  MHD_stop_daemon (d);
  return 0;
}


int
main (int argc,
      char *const *argv)
{
  int error_count = 0;

  if (0 != system ("openssl version 1> /dev/null"))
    return 77; /* openssl not available, can't run the test */

  /* try external select */
  error_count += test_upgrade (0,
                               0);
#ifdef EPOLL_SUPPORT
  error_count += test_upgrade (MHD_USE_TLS_EPOLL_UPGRADE,
                               0);
#endif

  /* Test thread-per-connection */
  error_count += test_upgrade (MHD_USE_THREAD_PER_CONNECTION,
                               0);
  error_count += test_upgrade (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL,
                               0);

  /* Test different event loops, with and without thread pool */
  error_count += test_upgrade (MHD_USE_SELECT_INTERNALLY,
                               0);
  error_count += test_upgrade (MHD_USE_SELECT_INTERNALLY,
                               2);
#ifdef HAVE_POLL
  error_count += test_upgrade (MHD_USE_POLL_INTERNALLY,
                               0);
  error_count += test_upgrade (MHD_USE_POLL_INTERNALLY,
                               2);
#endif
#ifdef EPOLL_SUPPORT
  error_count += test_upgrade (MHD_USE_EPOLL_INTERNALLY |
                               MHD_USE_TLS_EPOLL_UPGRADE,
                               0);
  error_count += test_upgrade (MHD_USE_EPOLL_INTERNALLY |
                               MHD_USE_TLS_EPOLL_UPGRADE,
                               2);
#endif
  /* report result */
  if (0 != error_count)
    fprintf (stderr,
             "Error (code: %u)\n",
             error_count);
  return error_count != 0;       /* 0 == pass */
}
