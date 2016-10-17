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
 * @file test_upgrade.c
 * @brief  Testcase for libmicrohttpd upgrading a connection
 * @author Christian Grothoff
 */

#include "platform.h"
#include "microhttpd.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#ifndef WINDOWS
#include <unistd.h>
#endif

#include "mhd_sockets.h"
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif /* HAVE_NETINET_IP_H */
#include "test_upgrade_common.c"


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
  struct sockaddr_in sa;

  done = 0;
  if (0 == (flags & MHD_USE_THREAD_PER_CONNECTION))
    flags |= MHD_USE_SUSPEND_RESUME;
  d = MHD_start_daemon (flags | MHD_USE_DEBUG,
                        1080,
                        NULL, NULL,
                        &ahc_upgrade, NULL,
                        MHD_OPTION_URI_LOG_CALLBACK, &log_cb, NULL,
                        MHD_OPTION_NOTIFY_COMPLETED, &notify_completed_cb, NULL,
                        MHD_OPTION_NOTIFY_CONNECTION, &notify_connection_cb, NULL,
                        MHD_OPTION_THREAD_POOL_SIZE, pool,
                        MHD_OPTION_END);
  if (NULL == d)
    return 2;
  sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (MHD_INVALID_SOCKET == sock)
    abort ();
  sa.sin_family = AF_INET;
  sa.sin_port = htons (1080);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (0 != connect (sock,
                    (struct sockaddr *) &sa,
                    sizeof (sa)))
    abort ();
  if (0 != pthread_create (&pt_client,
                           NULL,
                           &run_usock_client,
                           &sock))
    abort ();
  if (0 == (flags & (MHD_USE_SELECT_INTERNALLY |
                     MHD_USE_THREAD_PER_CONNECTION)) )
    run_mhd_loop (d, flags);
  pthread_join (pt_client,
                NULL);
  pthread_join (pt,
                NULL);
  MHD_stop_daemon (d);
  return 0;
}


int
main (int argc,
      char *const *argv)
{
  int error_count = 0;

  /* try external select */
  error_count += test_upgrade (0,
                               0);
#ifdef EPOLL_SUPPORT
  error_count += test_upgrade (MHD_USE_EPOLL,
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
  error_count += test_upgrade (MHD_USE_EPOLL_INTERNALLY,
                               0);
  error_count += test_upgrade (MHD_USE_EPOLL_INTERNALLY,
                               2);
#endif
  /* report result */
  if (0 != error_count)
    fprintf (stderr,
             "Error (code: %u)\n",
             error_count);
  return error_count != 0;       /* 0 == pass */
}
