/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Christian Grothoff

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file libtest_convenience.c
 * @brief convenience functions for libtest users
 * @author Christian Grothoff
 */
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "microhttpd2.h"
#include "libtest.h"
#include <curl/curl.h>


const char *
MHDT_server_setup_minimal (void *cls,
                           struct MHD_Daemon *d)
{
  const struct MHD_DaemonOptionAndValue *options = cls;

  if (MHD_SC_OK !=
      MHD_daemon_set_options (
        d,
        options,
        MHD_OPTIONS_ARRAY_MAX_SIZE))
    return "Failed to configure threading mode!";
  if (MHD_SC_OK !=
      MHD_DAEMON_SET_OPTIONS (
        d,
        MHD_D_OPTION_BIND_PORT (MHD_AF_AUTO,
                                0)))
    return "Failed to bind to port 0!";
  return NULL;
}


void
MHDT_server_run_minimal (void *cls,
                         int finsig,
                         struct MHD_Daemon *d)
{
  fd_set r;
  char c;

  FD_ZERO (&r);
  FD_SET (finsig, &r);
  while (1)
  {
    if ( (-1 ==
          select (finsig + 1,
                  &r,
                  NULL,
                  NULL,
                  NULL)) &&
         (EAGAIN != errno) )
    {
      fprintf (stderr,
               "Failure waiting on termination signal: %s\n",
               strerror (errno));
      break;
    }
    if (FD_ISSET (finsig,
                  &r))
      break;
  }
  if ( (FD_ISSET (finsig,
                  &r)) &&
       (1 != read (finsig,
                   &c,
                   1)) )
  {
    fprintf (stderr,
             "Failed to drain termination signal\n");
  }
}


void
MHDT_server_run_blocking (void *cls,
                          int finsig,
                          struct MHD_Daemon *d)
{
  fd_set r;
  char c;

  FD_ZERO (&r);
  FD_SET (finsig, &r);
  while (1)
  {
    struct timeval timeout = {
      .tv_usec = 1000 /* 1000 microseconds */
    };

    if ( (-1 ==
          select (finsig + 1,
                  &r,
                  NULL,
                  NULL,
                  &timeout)) &&
         (EAGAIN != errno) )
    {
      fprintf (stderr,
               "Failure waiting on termination signal: %s\n",
               strerror (errno));
      break;
    }
#if FIXME
    if (MHD_SC_OK !=
        MHD_daemon_process_blocking (d,
                                     1000))
    {
      fprintf (stderr,
               "Failure running MHD_daemon_process_blocking()\n");
      break;
    }
#else
    abort ();
#endif
  }
  if ( (FD_ISSET (finsig,
                  &r)) &&
       (1 != read (finsig,
                   &c,
                   1)) )
  {
    fprintf (stderr,
             "Failed to drain termination signal\n");
  }
}
