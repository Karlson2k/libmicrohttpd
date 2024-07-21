/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

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
 * @file minimal_example2.c
 * @brief  Minimal example for libmicrohttpd v2
 * @author Karlson2k (Evgeny Grin)
 */

#include <stdio.h>
#include <stdlib.h>
#include <microhttpd2.h>

static MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3)
const struct MHD_Action *
req_cb (void *cls,
        struct MHD_Request *MHD_RESTRICT request,
        const struct MHD_String *MHD_RESTRICT path,
        enum MHD_HTTP_Method method,
        uint_fast64_t upload_size)
{
  static const char res_msg[] = "Hello there!";

  (void) cls; (void) path; (void) method; (void) upload_size; /* Unused */

  return MHD_action_from_response (
    request,
    MHD_response_from_buffer_static (MHD_HTTP_STATUS_OK,
                                     sizeof(res_msg) / sizeof(char) - 1,
                                     res_msg));
}


int
main (int argc,
      char *const *argv)
{
  struct MHD_Daemon *d;
  int port;

  if (argc != 2)
  {
    fprintf (stderr,"Usage:\n%s PORT\n", argv[0]);
    return 1;
  }
  port = atoi (argv[1]);
  if ( (1 > port) || (port > 65535) )
  {
    fprintf (stderr,
             "The port must be a number between 1 and 65535.\n");
    return 2;
  }
  d = MHD_daemon_create (&req_cb, NULL);
  if (NULL != d)
  {
    if (MHD_SC_OK ==
        MHD_DAEMON_SET_OPTIONS (d,
                                MHD_D_OPTION_WM_WORKER_THREADS (1),
                                MHD_D_OPTION_BIND_PORT (MHD_AF_AUTO,
                                                        (uint_least16_t) port)))
    {
      if (MHD_SC_OK == MHD_daemon_start (d))
      {
        printf ("The MHD daemon is listening on port %d\n"
                "Press ENTER to stop.\n", port);
        (void) fgetc (stdin);
      }
      else
        fprintf (stderr, "Failed to start MHD daemon.\n");
    }
    else
      fprintf (stderr, "Failed to set MHD daemon run parameters.\n");
    printf ("Stopping... ");
    MHD_daemon_destroy (d);
    printf ("OK\n");

  }
  else
    fprintf (stderr, "Failed to create MHD daemon.\n");

  return 0;
}
