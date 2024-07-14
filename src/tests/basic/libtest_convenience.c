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
  if (MHD_SC_OK !=
      MHD_DAEMON_SET_OPTIONS (d,
                              MHD_D_OPTION_BIND_PORT (MHD_AF_DUAL,
                                                      0)))
    return "Failed to bind to port 0!";
  return NULL;
}


void
MHDT_server_run_blocking (void *cls,
                          int finsig,
                          struct MHD_Daemon *d)
{
  char e;

  while (-1 ==
         read (finsig,
               &e,
               1))
  {
    if (EAGAIN != errno)
    {
      fprintf (stderr,
               "Failure reading termination signal: %s\n",
               strerror (errno));
      break;
    }
    if (MHD_SC_OK !=
        MHD_daemon_process_blocking (d,
                                     1000))
    {
      fprintf (stderr,
               "Failure running MHD_daemon_process_blocking()\n");
      break;
    }
  }
}


const struct MHD_Action *
MHDT_server_reply_text (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *text = cls;

  return MHD_action_from_response (
    request,
    MHD_response_from_buffer_static (MHD_HTTP_STATUS_OK,
                                     strlen (text),
                                     text));
}


const char *
MHDT_client_get_root (
  void *cls,
  const struct MHDT_PhaseContext *pc)
{
  const char *text = cls;
  CURL *c;
  CURLcode res;

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_URL,
                        pc->base_url))
  {
    curl_easy_cleanup (c);
    return "Failed to set URL for curl request";
  }
  res = curl_easy_perform (c);
  curl_easy_cleanup (c);
  if (CURLE_OK != res)
    return "Failed to fetch URL";
  (void) text; // FIXME: check data returned was 'text'
  return NULL;
}
