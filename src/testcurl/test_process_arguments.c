/*
     This file is part of libmicrohttpd
     Copyright (C) 2007, 2013 Christian Grothoff
     Copyright (C) 2014-2022 Evgeny Grin (Karlson2k)

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
 * @file test_process_arguments.c
 * @brief  Testcase for HTTP URI arguments
 * @author Christian Grothoff
 * @author Karlson2k (Evgeny Grin)
 */

#include "MHD_config.h"
#include "platform.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "mhd_has_in_name.h"

#ifndef WINDOWS
#include <unistd.h>
#endif

static int oneone;

struct CBC
{
  char *buf;
  size_t pos;
  size_t size;
};


static size_t
copyBuffer (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct CBC *cbc = ctx;

  if (cbc->pos + size * nmemb > cbc->size)
    return 0;                   /* overflow */
  memcpy (&cbc->buf[cbc->pos], ptr, size * nmemb);
  cbc->pos += size * nmemb;
  return size * nmemb;
}


static enum MHD_Result
ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size,
          void **req_cls)
{
  static int ptr;
  struct MHD_Response *response;
  enum MHD_Result ret;
  const char *hdr;
  (void) cls;
  (void) version; (void) upload_data; (void) upload_data_size;       /* Unused. Silent compiler warning. */

  if (0 != strcmp (MHD_HTTP_METHOD_GET, method))
    return MHD_NO;              /* unexpected method */
  if (&ptr != *req_cls)
  {
    *req_cls = &ptr;
    return MHD_YES;
  }
  *req_cls = NULL;
  hdr = MHD_lookup_connection_value (connection, MHD_GET_ARGUMENT_KIND, "k");
  if ((hdr == NULL) || (0 != strcmp (hdr, "v x")))
    abort ();
  hdr = MHD_lookup_connection_value (connection,
                                     MHD_GET_ARGUMENT_KIND, "hash");
  if ((hdr == NULL) || (0 != strcmp (hdr, "#foo")))
    abort ();
  hdr = MHD_lookup_connection_value (connection,
                                     MHD_GET_ARGUMENT_KIND, "space");
  if ((hdr == NULL) || (0 != strcmp (hdr, "\240bar")))
    abort ();
  if (3 != MHD_get_connection_values (connection,
                                      MHD_GET_ARGUMENT_KIND,
                                      NULL, NULL))
    abort ();
  response = MHD_create_response_from_buffer_copy (strlen (url),
                                                   (const void *) url);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  if (ret == MHD_NO)
    abort ();
  return ret;
}


static unsigned int
testExternalGet (void)
{
  struct MHD_Daemon *d;
  CURL *c;
  char buf[2048];
  struct CBC cbc;
  CURLM *multi;
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  MHD_socket maxsock;
#ifdef MHD_WINSOCK_SOCKETS
  int maxposixs; /* Max socket number unused on W32 */
#else  /* MHD_POSIX_SOCKETS */
#define maxposixs maxsock
#endif /* MHD_POSIX_SOCKETS */
  int running;
  struct CURLMsg *msg;
  time_t start;
  struct timeval tv;
  uint16_t port;

  if (MHD_NO != MHD_is_feature_supported (MHD_FEATURE_AUTODETECT_BIND_PORT))
    port = 0;
  else
  {
    port = 1410;
    if (oneone)
      port += 5;
  }

  multi = NULL;
  cbc.buf = buf;
  cbc.size = 2048;
  cbc.pos = 0;
  d = MHD_start_daemon (MHD_USE_ERROR_LOG | MHD_USE_NO_THREAD_SAFETY,
                        port, NULL, NULL, &ahc_echo, NULL,
                        MHD_OPTION_APP_FD_SETSIZE, (int) FD_SETSIZE,
                        MHD_OPTION_END);
  if (d == NULL)
    return 256;
  if (0 == port)
  {
    const union MHD_DaemonInfo *dinfo;
    dinfo = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
    if ((NULL == dinfo) || (0 == dinfo->port) )
    {
      MHD_stop_daemon (d); return 32;
    }
    port = dinfo->port;
  }
  c = curl_easy_init ();
  curl_easy_setopt (c, CURLOPT_URL,
                    "http://127.0.0.1/hello+world?k=v+x&hash=%23foo&space=%A0bar");
  curl_easy_setopt (c, CURLOPT_PORT, (long) port);
  curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (c, CURLOPT_WRITEDATA, &cbc);
  curl_easy_setopt (c, CURLOPT_FAILONERROR, 1L);
  if (oneone)
    curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  else
    curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
  curl_easy_setopt (c, CURLOPT_TIMEOUT, 150L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 150L);
  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system! */
  curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1L);


  multi = curl_multi_init ();
  if (multi == NULL)
  {
    curl_easy_cleanup (c);
    MHD_stop_daemon (d);
    return 512;
  }
  mret = curl_multi_add_handle (multi, c);
  if (mret != CURLM_OK)
  {
    curl_multi_cleanup (multi);
    curl_easy_cleanup (c);
    MHD_stop_daemon (d);
    return 1024;
  }
  start = time (NULL);
  while ((time (NULL) - start < 5) && (multi != NULL))
  {
    maxsock = MHD_INVALID_SOCKET;
    maxposixs = -1;
    FD_ZERO (&rs);
    FD_ZERO (&ws);
    FD_ZERO (&es);
    curl_multi_perform (multi, &running);
    mret = curl_multi_fdset (multi, &rs, &ws, &es, &maxposixs);
    if (mret != CURLM_OK)
    {
      curl_multi_remove_handle (multi, c);
      curl_multi_cleanup (multi);
      curl_easy_cleanup (c);
      MHD_stop_daemon (d);
      return 2048;
    }
    if (MHD_YES != MHD_get_fdset (d, &rs, &ws, &es, &maxsock))
    {
      curl_multi_remove_handle (multi, c);
      curl_multi_cleanup (multi);
      curl_easy_cleanup (c);
      MHD_stop_daemon (d);
      return 4096;
    }
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    if (-1 == select (maxposixs + 1, &rs, &ws, &es, &tv))
    {
#ifdef MHD_POSIX_SOCKETS
      if (EINTR != errno)
      {
        fprintf (stderr, "Unexpected select() error: %d. Line: %d\n",
                 (int) errno, __LINE__);
        fflush (stderr);
        exit (99);
      }
#else
      if ((WSAEINVAL != WSAGetLastError ()) ||
          (0 != rs.fd_count) || (0 != ws.fd_count) || (0 != es.fd_count) )
      {
        fprintf (stderr, "Unexpected select() error: %d. Line: %d\n",
                 (int) WSAGetLastError (), __LINE__);
        fflush (stderr);
        exit (99);
      }
      Sleep (1);
#endif
    }
    curl_multi_perform (multi, &running);
    if (0 == running)
    {
      int pending;
      int curl_fine = 0;
      while (NULL != (msg = curl_multi_info_read (multi, &pending)))
      {
        if (msg->msg == CURLMSG_DONE)
        {
          if (msg->data.result == CURLE_OK)
            curl_fine = 1;
          else
          {
            fprintf (stderr,
                     "%s failed at %s:%d: `%s'\n",
                     "curl_multi_perform",
                     __FILE__,
                     __LINE__, curl_easy_strerror (msg->data.result));
            abort ();
          }
        }
      }
      if (! curl_fine)
      {
        fprintf (stderr, "libcurl haven't returned OK code\n");
        abort ();
      }
      curl_multi_remove_handle (multi, c);
      curl_multi_cleanup (multi);
      curl_easy_cleanup (c);
      c = NULL;
      multi = NULL;
    }
    MHD_run (d);
  }
  if (multi != NULL)
  {
    curl_multi_remove_handle (multi, c);
    curl_easy_cleanup (c);
    curl_multi_cleanup (multi);
  }
  MHD_stop_daemon (d);
  if (cbc.pos != strlen ("/hello+world"))
    return 8192;
  if (0 != strncmp ("/hello+world", cbc.buf, strlen ("/hello+world")))
    return 16384;
  return 0;
}


int
main (int argc, char *const *argv)
{
  unsigned int errorCount = 0;
  (void) argc;   /* Unused. Silent compiler warning. */

  if ((NULL == argv) || (0 == argv[0]))
    return 99;
  oneone = has_in_name (argv[0], "11");
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    return 2;
  errorCount += testExternalGet ();
  if (errorCount != 0)
    fprintf (stderr, "Error (code: %u)\n", errorCount);
  curl_global_cleanup ();
  return (0 == errorCount) ? 0 : 1;       /* 0 == pass */
}
