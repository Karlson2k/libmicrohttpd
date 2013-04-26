/*
     This file is part of libmicrohttpd
     (C) 2013 Christian Grothoff

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
 * @file daemontest_quiesce.c
 * @brief  Testcase for libmicrohttpd quiescing
 * @author Christian Grothoff
 */

#include "MHD_config.h"
#include "platform.h"
#include <curl/curl.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#endif

static int oneone;
static int done;

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

static int
ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size,
          void **unused)
{
  static int ptr;
  const char *me = cls;
  struct MHD_Response *response;
  int ret;

  if (0 != strcmp (me, method))
    return MHD_NO;              /* unexpected method */
  if (&ptr != *unused)
    {
      *unused = &ptr;
      return MHD_YES;
    }
  *unused = NULL;
  response = MHD_create_response_from_buffer (strlen (url),
  				      (void *) url,
					      MHD_RESPMEM_MUST_COPY);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  if (ret == MHD_NO)
    abort ();
  return ret;
}

void request_completed (void *cls, struct MHD_Connection *connection,
      void **con_cls, enum MHD_RequestTerminationCode code)
{
  int *done = (int *)cls;
  *done = 1;
}

void ServeOneRequest(int fd)
{
  struct MHD_Daemon *d;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct CURLMsg *msg;
  time_t start;
  struct timeval tv;
  int done = 0;
  d = MHD_start_daemon (MHD_USE_DEBUG,
                        1082, NULL, NULL, &ahc_echo, "GET",
                        MHD_OPTION_LISTEN_SOCKET, fd,
                        MHD_OPTION_NOTIFY_COMPLETED, &request_completed, &done,
                        MHD_OPTION_END);
  if (d == NULL)
    _exit(1);

  start = time (NULL);
  while ((time (NULL) - start < 5) && done == 0)
    {
      max = 0;
      FD_ZERO (&rs);
      FD_ZERO (&ws);
      FD_ZERO (&es);
      if (MHD_YES != MHD_get_fdset (d, &rs, &ws, &es, &max))
        {
          MHD_stop_daemon (d);
          close(fd);
          _exit(4096);
        }
      tv.tv_sec = 0;
      tv.tv_usec = 1000;
      select (max + 1, &rs, &ws, &es, &tv);
      MHD_run (d);
    }
  MHD_stop_daemon (d);
  close(fd);
  _exit(0);
}

CURL *setupCURL(void *cbc)
{
  CURL *c;
  c = curl_easy_init ();
  curl_easy_setopt (c, CURLOPT_URL, "http://127.0.0.1:11080/hello_world");
  curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (c, CURLOPT_WRITEDATA, cbc);
  curl_easy_setopt (c, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt (c, CURLOPT_TIMEOUT_MS, 150L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT_MS, 150L);
  if (oneone)
    curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  else
    curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system!*/
  curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1);

  return c;
}

static int
testGet (int type, int pool_count, int poll_flag)
{
  struct MHD_Daemon *d;
  CURL *c;
  char buf[2048];
  struct CBC cbc;
  CURLcode errornum;
  int fd;
  pid_t pid;

  cbc.buf = buf;
  cbc.size = 2048;
  cbc.pos = 0;
  if (pool_count > 0) {
    d = MHD_start_daemon (type | MHD_USE_DEBUG  | poll_flag,
                          11080, NULL, NULL, &ahc_echo, "GET",
                          MHD_OPTION_THREAD_POOL_SIZE, pool_count, MHD_OPTION_END);

  } else {
    d = MHD_start_daemon (type | MHD_USE_DEBUG  | poll_flag,
                          11080, NULL, NULL, &ahc_echo, "GET", MHD_OPTION_END);
  }
  if (d == NULL)
    return 1;

  c = setupCURL(&cbc);

  if (CURLE_OK != (errornum = curl_easy_perform (c)))
    {
      fprintf (stderr,
               "curl_easy_perform failed: `%s'\n",
               curl_easy_strerror (errornum));
      curl_easy_cleanup (c);
      MHD_stop_daemon (d);
      return 2;
    }

  if (cbc.pos != strlen ("/hello_world")) {
    curl_easy_cleanup (c);
    MHD_stop_daemon (d);
    return 4;
  }
  if (0 != strncmp ("/hello_world", cbc.buf, strlen ("/hello_world"))) {
    curl_easy_cleanup (c);
    MHD_stop_daemon (d);
    return 8;
  }

  fd = MHD_quiesce_daemon(d);

  if (fork() == 0) {
    ServeOneRequest(fd);
    _exit(1);
  }

  cbc.pos = 0;
  if (CURLE_OK != (errornum = curl_easy_perform (c)))
    {
      fprintf (stderr,
               "curl_easy_perform failed: `%s'\n",
               curl_easy_strerror (errornum));
      curl_easy_cleanup (c);
      return 2;
    }

  waitpid(-1, NULL, 0);

  if (cbc.pos != strlen ("/hello_world")) {
    fprintf(stderr, "%s\n", cbc.buf);
    curl_easy_cleanup (c);
    MHD_stop_daemon (d);
    close(fd);
    return 4;
  }
  if (0 != strncmp ("/hello_world", cbc.buf, strlen ("/hello_world"))) {
    fprintf(stderr, "%s\n", cbc.buf);
    curl_easy_cleanup (c);
    MHD_stop_daemon (d);
    close(fd);
    return 8;
  }

  /* at this point, the forked server quit, and the new
   * server has quiesced, so new requests should fail
   */
  if (CURLE_OK == (errornum = curl_easy_perform (c)))
    {
      fprintf (stderr, "curl_easy_perform should fail\n");
      curl_easy_cleanup (c);
      MHD_stop_daemon (d);
      close(fd);
      return 2;
    }
  curl_easy_cleanup (c);
  MHD_stop_daemon (d);
  close(fd);

  return 0;
}


static int
testExternalGet ()
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
  int max;
  int running; 
  struct CURLMsg *msg;
  time_t start;
  struct timeval tv;
  int i;
  int fd;

  multi = NULL;
  cbc.buf = buf;
  cbc.size = 2048;
  cbc.pos = 0;
  d = MHD_start_daemon (MHD_USE_DEBUG,
                        11080, NULL, NULL, &ahc_echo, "GET", MHD_OPTION_END);
  if (d == NULL)
    return 256;
  c = setupCURL(&cbc);

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

  for (i = 0; i < 2; i++) {
    start = time (NULL);
    while ((time (NULL) - start < 5) && (multi != NULL))
      {
        max = 0;
        FD_ZERO (&rs);
        FD_ZERO (&ws);
        FD_ZERO (&es);
        curl_multi_perform (multi, &running);
        mret = curl_multi_fdset (multi, &rs, &ws, &es, &max);
        if (mret != CURLM_OK)
          {
            curl_multi_remove_handle (multi, c);
            curl_multi_cleanup (multi);
            curl_easy_cleanup (c);
            MHD_stop_daemon (d);
            return 2048;
          }
        if (MHD_YES != MHD_get_fdset (d, &rs, &ws, &es, &max))
          {
            curl_multi_remove_handle (multi, c);
            curl_multi_cleanup (multi);
            curl_easy_cleanup (c);
            MHD_stop_daemon (d);
            return 4096;
          }
        tv.tv_sec = 0;
        tv.tv_usec = 1000;
        select (max + 1, &rs, &ws, &es, &tv);
        curl_multi_perform (multi, &running);
        if (running == 0)
          {
            msg = curl_multi_info_read (multi, &running);
            if (msg == NULL)
              break;
            if (msg->msg == CURLMSG_DONE)
              {
                if (i == 0 && msg->data.result != CURLE_OK)
                  printf ("%s failed at %s:%d: `%s'\n",
                          "curl_multi_perform",
                          __FILE__,
                          __LINE__, curl_easy_strerror (msg->data.result));
                else if (i == 1 && msg->data.result == CURLE_OK)
                  printf ("%s should have failed at %s:%d\n",
                          "curl_multi_perform",
                          __FILE__,
                          __LINE__);
                curl_multi_remove_handle (multi, c);
                curl_multi_cleanup (multi);
                curl_easy_cleanup (c);
                c = NULL;
                multi = NULL;
              }
          }
        MHD_run (d);
      }

      if (i == 0) {
        /* quiesce the daemon on the 1st iteration, so the 2nd should fail */
        fd = MHD_quiesce_daemon(d);
        close(fd);
        c = setupCURL(&cbc);
        multi = curl_multi_init ();
        mret = curl_multi_add_handle (multi, c);
      }
    }
  if (multi != NULL)
    {
      curl_multi_remove_handle (multi, c);
      curl_easy_cleanup (c);
      curl_multi_cleanup (multi);
    }
  MHD_stop_daemon (d);
  if (cbc.pos != strlen ("/hello_world"))
    return 8192;
  if (0 != strncmp ("/hello_world", cbc.buf, strlen ("/hello_world")))
    return 16384;
  return 0;
}


int
main (int argc, char *const *argv)
{
  unsigned int errorCount = 0;

  oneone = NULL != strstr (argv[0], "11");
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    return 2;
  errorCount += testGet (MHD_USE_SELECT_INTERNALLY, 0, 0);
  errorCount += testGet (MHD_USE_THREAD_PER_CONNECTION, 0, 0);
  errorCount += testGet (MHD_USE_SELECT_INTERNALLY, 4, 0);
  errorCount += testExternalGet ();
#ifndef WINDOWS
  errorCount += testGet (MHD_USE_SELECT_INTERNALLY, 0, MHD_USE_POLL);
  errorCount += testGet (MHD_USE_THREAD_PER_CONNECTION, 0, MHD_USE_POLL);
  errorCount += testGet (MHD_USE_SELECT_INTERNALLY, 4, MHD_USE_POLL);
#endif
  if (errorCount != 0)
    fprintf (stderr, "Error (code: %u)\n", errorCount);
  curl_global_cleanup ();
  return errorCount != 0;       /* 0 == pass */
}
