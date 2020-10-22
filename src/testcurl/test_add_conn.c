/*
     This file is part of libmicrohttpd
     Copyright (C) 2007, 2009, 2011 Christian Grothoff
     Copyright (C) 2020 Karlson2k (Evgeny Grin) - large rework, multithreading.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file test_add_conn.c
 * @brief  Testcase for libmicrohttpd GET operations
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
#include "test_helpers.h"
#include "mhd_sockets.h" /* only macros used */


#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif /* !WIN32_LEAN_AND_MEAN */
#include <windows.h>
#endif

#ifndef WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif /* HAVE_PTHREAD_H */

#if defined(CPU_COUNT) && (CPU_COUNT + 0) < 2
#undef CPU_COUNT
#endif
#if ! defined(CPU_COUNT)
#define CPU_COUNT 2
#endif

/* Could be increased to facilitate debugging */
#define TIMEOUTS_VAL 5

#define EXPECTED_URI_BASE_PATH  "/hello_world"
#define EXPECTED_URI_QUERY      "a=%26&b=c"
#define EXPECTED_URI_FULL_PATH  EXPECTED_URI_BASE_PATH "?" EXPECTED_URI_QUERY

static int oneone;
static int no_listen;
static int global_port;

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


static void *
log_cb (void *cls,
        const char *uri,
        struct MHD_Connection *con)
{
  (void) cls;
  (void) con;
  if (0 != strcmp (uri,
                   EXPECTED_URI_FULL_PATH))
  {
    fprintf (stderr,
             "Wrong URI: `%s'\n",
             uri);
    _exit (22);
  }
  return NULL;
}


static enum MHD_Result
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
  enum MHD_Result ret;
  const char *v;
  (void) version;
  (void) upload_data;
  (void) upload_data_size;       /* Unused. Silence compiler warning. */

  if (0 != strcasecmp (me, method))
    return MHD_NO;              /* unexpected method */
  if (&ptr != *unused)
  {
    *unused = &ptr;
    return MHD_YES;
  }
  *unused = NULL;
  v = MHD_lookup_connection_value (connection,
                                   MHD_GET_ARGUMENT_KIND,
                                   "a");
  if ( (NULL == v) ||
       (0 != strcmp ("&",
                     v)) )
  {
    fprintf (stderr, "Found while looking for 'a=&': 'a=%s'\n",
             NULL == v ? "NULL" : v);
    _exit (17);
  }
  v = NULL;
  if (MHD_YES != MHD_lookup_connection_value_n (connection,
                                                MHD_GET_ARGUMENT_KIND,
                                                "b",
                                                1,
                                                &v,
                                                NULL))
  {
    fprintf (stderr, "Not found 'b' GET argument.\n");
    _exit (18);
  }
  if ( (NULL == v) ||
       (0 != strcmp ("c",
                     v)) )
  {
    fprintf (stderr, "Found while looking for 'b=c': 'b=%s'\n",
             NULL == v ? "NULL" : v);
    _exit (19);
  }
  response = MHD_create_response_from_buffer (strlen (url),
                                              (void *) url,
                                              MHD_RESPMEM_MUST_COPY);
  ret = MHD_queue_response (connection,
                            MHD_HTTP_OK,
                            response);
  MHD_destroy_response (response);
  if (ret == MHD_NO)
  {
    fprintf (stderr, "Failed to queue response.\n");
    _exit (19);
  }
  return ret;
}


static void
_externalErrorExit_func (const char *errDesc, const char *funcName, int lineNum)
{
  if ((NULL != errDesc) && (0 != errDesc[0]))
    fprintf (stderr, "%s", errDesc);
  else
    fprintf (stderr, "System or external library call failed");
  if ((NULL != funcName) && (0 != funcName[0]))
    fprintf (stderr, " in %s", funcName);
  if (0 < lineNum)
    fprintf (stderr, " at line %d", lineNum);

  fprintf (stderr, ".\nLast errno value: %d\n", (int) errno);
#ifdef MHD_WINSOCK_SOCKETS
  fprintf (stderr, "WSAGetLastError() value: %d\n", (int) WSAGetLastError ());
#endif /* MHD_WINSOCK_SOCKETS */
  fflush (stderr);
  _exit (99);
}


#if defined(HAVE___FUNC__)
#define externalErrorExit(ignore) \
    _externalErrorExit_func(NULL, __func__, __LINE__)
#define externalErrorExitDesc(errDesc) \
    _externalErrorExit_func(errDesc, __func__, __LINE__)
#elif defined(HAVE___FUNCTION__)
#define externalErrorExit(ignore) \
    _externalErrorExit_func(NULL, __FUNCTION__, __LINE__)
#define externalErrorExitDesc(errDesc) \
    _externalErrorExit_func(errDesc, __FUNCTION__, __LINE__)
#else
#define externalErrorExit(ignore) _externalErrorExit_func(NULL, NULL, __LINE__)
#define externalErrorExitDesc(errDesc) \
  _externalErrorExit_func(errDesc, NULL, __LINE__)
#endif


/* Static const value, indicates that result value was not set yet */
static const int eMarker = 0xCE;


static MHD_socket
createListeningSocket (int *pport)
{
  MHD_socket skt;
  static const int on = 1;
  struct sockaddr_in sin;
  socklen_t sin_len;

  skt = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (MHD_INVALID_SOCKET == skt)
    externalErrorExitDesc ("socket() failed");

#ifdef MHD_POSIX_SOCKETS
  setsockopt (skt, SOL_SOCKET, SO_REUSEADDR, (void*) &on, sizeof (on));
  /* Ignore possible error */
#endif /* MHD_POSIX_SOCKETS */

  memset (&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (*pport);
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (0 != bind (skt, (struct sockaddr*) &sin, sizeof(sin)))
    externalErrorExitDesc ("bind() failed");

  if (0 != listen (skt, SOMAXCONN))
    externalErrorExitDesc ("listen() failed");

  if (0 == *pport)
  {
    memset (&sin, 0, sizeof(sin));
    sin_len = sizeof(sin);
    if (0 != getsockname (skt, (struct sockaddr *) &sin, &sin_len))
      externalErrorExitDesc ("getsockname() failed");

    if (sizeof(sin) < sin_len)
      externalErrorExitDesc ("getsockname() failed");

    if (AF_INET != sin.sin_family)
      externalErrorExitDesc ("getsockname() returned wrong socket family");

    *pport = (int) ntohs (sin.sin_port);
  }

  return skt;
}


static MHD_socket
acceptTimeLimited (MHD_socket lstn_sk, struct sockaddr *paddr,
                   socklen_t *paddr_len)
{
  fd_set rs;
  struct timeval timeoutval;
  MHD_socket accepted;

  FD_ZERO (&rs);
  FD_SET (lstn_sk, &rs);
  timeoutval.tv_sec = TIMEOUTS_VAL;
  timeoutval.tv_usec = 0;
  if (1 != select (((int) lstn_sk) + 1, &rs, NULL, NULL, &timeoutval))
    externalErrorExitDesc ("select() failed");

  accepted = accept (lstn_sk, paddr, paddr_len);
  if (MHD_INVALID_SOCKET == accepted)
    externalErrorExitDesc ("accept() failed");

  return accepted;
}


struct addConnParam
{
  struct MHD_Daemon *d;

  MHD_socket lstn_sk;

  /* Non-zero indicate error */
  volatile int result;

#ifdef HAVE_PTHREAD_H
  pthread_t addConnThread;
#endif /* HAVE_PTHREAD_H */
};

static int
doAcceptAndAddConnInThread (struct addConnParam *p)
{
  MHD_socket newConn;
  struct sockaddr addr;
  socklen_t addr_len = sizeof(addr);

  newConn = acceptTimeLimited (p->lstn_sk, &addr, &addr_len);

  p->result = (MHD_YES == MHD_add_connection (p->d, newConn, &addr, addr_len)) ?
              0 : 1;
  if (p->result)
    fprintf (stderr, "MHD_add_connection() failed, errno=%d.\n", errno);
  return p->result;
}


#ifdef HAVE_PTHREAD_H
static void *
doAcceptAndAddConn (void *param)
{
  struct addConnParam *p = param;

  (void) doAcceptAndAddConnInThread (p);

  return (void*) p;
}


static void
startThreadAddConn (struct addConnParam *param)
{
  /* thread must reset this value to zero if succeed */
  param->result = eMarker;

  if (0 != pthread_create (&param->addConnThread, NULL, &doAcceptAndAddConn,
                           (void*) param))
    externalErrorExitDesc ("pthread_create() failed");
}


static int
finishThreadAddConn (struct addConnParam *param)
{
  struct addConnParam *result;

  if (0 != pthread_join (param->addConnThread, (void**) &result))
    externalErrorExitDesc ("pthread_join() failed");

  if (param != result)
    abort (); /* Test used in a wrong way */

  if (eMarker == param->result)
    abort (); /* Test used in a wrong way */

  return result->result;
}


#endif /* HAVE_PTHREAD_H */


struct curlQueryParams
{
  /* Destination path for CURL query */
  const char *queryPath;

  /* Destination port for CURL query */
  int queryPort;

  /* CURL query result error flag */
  volatile int queryError;

#ifdef HAVE_PTHREAD_H
  pthread_t queryThread;
#endif /* HAVE_PTHREAD_H */
};

static CURL *
curlEasyInitForTest (const char *queryPath, int port, struct CBC *pcbc)
{
  CURL *c;

  c = curl_easy_init ();
  if (NULL == c)
  {
    fprintf (stderr, "curl_easy_init() failed.\n");
    _exit (99);
  }
  curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt (c, CURLOPT_URL, queryPath);
  curl_easy_setopt (c, CURLOPT_PORT, (long) port);
  curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (c, CURLOPT_WRITEDATA, pcbc);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, (long) TIMEOUTS_VAL);
  curl_easy_setopt (c, CURLOPT_TIMEOUT, (long) TIMEOUTS_VAL);
  curl_easy_setopt (c, CURLOPT_FAILONERROR, 1L);
  if (oneone)
    curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  else
    curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);

  return c;
}


static int
doCurlQueryInThread (struct curlQueryParams *p)
{
  CURL *c;
  char buf[2048];
  struct CBC cbc;
  CURLcode errornum;

  if (NULL == p->queryPath)
    abort ();

  if (0 == p->queryPort)
    abort ();

  cbc.buf = buf;
  cbc.size = sizeof(buf);
  cbc.pos = 0;

  c = curlEasyInitForTest (p->queryPath, p->queryPort, &cbc);

  errornum = curl_easy_perform (c);
  if (CURLE_OK != errornum)
  {
    fprintf (stderr,
             "curl_easy_perform failed: `%s'\n",
             curl_easy_strerror (errornum));
    p->queryError = 2;
  }
  else
  {
    if (cbc.pos != strlen (EXPECTED_URI_BASE_PATH))
    {
      fprintf (stderr, "curl reports wrong size of MHD reply body data.\n");
      p->queryError = 4;
    }
    else if (0 != strncmp (EXPECTED_URI_BASE_PATH, cbc.buf,
                           strlen (EXPECTED_URI_BASE_PATH)))
    {
      fprintf (stderr, "curl reports wrong MHD reply body data.\n");
      p->queryError = 4;
    }
    else
      p->queryError = 0;
  }
  curl_easy_cleanup (c);

  return p->queryError;
}


#ifdef HAVE_PTHREAD_H
static void *
doCurlQuery (void *param)
{
  struct curlQueryParams *p = (struct curlQueryParams*) param;

  (void) doCurlQueryInThread (p);

  return param;
}


static void
startThreadCurlQuery (struct curlQueryParams *param)
{
  /* thread must reset this value to zero if succeed */
  param->queryError = eMarker;

  if (0 != pthread_create (&param->queryThread, NULL, &doCurlQuery,
                           (void*) param))
    externalErrorExitDesc ("pthread_create() failed");
}


static int
finishThreadCurlQuery (struct curlQueryParams *param)
{
  struct curlQueryParams *result;

  if (0 != pthread_join (param->queryThread, (void**) &result))
    externalErrorExitDesc ("pthread_join() failed");

  if (param != result)
    abort (); /* Test used in wrong way */

  if (eMarker == param->queryError)
    abort (); /* Test used in wrong way */

  return result->queryError;
}


/* Perform test queries and shut down MHD daemon */
static int
performTestQueries (struct MHD_Daemon *d, int d_port)
{
  struct curlQueryParams qParam;
  struct addConnParam aParam;
  int a_port = 0;           /* Additional listening socket port */
  int ret = 0;              /* Return value */

  qParam.queryPath = "http://127.0.0.1" EXPECTED_URI_FULL_PATH;
  qParam.queryPort = 0; /* autoassign */

  aParam.d = d;
  aParam.lstn_sk = createListeningSocket (&a_port); /* Sets a_port */

  /* Test of adding connection in the same thread */
  qParam.queryError = eMarker; /* to be zeroed in new thread */
  qParam.queryPort = a_port;   /* Connect to additional socket */
  startThreadCurlQuery (&qParam);
  ret |= doAcceptAndAddConnInThread (&aParam);
  ret |= finishThreadCurlQuery (&qParam);

  if (! no_listen)
  {
    /* Test of the daemon itself can accept and process new connection. */
    ret <<= 3;                   /* Remember errors for each step */
    qParam.queryPort = d_port;   /* Connect to the daemon */
    ret |= doCurlQueryInThread (&qParam);
  }

  /* Test of adding connection in an external thread */
  ret <<= 3;                   /* Remember errors for each step */
  aParam.result = eMarker;     /* to be zeroed in new thread */
  qParam.queryPort = a_port;   /* Connect to the daemon */
  startThreadAddConn (&aParam);
  ret |= doCurlQueryInThread (&qParam);
  ret |= finishThreadAddConn (&aParam);

  (void) MHD_socket_close_ (aParam.lstn_sk);
  MHD_stop_daemon (d);

  return ret;
}


#endif /* HAVE_PTHREAD_H */

enum testMhdThreadsType
{
  testMhdThreadExternal              = 0,
  testMhdThreadInternal              = MHD_USE_INTERNAL_POLLING_THREAD,
  testMhdThreadInternalPerConnection = MHD_USE_THREAD_PER_CONNECTION
                                       | MHD_USE_INTERNAL_POLLING_THREAD,
  testMhdThreadInternalPool
};

enum testMhdPollType
{
  testMhdPollBySelect = 0,
  testMhdPollByPoll   = MHD_USE_POLL,
  testMhdPollByEpoll  = MHD_USE_EPOLL,
  testMhdPollAuto     = MHD_USE_AUTO
};

static struct MHD_Daemon *
startTestMhdDaemon (enum testMhdThreadsType thrType,
                    enum testMhdPollType pollType, int *pport)
{
  struct MHD_Daemon *d;
  const union MHD_DaemonInfo *dinfo;

  if ( (0 == *pport) &&
       (MHD_NO == MHD_is_feature_supported (MHD_FEATURE_AUTODETECT_BIND_PORT)) )
    *pport = oneone ? 1550 : 1570;

  if (testMhdThreadInternalPool != thrType)
    d = MHD_start_daemon (((int) thrType) | ((int) pollType)
                          | (thrType == testMhdThreadExternal ?
                             0 : MHD_USE_ITC)
                          | (no_listen ? MHD_USE_NO_LISTEN_SOCKET : 0)
                          | MHD_USE_ERROR_LOG,
                          *pport, NULL, NULL,
                          &ahc_echo, "GET",
                          MHD_OPTION_URI_LOG_CALLBACK, &log_cb, NULL,
                          MHD_OPTION_END);
  else
    d = MHD_start_daemon (MHD_USE_INTERNAL_POLLING_THREAD | ((int) pollType)
                          | MHD_USE_ITC
                          | (no_listen ? MHD_USE_NO_LISTEN_SOCKET : 0)
                          | MHD_USE_ERROR_LOG,
                          *pport, NULL, NULL,
                          &ahc_echo, "GET",
                          MHD_OPTION_THREAD_POOL_SIZE, CPU_COUNT,
                          MHD_OPTION_URI_LOG_CALLBACK, &log_cb, NULL,
                          MHD_OPTION_END);

  if (NULL == d)
  {
    fprintf (stderr, "Failed to start MHD daemon, errno=%d.\n", errno);
    abort ();
  }

  if ((! no_listen) && (0 == *pport))
  {
    dinfo = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
    if ((NULL == dinfo) || (0 == dinfo->port) )
    {
      fprintf (stderr, "MHD_get_daemon_info() failed.\n");
      abort ();
    }
    *pport = (int) dinfo->port;
  }

  return d;
}


/* Test runners */


static int
testExternalGet (void)
{
  struct MHD_Daemon *d;
  CURL *c_d;
  char buf_d[2048];
  struct CBC cbc_d;
  CURL *c_a;
  char buf_a[2048];
  struct CBC cbc_a;
  CURLM *multi;
  time_t start;
  struct timeval tv;
  int d_port = global_port; /* Daemon's port */
  int a_port = 0;           /* Additional listening socket port */
  struct addConnParam aParam;
  int ret = 0;              /* Return value of the test */

  d = startTestMhdDaemon (testMhdThreadExternal, testMhdPollBySelect, &d_port);

  aParam.d = d;
  aParam.lstn_sk = createListeningSocket (&a_port);

  multi = NULL;
  cbc_d.buf = buf_d;
  cbc_d.size = sizeof(buf_d);
  cbc_d.pos = 0;
  cbc_a.buf = buf_a;
  cbc_a.size = sizeof(buf_a);
  cbc_a.pos = 0;

  if (! no_listen)
    c_d = curlEasyInitForTest ("http://127.0.0.1" EXPECTED_URI_FULL_PATH,
                               d_port, &cbc_d);

  c_a = curlEasyInitForTest ("http://127.0.0.1" EXPECTED_URI_FULL_PATH,
                             a_port, &cbc_a);

  multi = curl_multi_init ();
  if (multi == NULL)
  {
    fprintf (stderr, "curl_multi_init() failed.\n");
    _exit (99);
  }
  if (! no_listen)
  {
    if (CURLM_OK != curl_multi_add_handle (multi, c_d))
    {
      fprintf (stderr, "curl_multi_add_handle() failed.\n");
      _exit (99);
    }
  }

  if (CURLM_OK != curl_multi_add_handle (multi, c_a))
  {
    fprintf (stderr, "curl_multi_add_handle() failed.\n");
    _exit (99);
  }

  start = time (NULL);
  while (time (NULL) - start <= TIMEOUTS_VAL)
  {
    fd_set rs;
    fd_set ws;
    fd_set es;
    MHD_socket maxMhdSk;
    int maxCurlSk;
    int running;

    maxMhdSk = MHD_INVALID_SOCKET;
    maxCurlSk = -1;
    FD_ZERO (&rs);
    FD_ZERO (&ws);
    FD_ZERO (&es);
    curl_multi_perform (multi, &running);
    if (0 == running)
    {
      struct CURLMsg *msg;
      int msgLeft;
      int totalMsgs = 0;
      do
      {
        msg = curl_multi_info_read (multi, &msgLeft);
        if (NULL == msg)
        {
          fprintf (stderr, "curl_multi_info_read failed, NULL returned.\n");
          _exit (99);
        }
        totalMsgs++;
        if (CURLMSG_DONE == msg->msg)
        {
          if (CURLE_OK != msg->data.result)
          {
            fprintf (stderr, "curl_multi_info_read failed, error: '%s'\n",
                     curl_easy_strerror (msg->data.result));
            ret |= 2;
          }
        }
      } while (msgLeft > 0);
      if ((no_listen ? 1 : 2) != totalMsgs)
      {
        fprintf (stderr,
                 "curl_multi_info_read returned wrong "
                 "number of results (%d).\n",
                 totalMsgs);
        _exit (99);
      }
      break; /* All transfers have finished. */
    }
    if (CURLM_OK != curl_multi_fdset (multi, &rs, &ws, &es, &maxCurlSk))
    {
      fprintf (stderr, "curl_multi_fdset() failed.\n");
      _exit (99);
    }
    if (MHD_YES != MHD_get_fdset (d, &rs, &ws, &es, &maxMhdSk))
    {
      ret |= 8;
      break;
    }
    FD_SET (aParam.lstn_sk, &rs);
    if (maxMhdSk < aParam.lstn_sk)
      maxMhdSk = aParam.lstn_sk;
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
#ifdef MHD_POSIX_SOCKETS
    if (maxMhdSk > maxCurlSk)
      maxCurlSk = maxMhdSk;
#endif /* MHD_POSIX_SOCKETS */
    if (-1 == select (maxCurlSk + 1, &rs, &ws, &es, &tv))
    {
#ifdef MHD_POSIX_SOCKETS
      if (EINTR != errno)
        externalErrorExitDesc ("select() failed");
#else
      if ((WSAEINVAL != WSAGetLastError ()) || (0 != rs.fd_count) || (0 !=
                                                                      ws.
                                                                      fd_count)
          || (0 != es.fd_count) )
        externalErrorExitDesc ("select() failed");
      Sleep (1000);
#endif
    }
    if (FD_ISSET (aParam.lstn_sk, &rs))
      ret |= doAcceptAndAddConnInThread (&aParam);

    if (MHD_YES != MHD_run_from_select (d, &rs, &ws, &es))
    {
      fprintf (stderr, "MHD_run_from_select() failed.\n");
      ret |= 1;
      break;
    }
  }

  MHD_stop_daemon (d);
  (void) MHD_socket_close_ (aParam.lstn_sk);

  if (! no_listen)
  {
    curl_multi_remove_handle (multi, c_d);
    curl_easy_cleanup (c_d);
    if (cbc_d.pos != strlen ("/hello_world"))
    {
      fprintf (stderr,
               "curl reports wrong size of MHD reply body data at line %d.\n",
               __LINE__);
      ret |= 4;
    }
    if (0 != strncmp ("/hello_world", cbc_d.buf, strlen ("/hello_world")))
    {
      fprintf (stderr, "curl reports wrong MHD reply body data at line %d.\n",
               __LINE__);
      ret |= 4;
    }
  }
  curl_multi_remove_handle (multi, c_a);
  curl_easy_cleanup (c_a);
  curl_multi_cleanup (multi);
  if (cbc_a.pos != strlen ("/hello_world"))
  {
    fprintf (stderr,
             "curl reports wrong size of MHD reply body data at line %d.\n",
             __LINE__);
    ret |= 4;
  }
  if (0 != strncmp ("/hello_world", cbc_a.buf, strlen ("/hello_world")))
  {
    fprintf (stderr, "curl reports wrong MHD reply body data at line %d.\n",
             __LINE__);
    ret |= 4;
  }
  return ret;
}


#ifdef HAVE_PTHREAD_H
static int
testInternalGet (enum testMhdPollType pollType)
{
  struct MHD_Daemon *d;
  int d_port = global_port; /* Daemon's port */

  d = startTestMhdDaemon (testMhdThreadInternal, pollType,
                          &d_port);

  return performTestQueries (d, d_port);
}


static int
testMultithreadedGet (enum testMhdPollType pollType)
{
  struct MHD_Daemon *d;
  int d_port = global_port; /* Daemon's port */

  d = startTestMhdDaemon (testMhdThreadInternalPerConnection, pollType,
                          &d_port);

  return performTestQueries (d, d_port);
}


static int
testMultithreadedPoolGet (enum testMhdPollType pollType)
{
  struct MHD_Daemon *d;
  int d_port = global_port; /* Daemon's port */

  d = startTestMhdDaemon (testMhdThreadInternalPool, pollType,
                          &d_port);

  return performTestQueries (d, d_port);
}


static int
testStopRace (enum testMhdPollType pollType)
{
  struct MHD_Daemon *d;
  int d_port = global_port; /* Daemon's port */
  int a_port = 0;           /* Additional listening socket port */
  struct sockaddr_in sin;
  MHD_socket fd1;
  MHD_socket fd2;
  struct addConnParam aParam;
  int ret = 0;              /* Return value of the test */

  d = startTestMhdDaemon (testMhdThreadInternal, pollType,
                          &d_port);

  if (! no_listen)
  {
    fd1 = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (MHD_INVALID_SOCKET == fd1)
      externalErrorExitDesc ("socket() failed");

    memset (&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons (d_port);
    sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    if (connect (fd1, (struct sockaddr *) (&sin), sizeof(sin)) < 0)
      externalErrorExitDesc ("socket() failed");
  }

  aParam.d = d;
  aParam.lstn_sk = createListeningSocket (&a_port); /* Sets a_port */
  startThreadAddConn (&aParam);

  fd2 = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (MHD_INVALID_SOCKET == fd2)
    externalErrorExitDesc ("socket() failed");
  memset (&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (a_port);
  sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (connect (fd2, (struct sockaddr *) (&sin), sizeof(sin)) < 0)
    externalErrorExitDesc ("socket() failed");
  ret |= finishThreadAddConn (&aParam);

  /* Let the thread get going. */
  usleep (500000);

  MHD_stop_daemon (d);

  if (! no_listen)
    (void) MHD_socket_close_ (fd1);
  (void) MHD_socket_close_ (aParam.lstn_sk);
  (void) MHD_socket_close_ (fd2);

  return ret;
}


#endif /* HAVE_PTHREAD_H */


int
main (int argc, char *const *argv)
{
  unsigned int errorCount = 0;
  unsigned int test_result = 0;
  int verbose = 0;

  if ((NULL == argv) || (0 == argv[0]))
    return 99;
  oneone = has_in_name (argv[0], "11");
  no_listen = has_in_name (argv[0], "_nolisten");
  verbose = ! has_param (argc, argv, "-q") || has_param (argc, argv, "--quiet");
  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    return 2;
  /* Could be set to non-zero value to enforce using specific port
   * in the test */
  global_port = 0;
  test_result = testExternalGet ();
  if (test_result)
    fprintf (stderr, "FAILED: testExternalGet () - %u.\n", test_result);
  else if (verbose)
    printf ("PASSED: testExternalGet ().\n");
  errorCount += test_result;
#ifdef HAVE_PTHREAD_H
  if (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_THREADS))
  {
    test_result = testInternalGet (testMhdPollBySelect);
    if (test_result)
      fprintf (stderr, "FAILED: testInternalGet (testMhdPollBySelect) - %u.\n",
               test_result);
    else if (verbose)
      printf ("PASSED: testInternalGet (testMhdPollBySelect).\n");
    errorCount += test_result;
    test_result = testMultithreadedGet (testMhdPollBySelect);
    if (test_result)
      fprintf (stderr,
               "FAILED: testMultithreadedGet (testMhdPollBySelect) - %u.\n",
               test_result);
    else if (verbose)
      printf ("PASSED: testMultithreadedGet (testMhdPollBySelect).\n");
    errorCount += test_result;
    test_result = testMultithreadedPoolGet (testMhdPollBySelect);
    if (test_result)
      fprintf (stderr,
               "FAILED: testMultithreadedPoolGet (testMhdPollBySelect) - %u.\n",
               test_result);
    else if (verbose)
      printf ("PASSED: testMultithreadedPoolGet (testMhdPollBySelect).\n");
    errorCount += test_result;
    test_result = testStopRace (testMhdPollBySelect);
    if (test_result)
      fprintf (stderr, "FAILED: testStopRace (testMhdPollBySelect) - %u.\n",
               test_result);
    else if (verbose)
      printf ("PASSED: testStopRace (testMhdPollBySelect).\n");
    errorCount += test_result;
    if (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_POLL))
    {
      test_result = testInternalGet (testMhdPollByPoll);
      if (test_result)
        fprintf (stderr, "FAILED: testInternalGet (testMhdPollByPoll) - %u.\n",
                 test_result);
      else if (verbose)
        printf ("PASSED: testInternalGet (testMhdPollByPoll).\n");
      errorCount += test_result;
      test_result = testMultithreadedGet (testMhdPollByPoll);
      if (test_result)
        fprintf (stderr,
                 "FAILED: testMultithreadedGet (testMhdPollByPoll) - %u.\n",
                 test_result);
      else if (verbose)
        printf ("PASSED: testMultithreadedGet (testMhdPollByPoll).\n");
      errorCount += test_result;
      test_result = testMultithreadedPoolGet (testMhdPollByPoll);
      if (test_result)
        fprintf (stderr,
                 "FAILED: testMultithreadedPoolGet (testMhdPollByPoll) - %u.\n",
                 test_result);
      else if (verbose)
        printf ("PASSED: testMultithreadedPoolGet (testMhdPollByPoll).\n");
      errorCount += test_result;
      test_result = testStopRace (testMhdPollByPoll);
      if (test_result)
        fprintf (stderr, "FAILED: testStopRace (testMhdPollByPoll) - %u.\n",
                 test_result);
      else if (verbose)
        printf ("PASSED: testStopRace (testMhdPollByPoll).\n");
      errorCount += test_result;
    }
    if (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_EPOLL))
    {
      test_result = testInternalGet (testMhdPollByEpoll);
      if (test_result)
        fprintf (stderr, "FAILED: testInternalGet (testMhdPollByEpoll) - %u.\n",
                 test_result);
      else if (verbose)
        printf ("PASSED: testInternalGet (testMhdPollByEpoll).\n");
      errorCount += test_result;
      test_result = testMultithreadedPoolGet (testMhdPollByEpoll);
      if (test_result)
        fprintf (stderr,
                 "FAILED: testMultithreadedPoolGet (testMhdPollByEpoll) - %u.\n",
                 test_result);
      else if (verbose)
        printf ("PASSED: testMultithreadedPoolGet (testMhdPollByEpoll).\n");
      errorCount += test_result;
    }
  }
#endif /* HAVE_PTHREAD_H */
  if (0 != errorCount)
    fprintf (stderr,
             "Error (code: %u)\n",
             errorCount);
  else if (verbose)
    printf ("All tests passed.\n");
  curl_global_cleanup ();
  return (errorCount == 0) ? 0 : 1;       /* 0 == pass */
}