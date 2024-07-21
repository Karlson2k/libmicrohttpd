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
 * @file libtest.c
 * @brief testing harness with clients against server
 * @author Christian Grothoff
 */
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "microhttpd2.h"
#include "libtest.h"

/**
 * A semaphore.
 */
struct Semaphore
{
  /**
   * Mutex for the semaphore.
   */
  pthread_mutex_t mutex;

  /**
   * Condition variable for the semaphore.
   */
  pthread_cond_t cv;

  /**
   * Counter of the semaphore.
   */
  unsigned int ctr;
};


/**
 * Check that @a cond is true, otherwise abort().
 *
 * @param cond condition to check
 * @param filename filename to log
 * @param line line number to log
 */
static void
test_check_ (bool cond,
             const char *filename,
             unsigned int line)
{
  if (! cond)
  {
    fprintf (stderr,
             "Assertion failed at %s:%u\n",
             filename,
             line);
    abort ();
  }
}


/**
 * Checks that @a cond is true and otherwise aborts.
 *
 * @param cond condition to check
 */
#define test_check(cond) \
        test_check_ (cond, __FILE__, __LINE__)


/**
 * Initialize a semaphore @a sem with a value of @a val.
 *
 * @param[out] sem semaphore to initialize
 * @param val initial value of the semaphore
 */
static void
semaphore_create (struct Semaphore *sem,
                  unsigned int val)
{
  test_check (0 ==
              pthread_mutex_init (&sem->mutex,
                                  NULL));
  test_check (0 ==
              pthread_cond_init (&sem->cv,
                                 NULL));
  sem->ctr = val;
}


/**
 * Decrement semaphore, blocks until this is possible.
 *
 * @param[in,out] sem semaphore to decrement
 */
static void
semaphore_down (struct Semaphore *sem)
{
  test_check (0 == pthread_mutex_lock (&sem->mutex));
  while (0 == sem->ctr)
  {
    pthread_cond_wait (&sem->cv,
                       &sem->mutex);
  }
  sem->ctr--;
  test_check (0 == pthread_mutex_unlock (&sem->mutex));
}


/**
 * Increment semaphore, blocks until this is possible.
 *
 * @param[in,out] sem semaphore to decrement
 */
static void
semaphore_up (struct Semaphore *sem)
{
  test_check (0 == pthread_mutex_lock (&sem->mutex));
  sem->ctr++;
  test_check (0 == pthread_mutex_unlock (&sem->mutex));
  pthread_cond_signal (&sem->cv);
}


/**
 * Release resources used by @a sem.
 *
 * @param[in] sem semaphore to release (except the memory itself)
 */
static void
semaphore_destroy (struct Semaphore *sem)
{
  test_check (0 == pthread_cond_destroy (&sem->cv));
  test_check (0 == pthread_mutex_destroy (&sem->mutex));
}


/**
 * Context for the implementation of the HTTP server.
 */
struct ServerContext
{
  /**
   * Semaphore the client raises when it goes into the
   * next phase.
   */
  struct Semaphore client_sem;

  /**
   * Semaphore the server raises when it goes into the
   * next phase.
   */
  struct Semaphore server_sem;

  /**
   * Current phase of the server.
   */
  const struct MHDT_Phase *phase;

  /**
   * Main function to run the server.
   */
  MHDT_ServerRunner run_cb;

  /**
   * Closure for @e run_cb.
   */
  void *run_cb_cls;

  /**
   * The daemon we are running.
   */
  struct MHD_Daemon *d;

  /**
   * Signal for server termination.
   */
  int finsig;
};


/**
 * A client has requested the given url using the given method
 * (#MHD_HTTP_METHOD_GET, #MHD_HTTP_METHOD_PUT,
 * #MHD_HTTP_METHOD_DELETE, #MHD_HTTP_METHOD_POST, etc).
 * If @a upload_size is not zero and response action is provided by this
 * callback, then upload will be discarded and the stream (the connection for
 * HTTP/1.1) will be closed after sending the response.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
static const struct MHD_Action *
server_req_cb (void *cls,
               struct MHD_Request *MHD_RESTRICT request,
               const struct MHD_String *MHD_RESTRICT path,
               enum MHD_HTTP_Method method,
               uint_fast64_t upload_size)
{
  struct ServerContext *sc = cls;

  if (NULL == sc->phase->label)
    return NULL;
  return sc->phase->server_cb (sc->phase->server_cb_cls,
                               request,
                               path,
                               method,
                               upload_size);
}


/**
 * Closure for run_single_client()
 */
struct ClientContext
{
  /**
   * Test phase to run.
   */
  const struct MHDT_Phase *phase;

  /**
   * Phase and client specific context.
   */
  struct MHDT_PhaseContext pc;

  /**
   * Pipe to use to signal that the thread has
   * finished.
   */
  int p2;

  /**
   * Set to true on success.
   */
  bool status;
};


/**
 * Runs the logic for a single client in a thread.
 *
 * @param cls a `struct ClientContext`
 * @return NULL
 */
static void *
run_single_client (void *cls)
{
  struct ClientContext *cc = cls;
  const char *err;

  fprintf (stderr,
           "Client %u started in phase `%s'\n",
           cc->pc.client_id,
           cc->phase->label);
  err = cc->phase->client_cb (cc->phase->client_cb_cls,
                              &cc->pc);
  if (NULL != err)
  {
    fprintf (stderr,
             "Client %u failed in phase `%s': %s\n",
             cc->pc.client_id,
             cc->phase->label,
             err);
    /* This is a blocking write, thus must succeed */
    test_check (1 ==
                write (cc->p2,
                       "e",
                       1));
    return NULL;
  }
  cc->status = true;
  /* This is a blocking write, thus must succeed */
  test_check (1 ==
              write (cc->p2,
                     "s",
                     1));
  fprintf (stderr,
           "Client %u finished in phase `%s'\n",
           cc->pc.client_id,
           cc->phase->label);
  return NULL;
}


/**
 * Creates a pipe with a non-blocking read end.
 *
 * @param p pipe to initialize
 */
static void
make_pipe (int p[2])
{
  int flags;

  test_check (0 ==
              pipe (p));
  flags = fcntl (p[0],
                 F_GETFL);
  flags |= O_NONBLOCK;
  test_check (0 ==
              fcntl (p[0],
                     F_SETFL,
                     flags));
}


/**
 * Run client processes for the given test @a phase
 *
 * @param phase test phase to run
 * @param pc context to give to clients
 */
static bool
run_client_phase (const struct MHDT_Phase *phase,
                  const struct MHDT_PhaseContext *pc)
{
  unsigned int num_clients
    = (0 == phase->num_clients)
    ? 1
    : phase->num_clients;
  unsigned int clients_left = 0;
  struct ClientContext cctxs[num_clients];
  pthread_t clients[num_clients];
  int p[2];
  unsigned int i;
  bool ret = true;

  make_pipe (p);
  fprintf (stderr,
           "Starting phase `%s'\n",
           phase->label);
  for (i = 0; i<num_clients; i++)
  {
    cctxs[i].phase = phase;
    cctxs[i].pc = *pc;
    cctxs[i].pc.client_id = i;
    cctxs[i].p2 = p[1];
    cctxs[i].status = false;
    if (0 !=
        pthread_create (&clients[i],
                        NULL,
                        &run_single_client,
                        &cctxs[i]))
      goto cleanup;
    clients_left++;
  }

  /* 0 for timeout_ms means no timeout, we deliberately
     underflow to MAX_UINT in this case... */
  for (i = phase->timeout_ms - 1; i>0; i--)
  {
    struct timespec ms = {
      .tv_nsec = 1000 * 1000
    };
    struct timespec rem;
    char c;

    if (0 != nanosleep (&ms,
                        &rem))
    {
      fprintf (stderr,
               "nanosleep() interrupted (%s), trying again\n",
               strerror (errno));
      i++;
    }
    /* This is a non-blocking read */
    while (1 == read (p[0],
                      &c,
                      1))
      clients_left--;
    if (0 == clients_left)
      break;
  }
  if (0 != clients_left)
  {
    fprintf (stderr,
             "Timeout (%u ms) in phase `%s': %u clients still running\n",
             phase->timeout_ms,
             phase->label,
             clients_left);
    exit (1);
  }
cleanup:
  for (i = 0; i<num_clients; i++)
  {
    void *res;

    test_check (0 ==
                pthread_join (clients[i],
                              &res));
    if (! cctxs[i].status)
      ret = false;
  }
  test_check (0 == close (p[0]));
  test_check (0 == close (p[1]));
  fprintf (stderr,
           "Finished phase `%s' with %s\n",
           phase->label,
           ret ? "success" : "FAILURE");
  return ret;
}


/**
 * Thread that switches the server to the next phase
 * as needed.
 *
 * @param cls a `struct ServerContext`
 * @return NULL
 */
static void *
server_phase_logic (void *cls)
{
  struct ServerContext *ctx = cls;
  unsigned int i;

  for (i = 0; NULL != ctx->phase->label; i++)
  {
    fprintf (stderr,
             "Running server phase `%s'\n",
             ctx->phase->label);
    semaphore_down (&ctx->client_sem);
    ctx->phase++;
    semaphore_up (&ctx->server_sem);
  }
  fprintf (stderr,
           "Server terminating\n");
  return NULL;
}


/**
 * Thread that runs the MHD daemon.
 *
 * @param cls a `struct ServerContext`
 * @return NULL
 */
static void *
server_run_logic (void *cls)
{
  struct ServerContext *ctx = cls;

  ctx->run_cb (ctx->run_cb_cls,
               ctx->finsig,
               ctx->d);
  return NULL;
}


int
MHDT_test (MHDT_ServerSetup ss_cb,
           void *ss_cb_cls,
           MHDT_ServerRunner run_cb,
           void *run_cb_cls,
           const struct MHDT_Phase *phases)
{
  struct ServerContext ctx = {
    .run_cb = run_cb,
    .run_cb_cls = run_cb_cls,
    .phase = &phases[0]
  };
  struct MHD_Daemon *d;
  int res;
  const char *err;
  pthread_t server_phase_thr;
  pthread_t server_run_thr;
  struct MHDT_PhaseContext pc;
  char base_url[128];
  unsigned int i;
  int p[2];

  make_pipe (p);
  semaphore_create (&ctx.server_sem,
                    0);
  semaphore_create (&ctx.client_sem,
                    0);
  d = MHD_daemon_create (&server_req_cb,
                         &ctx);
  if (NULL == d)
    exit (77);
  err = ss_cb (ss_cb_cls,
               d);
  if (NULL != err)
  {
    fprintf (stderr,
             "Failed to setup server: %s\n",
             err);
    return 1;
  }
  {
    enum MHD_StatusCode sc;

    sc = MHD_daemon_start (d);
    if (MHD_SC_OK != sc)
    {
      fprintf (stderr,
               "Failed to start server: %s\n",
               err);
      return 1;
    }
  }
  {
    union MHD_DaemonInfoFixedData info;
    enum MHD_StatusCode sc;

    sc = MHD_daemon_get_info_fixed (
      d,
      MHD_DAEMON_INFO_FIXED_BIND_PORT,
      &info);
    test_check (MHD_SC_OK == sc);
    snprintf (base_url,
              sizeof (base_url),
              "http://localhost:%u/",
              (unsigned int) info.v_port);
    pc.base_url = base_url;
  }
  if (0 != pthread_create (&server_phase_thr,
                           NULL,
                           &server_phase_logic,
                           &ctx))
  {
    fprintf (stderr,
             "Failed to start server phase thread: %s\n",
             strerror (errno));
    return 77;
  }
  ctx.finsig = p[0];
  ctx.d = d;
  if (0 != pthread_create (&server_run_thr,
                           NULL,
                           &server_run_logic,
                           &ctx))
  {
    fprintf (stderr,
             "Failed to start server run thread: %s\n",
             strerror (errno));
    return 77;
  }
  for (i = 0; NULL != phases[i].label; i++)
  {
    fprintf (stderr,
             "Running test phase `%s'\n",
             phases[i].label);
    if (! run_client_phase (&phases[i],
                            &pc))
    {
      res = 1;
      goto cleanup;
    }
    /* client is done with phase */
    semaphore_up (&ctx.client_sem);
    /* wait for server to have moved to new phase */
    semaphore_down (&ctx.server_sem);
  }
  res = 0;
cleanup:
  /* stop thread that runs the actual server */
  {
    void *pres;

    test_check (1 ==
                write (p[1],
                       "e",
                       1));
    test_check (0 ==
                pthread_join (server_run_thr,
                              &pres));
  }
  {
    void *pres;

    /* Unblock the #server_phase_logic() even if we had
       an error */
    for (i = 0; NULL != phases[i].label; i++)
      semaphore_up (&ctx.client_sem);
    test_check (0 ==
                pthread_join (server_phase_thr,
                              &pres));
  }
  MHD_daemon_destroy (d);
  semaphore_destroy (&ctx.client_sem);
  semaphore_destroy (&ctx.server_sem);
  test_check (0 == close (p[0]));
  test_check (0 == close (p[1]));
  return res;
}
