/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2018 Daniel Pittman and Christian Grothoff

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file lib/daemon.c
 * @brief main functions to create, start, quiesce and destroy a daemon
 * @author Christian Grothoff
 */
#include "internal.h"


/**
 * Logging implementation that logs to a file given
 * as the @a cls.
 *
 * @param cls a `FILE *` to log to
 * @param sc status code of the event (ignored)
 * @param fm format string (`printf()`-style)
 * @param ap arguments to @a fm
 * @ingroup logging
 */
static void
file_logger (void *cls,
	     enum MHD_StatusCode sc,
	     const char *fm,
	     va_list ap)
{
  FILE *f = cls;

  (void) sc;
  (void) vfprintf (f,
		   fm,
		   ap);
}


/**
 * Process escape sequences ('%HH') Updates val in place; the
 * result should be UTF-8 encoded and cannot be larger than the input.
 * The result must also still be 0-terminated.
 *
 * @param cls closure (use NULL)
 * @param req handle to request, not used
 * @param val value to unescape (modified in the process)
 * @return length of the resulting val (strlen(val) maybe
 *  shorter afterwards due to elimination of escape sequences)
 */
static size_t
unescape_wrapper (void *cls,
                  struct MHD_Request *req,
                  char *val)
{
  (void) cls; /* Mute compiler warning. */
  (void) req; /* Mute compiler warning. */
  return MHD_http_unescape (val);
}


/**
 * Create (but do not yet start) an MHD daemon.
 * Usually, you will want to set various options before
 * starting the daemon with #MHD_daemon_start().
 *
 * @param cb function to be called for incoming requests
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
struct MHD_Daemon *
MHD_daemon_create (MHD_RequestCallback cb,
		   void *cb_cls)
{
  struct MHD_Daemon *daemon;

  MHD_check_global_init_();
  if (NULL == cb)
    return NULL;
  if (NULL == (daemon = malloc (sizeof (struct MHD_Daemon))))
    return NULL;
  memset (daemon,
	  0,
	  sizeof (struct MHD_Daemon));
  daemon->rc = cb;
  daemon->rc_cls = cb_cls;
  daemon->logger = &file_logger;
  daemon->logger_cls = stderr;
  daemon->unescape_cb = &unescape_wrapper;
  daemon->tls_ciphers = TLS_CIPHERS_DEFAULT;
  daemon->connection_memory_limit_b = MHD_POOL_SIZE_DEFAULT;
  daemon->connection_memory_increment_b = BUF_INC_SIZE_DEFAULT;
#if ENABLE_DAUTH
  daemon->digest_nc_length = DIGEST_NC_LENGTH_DEFAULT;
#endif
  daemon->listen_backlog = LISTEN_BACKLOG_DEFAULT;  
  daemon->fo_queue_length = FO_QUEUE_LENGTH_DEFAULT;
  daemon->listen_socket = MHD_INVALID_SOCKET;
  return daemon;
}


/**
 * Start a webserver.
 *
 * @param daemon daemon to start; you can no longer set
 *        options on this daemon after this call!
 * @return #MHD_SC_OK on success
 * @ingroup event
 */
enum MHD_StatusCode
MHD_daemon_start (struct MHD_Daemon *daemon)
{
  
  return -1;
}


/**
 * Stop accepting connections from the listening socket.  Allows
 * clients to continue processing, but stops accepting new
 * connections.  Note that the caller is responsible for closing the
 * returned socket; however, if MHD is run using threads (anything but
 * external select mode), it must not be closed until AFTER
 * #MHD_stop_daemon has been called (as it is theoretically possible
 * that an existing thread is still using it).
 *
 * Note that some thread modes require the caller to have passed
 * #MHD_USE_ITC when using this API.  If this daemon is
 * in one of those modes and this option was not given to
 * #MHD_start_daemon, this function will return #MHD_INVALID_SOCKET.
 *
 * @param daemon daemon to stop accepting new connections for
 * @return old listen socket on success, #MHD_INVALID_SOCKET if
 *         the daemon was already not listening anymore, or
 *         was never started
 * @ingroup specialized
 */
MHD_socket
MHD_daemon_quiesce (struct MHD_Daemon *daemon)
{
  return -1;
}


/**
 * Shutdown and destroy an HTTP daemon.
 *
 * @param daemon daemon to stop
 * @ingroup event
 */
void
MHD_daemon_destroy (struct MHD_Daemon *daemon)
{
  free (daemon);
}


/* end of daemon.c */
