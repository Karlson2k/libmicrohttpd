/*
     This file is part of libmicrohttpd
     (C) 2007 Daniel Pittman and Christian Grothoff

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
 * @file daemon.c
 * @brief  A minimal-HTTP server library
 * @author Daniel Pittman
 * @author Christian Grothoff
 */

#include "internal.h"
#include "response.h"
#include "connection.h"
#include "memorypool.h"

/**
 * Default connection limit.
 */
#define MHD_MAX_CONNECTIONS_DEFAULT FD_SETSIZE -4

/**
 * Default memory allowed per connection.
 */
#define MHD_POOL_SIZE_DEFAULT (1024 * 1024)

/**
 * Print extra messages with reasons for closing
 * sockets? (only adds non-error messages). 
 */
#define DEBUG_CLOSE 0

/**
 * Register an access handler for all URIs beginning with uri_prefix.
 *
 * @param uri_prefix
 * @return MRI_NO if a handler for this exact prefix
 *         already exists
 */
int
MHD_register_handler (struct MHD_Daemon *daemon,
                      const char *uri_prefix,
                      MHD_AccessHandlerCallback dh, void *dh_cls)
{
  struct MHD_Access_Handler *ah;

  if ((daemon == NULL) || (uri_prefix == NULL) || (dh == NULL))
    return MHD_NO;
  ah = daemon->handlers;
  while (ah != NULL)
    {
      if (0 == strcmp (uri_prefix, ah->uri_prefix))
        return MHD_NO;
      ah = ah->next;
    }
  ah = malloc (sizeof (struct MHD_Access_Handler));
  if (ah == NULL)
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Error allocating memory: %s\n", STRERROR (errno));
#endif
      return MHD_NO;
    }

  ah->next = daemon->handlers;
  ah->uri_prefix = strdup (uri_prefix);
  ah->dh = dh;
  ah->dh_cls = dh_cls;
  daemon->handlers = ah;
  return MHD_YES;
}


/**
 * Unregister an access handler for the URIs beginning with
 * uri_prefix.
 *
 * @param uri_prefix
 * @return MHD_NO if a handler for this exact prefix
 *         is not known for this daemon
 */
int
MHD_unregister_handler (struct MHD_Daemon *daemon,
                        const char *uri_prefix,
                        MHD_AccessHandlerCallback dh, void *dh_cls)
{
  struct MHD_Access_Handler *prev;
  struct MHD_Access_Handler *pos;

  if ((daemon == NULL) || (uri_prefix == NULL) || (dh == NULL))
    return MHD_NO;
  pos = daemon->handlers;
  prev = NULL;
  while (pos != NULL)
    {
      if ((dh == pos->dh) &&
          (dh_cls == pos->dh_cls) &&
          (0 == strcmp (uri_prefix, pos->uri_prefix)))
        {
          if (prev == NULL)
            daemon->handlers = pos->next;
          else
            prev->next = pos->next;
          free (pos);
          return MHD_YES;
        }
      prev = pos;
      pos = pos->next;
    }
  return MHD_NO;
}

/**
 * Obtain the select sets for this daemon.
 *
 * @return MHD_YES on success, MHD_NO if this
 *         daemon was not started with the right
 *         options for this call.
 */
int
MHD_get_fdset (struct MHD_Daemon *daemon,
               fd_set * read_fd_set,
               fd_set * write_fd_set, fd_set * except_fd_set, int *max_fd)
{
  struct MHD_Connection *pos;
  int fd;

  if ((daemon == NULL) ||
      (read_fd_set == NULL) ||
      (write_fd_set == NULL) ||
      (except_fd_set == NULL) ||
      (max_fd == NULL) ||
      (-1 == (fd = daemon->socket_fd)) ||
      (daemon->shutdown == MHD_YES) ||
      ((daemon->options & MHD_USE_THREAD_PER_CONNECTION) != 0))
    return MHD_NO;
  FD_SET (fd, read_fd_set);
  if ((*max_fd) < fd)
    *max_fd = fd;
  pos = daemon->connections;
  while (pos != NULL)
    {
      if (MHD_YES != MHD_connection_get_fdset (pos,
                                               read_fd_set,
                                               write_fd_set,
                                               except_fd_set, max_fd))
        return MHD_NO;
      pos = pos->next;
    }
  return MHD_YES;
}


/**
 * Main function of the thread that handles an individual
 * connection.
 */
static void *
MHD_handle_connection (void *data)
{
  struct MHD_Connection *con = data;
  int num_ready;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct timeval tv;
  unsigned int timeout;
  time_t now;

  if (con == NULL)
    abort ();
  timeout = con->daemon->connection_timeout;
  now = time (NULL);
  while ((!con->daemon->shutdown) &&
         (con->socket_fd != -1) &&
         ((timeout == 0) || (now - timeout > con->last_activity)))
    {
      FD_ZERO (&rs);
      FD_ZERO (&ws);
      FD_ZERO (&es);
      max = 0;
      MHD_connection_get_fdset (con, &rs, &ws, &es, &max);
      tv.tv_usec = 0;
      tv.tv_sec = timeout - (now - con->last_activity);
      num_ready = SELECT (max + 1,
                          &rs, &ws, &es, (timeout != 0) ? &tv : NULL);
      now = time (NULL);
      if (num_ready < 0)
        {
          if (errno == EINTR)
            continue;
#if HAVE_MESSAGES
          MHD_DLOG (con->daemon, "Error during select (%d): `%s'\n",
                    max, STRERROR (errno));
#endif
          break;
        }
      if (((FD_ISSET (con->socket_fd, &rs)) &&
           (MHD_YES != MHD_connection_handle_read (con))) ||
          ((con->socket_fd != -1) &&
           (FD_ISSET (con->socket_fd, &ws)) &&
           (MHD_YES != MHD_connection_handle_write (con))))
        break;
      if ((con->headersReceived == 1) && (con->response == NULL))
        MHD_call_connection_handler (con);
      if ((con->socket_fd != -1) &&
          ((FD_ISSET (con->socket_fd, &rs)) ||
           (FD_ISSET (con->socket_fd, &ws))))
        con->last_activity = now;
    }
  if (con->socket_fd != -1)
    {
#if DEBUG_CLOSE
#if HAVE_MESSAGES
      MHD_DLOG (con->daemon,
                "Processing thread terminating, closing connection\n");
#endif
#endif
      SHUTDOWN (con->socket_fd, SHUT_RDWR);
      CLOSE (con->socket_fd);
      con->socket_fd = -1;
    }
  return NULL;
}


/**
 * Accept an incoming connection and create the MHD_Connection object for
 * it.  This function also enforces policy by way of checking with the
 * accept policy callback.
 */
static int
MHD_accept_connection (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *connection;
  struct sockaddr_in6 addr6;
  struct sockaddr *addr = (struct sockaddr *) &addr6;
  socklen_t addrlen;
  int s;
#if OSX
  static int on=1;
#endif


  if (sizeof (struct sockaddr) > sizeof (struct sockaddr_in6))
    abort ();                   /* fatal, serious error */
  addrlen = sizeof (struct sockaddr_in6);
  memset (addr, 0, sizeof (struct sockaddr_in6));
  s = ACCEPT (daemon->socket_fd, addr, &addrlen);
  if ((s < 0) || (addrlen <= 0))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Error accepting connection: %s\n", STRERROR (errno));
#endif
      if (s != -1)
        {
          SHUTDOWN (s, SHUT_RDWR);
          CLOSE (s);            /* just in case */
        }
      return MHD_NO;
    }
  if (daemon->max_connections == 0)
    {
      /* above connection limit - reject */
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
                "Server reached connection limit (closing inbound connection)\n");
#endif
      SHUTDOWN (s, SHUT_RDWR);
      CLOSE (s);
      return MHD_NO;
    }
  if ((daemon->apc != NULL) &&
      (MHD_NO == daemon->apc (daemon->apc_cls, addr, addrlen)))
    {
#if DEBUG_CLOSE
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Connection rejected, closing connection\n");
#endif
#endif
      SHUTDOWN (s, SHUT_RDWR);
      CLOSE (s);
      return MHD_YES;
    }
#if OSX
#ifdef SOL_SOCKET
#ifdef SO_NOSIGPIPE
  setsockopt(s,
	     SOL_SOCKET,
	     SO_NOSIGPIPE,
	     &on,
	     sizeof(on));
#endif
#endif
#endif
  connection = malloc (sizeof (struct MHD_Connection));
  if (connection == NULL)
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Error allocating memory: %s\n", STRERROR (errno));
#endif
      SHUTDOWN (s, SHUT_RDWR);
      CLOSE (s);
      return MHD_NO;
    }
  memset (connection, 0, sizeof (struct MHD_Connection));
  connection->pool = NULL;
  connection->addr = malloc (addrlen);
  if (connection->addr == NULL)
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Error allocating memory: %s\n", STRERROR (errno));
#endif
      SHUTDOWN (s, SHUT_RDWR);
      CLOSE (s);
      free (connection);
      return MHD_NO;
    }
  memcpy (connection->addr, addr, addrlen);
  connection->addr_len = addrlen;
  connection->socket_fd = s;
  connection->daemon = daemon;
  if ((0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
      (0 != pthread_create (&connection->pid,
                            NULL, &MHD_handle_connection, connection)))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Failed to create a thread: %s\n", STRERROR (errno));
#endif
      SHUTDOWN (s, SHUT_RDWR);
      CLOSE (s);
      free (connection->addr);
      free (connection);
      return MHD_NO;
    }
  connection->last_activity = time (NULL);
  connection->next = daemon->connections;
  daemon->connections = connection;
  daemon->max_connections--;
  return MHD_YES;
}


/**
 * Free resources associated with all closed connections.
 * (destroy responses, free buffers, etc.).  A connection
 * is known to be closed if the socket_fd is -1.
 *
 * Also performs connection actions that need to be run
 * even if the connection is not selectable (such as
 * calling the application again with upload data when
 * the upload data buffer is full).
 */
static void
MHD_cleanup_connections (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *pos;
  struct MHD_Connection *prev;
  void *unused;
  time_t timeout;

  timeout = time (NULL);
  if (daemon->connection_timeout != 0)
    timeout -= daemon->connection_timeout;
  else
    timeout = 0;
  pos = daemon->connections;
  prev = NULL;
  while (pos != NULL)
    {
      if ((pos->last_activity < timeout) && (pos->socket_fd != -1))
        {
#if DEBUG_CLOSE
#if HAVE_MESSAGES
          MHD_DLOG (daemon, "Connection timed out, closing connection\n");
#endif
#endif
          SHUTDOWN (pos->socket_fd, SHUT_RDWR);
          CLOSE (pos->socket_fd);
          pos->socket_fd = -1;
          if (pos->daemon->notify_completed != NULL)
            pos->daemon->notify_completed (pos->daemon->notify_completed_cls,
                                           pos,
                                           &pos->client_context,
                                           MHD_REQUEST_TERMINATED_TIMEOUT_REACHED);
        }
      if (pos->socket_fd == -1)
        {
          if (prev == NULL)
            daemon->connections = pos->next;
          else
            prev->next = pos->next;
          if (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
            {
              pthread_kill (pos->pid, SIGALRM);
              pthread_join (pos->pid, &unused);
            }
          if (pos->response != NULL)
            MHD_destroy_response (pos->response);
          MHD_pool_destroy (pos->pool);
          free (pos->addr);
          free (pos);
          daemon->max_connections++;
          if (prev == NULL)
            pos = daemon->connections;
          else
            pos = prev->next;
          continue;
        }

      if ((pos->headersReceived == 1) && (pos->response == NULL))
        MHD_call_connection_handler (pos);

      prev = pos;
      pos = pos->next;
    }
}

/**
 * Obtain timeout value for select for this daemon
 * (only needed if connection timeout is used).  The
 * returned value is how long select should at most
 * block, not the timeout value set for connections.
 *
 * @param timeout set to the timeout (in milliseconds)
 * @return MHD_YES on success, MHD_NO if timeouts are
 *        not used (or no connections exist that would
 *        necessiate the use of a timeout right now).
 */
int
MHD_get_timeout (struct MHD_Daemon *daemon, unsigned long long *timeout)
{
  time_t earliest_deadline;
  time_t now;
  struct MHD_Connection *pos;
  unsigned int dto;

  dto = daemon->connection_timeout;
  if (0 == dto)
    return MHD_NO;
  pos = daemon->connections;
  if (pos == NULL)
    return MHD_NO;              /* no connections */
  now = time (NULL);
  /* start with conservative estimate */
  earliest_deadline = now + dto;
  while (pos != NULL)
    {
      if (earliest_deadline > pos->last_activity + dto)
        earliest_deadline = pos->last_activity + dto;
      pos = pos->next;
    }
  if (earliest_deadline < now)
    *timeout = 0;
  else
    *timeout = (earliest_deadline - now);
  return MHD_YES;
}

/**
 * Main select call.
 *
 * @param may_block YES if blocking, NO if non-blocking
 * @return MHD_NO on serious errors, MHD_YES on success
 */
static int
MHD_select (struct MHD_Daemon *daemon, int may_block)
{
  struct MHD_Connection *pos;
  int num_ready;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct timeval timeout;
  unsigned long long ltimeout;
  int ds;
  time_t now;

  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  if (daemon == NULL)
    abort ();
  if (daemon->shutdown == MHD_YES)
    return MHD_NO;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  max = 0;

  if (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    {
      /* single-threaded, go over everything */
      if (MHD_NO == MHD_get_fdset (daemon, &rs, &ws, &es, &max))
        return MHD_NO;
    }
  else
    {
      /* accept only, have one thread per connection */
      max = daemon->socket_fd;
      if (max == -1)
        return MHD_NO;
      FD_SET (max, &rs);
    }
  if (may_block == MHD_NO)
    {
      timeout.tv_usec = 0;
      timeout.tv_sec = 0;
    }
  else
    {
      /* ltimeout is in ms */
      if (MHD_YES == MHD_get_timeout (daemon, &ltimeout))
        {
          timeout.tv_usec = (ltimeout % 1000) * 1000;
          timeout.tv_sec = ltimeout / 1000;
          may_block = MHD_NO;
        }
    }
  num_ready = SELECT (max + 1,
                      &rs, &ws, &es, may_block == MHD_NO ? &timeout : NULL);
  if (daemon->shutdown == MHD_YES)
    return MHD_NO;
  if (num_ready < 0)
    {
      if (errno == EINTR)
        return MHD_YES;
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Select failed: %s\n", STRERROR (errno));
#endif
      return MHD_NO;
    }
  ds = daemon->socket_fd;
  if (ds == -1)
    return MHD_YES;
  if (FD_ISSET (ds, &rs))
    MHD_accept_connection (daemon);
  if (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    {
      /* do not have a thread per connection, process all connections now */
      now = time (NULL);
      pos = daemon->connections;
      while (pos != NULL)
        {
          ds = pos->socket_fd;
          if (ds != -1)
            {
              if (FD_ISSET (ds, &rs))
                {
                  pos->last_activity = now;
                  MHD_connection_handle_read (pos);
                }
              if (FD_ISSET (ds, &ws))
                {
                  pos->last_activity = now;
                  MHD_connection_handle_write (pos);
                }
            }
          pos = pos->next;
        }
    }
  return MHD_YES;
}


/**
 * Run webserver operations (without blocking unless
 * in client callbacks).  This method should be called
 * by clients in combination with MHD_get_fdset
 * if the client-controlled select method is used.
 *
 * @return MHD_YES on success, MHD_NO if this
 *         daemon was not started with the right
 *         options for this call.
 */
int
MHD_run (struct MHD_Daemon *daemon)
{
  if ((daemon->shutdown != MHD_NO) ||
      (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) ||
      (0 != (daemon->options & MHD_USE_SELECT_INTERNALLY)))
    return MHD_NO;
  MHD_select (daemon, MHD_NO);
  MHD_cleanup_connections (daemon);
  return MHD_YES;
}


/**
 * Thread that runs the select loop until the daemon
 * is explicitly shut down.
 */
static void *
MHD_select_thread (void *cls)
{
  struct MHD_Daemon *daemon = cls;
  while (daemon->shutdown == MHD_NO)
    {
      MHD_select (daemon, MHD_YES);
      MHD_cleanup_connections (daemon);
    }
  return NULL;
}


/**
 * Start a webserver on the given port.
 *
 * @param port port to bind to
 * @param apc callback to call to check which clients
 *        will be allowed to connect
 * @param apc_cls extra argument to apc
 * @param dh default handler for all URIs
 * @param dh_cls extra argument to dh
 * @return NULL on error, handle to daemon on success
 */
struct MHD_Daemon *
MHD_start_daemon (unsigned int options,
                  unsigned short port,
                  MHD_AcceptPolicyCallback apc,
                  void *apc_cls,
                  MHD_AccessHandlerCallback dh, void *dh_cls, ...)
{
  const int on = 1;
  struct MHD_Daemon *retVal;
  int socket_fd;
  struct sockaddr_in servaddr4;
  struct sockaddr_in6 servaddr6;
  const struct sockaddr *servaddr;
  socklen_t addrlen;
  va_list ap;
  enum MHD_OPTION opt;

  if ((options & MHD_USE_SSL) != 0)
    return NULL;
  if ((port == 0) || (dh == NULL))
    return NULL;
  if ((options & MHD_USE_IPv6) != 0)
    socket_fd = SOCKET (PF_INET6, SOCK_STREAM, 0);
  else
    socket_fd = SOCKET (PF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0)
    {
#if HAVE_MESSAGES
      if ((options & MHD_USE_DEBUG) != 0)
        fprintf (stderr, "Call to socket failed: %s\n", STRERROR (errno));
#endif
      return NULL;
    }
  if ((SETSOCKOPT (socket_fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &on, sizeof (on)) < 0) && (options & MHD_USE_DEBUG) != 0) {
#if HAVE_MESSAGES
    fprintf (stderr, "setsockopt failed: %s\n", STRERROR (errno));
#endif
  }
  if ((options & MHD_USE_IPv6) != 0)
    {
      memset (&servaddr6, 0, sizeof (struct sockaddr_in6));
      servaddr6.sin6_family = AF_INET6;
      servaddr6.sin6_port = htons (port);
      servaddr = (struct sockaddr *) &servaddr6;
      addrlen = sizeof (struct sockaddr_in6);
    }
  else
    {
      memset (&servaddr4, 0, sizeof (struct sockaddr_in));
      servaddr4.sin_family = AF_INET;
      servaddr4.sin_port = htons (port);
      servaddr = (struct sockaddr *) &servaddr4;
      addrlen = sizeof (struct sockaddr_in);
    }
  if (BIND (socket_fd, servaddr, addrlen) < 0)
    {
#if HAVE_MESSAGES
      if ((options & MHD_USE_DEBUG) != 0)
        fprintf (stderr,
                 "Failed to bind to port %u: %s\n", port, STRERROR (errno));
#endif
      CLOSE (socket_fd);
      return NULL;
    }
  if (LISTEN (socket_fd, 20) < 0)
    {
#if HAVE_MESSAGES
      if ((options & MHD_USE_DEBUG) != 0)
        fprintf (stderr,
                 "Failed to listen for connections: %s\n", STRERROR (errno));
#endif
      CLOSE (socket_fd);
      return NULL;
    }
  retVal = malloc (sizeof (struct MHD_Daemon));
  memset (retVal, 0, sizeof (struct MHD_Daemon));
  retVal->options = options;
  retVal->port = port;
  retVal->apc = apc;
  retVal->apc_cls = apc_cls;
  retVal->socket_fd = socket_fd;
  retVal->default_handler.dh = dh;
  retVal->default_handler.dh_cls = dh_cls;
  retVal->default_handler.uri_prefix = "";
  retVal->default_handler.next = NULL;
  retVal->max_connections = MHD_MAX_CONNECTIONS_DEFAULT;
  retVal->pool_size = MHD_POOL_SIZE_DEFAULT;
  retVal->connection_timeout = 0;       /* no timeout */
  va_start (ap, dh_cls);
  while (MHD_OPTION_END != (opt = va_arg (ap, enum MHD_OPTION)))
    {
      switch (opt)
        {
        case MHD_OPTION_CONNECTION_MEMORY_LIMIT:
          retVal->pool_size = va_arg (ap, unsigned int);
          break;
        case MHD_OPTION_CONNECTION_LIMIT:
          retVal->max_connections = va_arg (ap, unsigned int);
          break;
        case MHD_OPTION_CONNECTION_TIMEOUT:
          retVal->connection_timeout = va_arg (ap, unsigned int);
          break;
        case MHD_OPTION_NOTIFY_COMPLETED:
          retVal->notify_completed =
            va_arg (ap, MHD_RequestCompletedCallback);
          retVal->notify_completed_cls = va_arg (ap, void *);
          break;
        default:
#if HAVE_MESSAGES
          fprintf (stderr,
                   "Invalid MHD_OPTION argument! (Did you terminate the list with MHD_OPTION_END?)\n");
#endif
          abort ();
        }
    }
  va_end (ap);
  if (((0 != (options & MHD_USE_THREAD_PER_CONNECTION)) ||
       (0 != (options & MHD_USE_SELECT_INTERNALLY))) &&
      (0 != pthread_create (&retVal->pid, NULL, &MHD_select_thread, retVal)))
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal,
                "Failed to create listen thread: %s\n", STRERROR (errno));
#endif
      free (retVal);
      CLOSE (socket_fd);
      return NULL;
    }
  return retVal;
}

/**
 * Shutdown an http daemon.
 */
void
MHD_stop_daemon (struct MHD_Daemon *daemon)
{
  void *unused;
  int fd;

  if (daemon == NULL)
    return;
  daemon->shutdown = MHD_YES;
  fd = daemon->socket_fd;
  daemon->socket_fd = -1;
#if DEBUG_CLOSE
#if HAVE_MESSAGES
  MHD_DLOG (daemon, "MHD shutdown, closing listen socket\n");
#endif
#endif
  CLOSE (fd);
  if ((0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) ||
      (0 != (daemon->options & MHD_USE_SELECT_INTERNALLY)))
    {
      pthread_kill (daemon->pid, SIGALRM);
      pthread_join (daemon->pid, &unused);
    }
  while (daemon->connections != NULL)
    {
      if (-1 != daemon->connections->socket_fd)
        {
#if DEBUG_CLOSE
#if HAVE_MESSAGES
          MHD_DLOG (daemon, "MHD shutdown, closing active connections\n");
#endif
#endif
          if (daemon->notify_completed != NULL)
            daemon->notify_completed (daemon->notify_completed_cls,
                                      daemon->connections,
                                      &daemon->connections->client_context,
                                      MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN);
          SHUTDOWN (daemon->connections->socket_fd, SHUT_RDWR);
          CLOSE (daemon->connections->socket_fd);
          daemon->connections->socket_fd = -1;
        }
      MHD_cleanup_connections (daemon);
    }
  free (daemon);
}

#ifndef WINDOWS

static struct sigaction sig;

static struct sigaction old;

static void
sigalrmHandler (int sig)
{
}

/**
 * Initialize the signal handler for SIGALRM.
 */
void __attribute__ ((constructor)) MHD_pthread_handlers_ltdl_init ()
{
  /* make sure SIGALRM does not kill us */
  memset (&sig, 0, sizeof (struct sigaction));
  memset (&old, 0, sizeof (struct sigaction));
  sig.sa_flags = SA_NODEFER;
  sig.sa_handler = &sigalrmHandler;
  sigaction (SIGALRM, &sig, &old);
}

void __attribute__ ((destructor)) MHD_pthread_handlers_ltdl_fini ()
{
  sigaction (SIGALRM, &old, &sig);
}
#else
void __attribute__ ((constructor)) MHD_win_ltdl_init ()
{
  plibc_init ("CRISP", "libmicrohttpd");
}

void __attribute__ ((destructor)) MHD_win_ltdl_fini ()
{
  plibc_shutdown ();
}
#endif

/* end of daemon.c */
