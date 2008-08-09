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

#if HTTPS_SUPPORT
#include "gnutls_int.h"
#include "gnutls_global.h"
#include "auth_anon.h"
#endif

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
#define DEBUG_CLOSE MHD_NO

/**
 * Print extra messages when establishing
 * connections? (only adds non-error messages).
 */
#define DEBUG_CONNECT MHD_NO

/* TODO unite with code in gnutls_priority.c */
static int
MHD_init_daemon_certificate (struct MHD_Daemon *daemon)
{
  gnutls_datum_t key;
  gnutls_datum_t cert;

  /* certificate & key loaded from file */
  if (daemon->https_cert_path && daemon->https_key_path)
    {
      /* test for private key & certificate file exsitance */
      if (access (daemon->https_cert_path, R_OK))
        {
#if HAVE_MESSAGES
          MHD_DLOG (daemon, "Missing X.509 certificate file\n");
#endif
          free (daemon);
          CLOSE (daemon->socket_fd);
          return -1;
        }

      if (access (daemon->https_key_path, R_OK))
        {
#if HAVE_MESSAGES
          MHD_DLOG (daemon, "Missing X.509 key file\n");
#endif
          free (daemon);
          CLOSE (daemon->socket_fd);
          return -1;
        }
      return gnutls_certificate_set_x509_key_file (daemon->x509_cred,
                                                   daemon->https_cert_path,
                                                   daemon->https_key_path,
                                                   GNUTLS_X509_FMT_PEM);
    }
  /* certificate & key loaded from memory */
  else if (daemon->https_mem_cert && daemon->https_mem_key)
    {
      key.data = (unsigned char *) daemon->https_mem_key;
      key.size = strlen (daemon->https_mem_key);
      cert.data = (unsigned char *) daemon->https_mem_cert;
      cert.size = strlen (daemon->https_mem_cert);

      return gnutls_certificate_set_x509_key_mem (daemon->x509_cred, &cert,
                                                  &key, GNUTLS_X509_FMT_PEM);
    }
  else
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Failed to load certificate\n");
#endif
      return MHD_NO;
    }
}

/* initialize security aspects of the HTTPS daemon */
int
MHD_TLS_init (struct MHD_Daemon *daemon)
{
  int ret;

  switch (daemon->cred_type)
    {
    case MHD_GNUTLS_CRD_ANON:
      ret = gnutls_anon_allocate_server_credentials (&daemon->anon_cred);
      ret += gnutls_dh_params_init (&daemon->dh_params);
      if (ret != 0) {
		return GNUTLS_E_MEMORY_ERROR;
	  }
      gnutls_dh_params_generate2 (daemon->dh_params, 1024);
      gnutls_anon_set_server_dh_params (daemon->anon_cred, daemon->dh_params);
      break;
    case MHD_GNUTLS_CRD_CERTIFICATE:
      ret = gnutls_certificate_allocate_credentials (&daemon->x509_cred) ;
      if (ret != 0) {
		return GNUTLS_E_MEMORY_ERROR;
	  }
      if ((ret = MHD_init_daemon_certificate (daemon)) != 0)
        return ret;
    default:
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
                "Error: no daemon credentials type found. f: %s, l: %d\n",
                __FUNCTION__, __LINE__);
#endif
      break;
    }

  return MHD_NO;
}

inline static int
_set_priority (priority_st * st, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  st->num_algorithms = num;

  for (i = 0; i < num; i++)
    {
      st->priority[i] = list[i];
    }

  return 0;
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
  struct MHD_Connection *con_itr;
  int fd;

  if ((daemon == NULL) || (read_fd_set == NULL) || (write_fd_set == NULL)
      || (except_fd_set == NULL) || (max_fd == NULL) || (-1 == (fd = daemon->
                                                                socket_fd))
      || (daemon->shutdown == MHD_YES)
      || ((daemon->options & MHD_USE_THREAD_PER_CONNECTION) != 0))
    return MHD_NO;

  FD_SET (fd, read_fd_set);
  /* update max file descriptor */
  if ((*max_fd) < fd)
    *max_fd = fd;

  con_itr = daemon->connections;
  while (con_itr != NULL)
    {
      if (MHD_YES != MHD_connection_get_fdset (con_itr,
                                               read_fd_set,
                                               write_fd_set,
                                               except_fd_set, max_fd))
        return MHD_NO;
      con_itr = con_itr->next;
    }
#if DEBUG_CONNECT
  MHD_DLOG (daemon, "Maximum socket in select set: %d\n", *max_fd);
#endif
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
  unsigned int now;

  if (con == NULL)
    abort ();
  timeout = con->daemon->connection_timeout;
  while ((!con->daemon->shutdown) && (con->socket_fd != -1))
    {
      FD_ZERO (&rs);
      FD_ZERO (&ws);
      FD_ZERO (&es);
      max = 0;
      MHD_connection_get_fdset (con, &rs, &ws, &es, &max);
      now = time (NULL);
      tv.tv_usec = 0;
      if (timeout > (now - con->last_activity))
        tv.tv_sec = timeout - (now - con->last_activity);
      else
        tv.tv_sec = 0;
      num_ready = SELECT (max + 1,
                          &rs, &ws, &es, (timeout != 0) ? &tv : NULL);
      if (num_ready < 0)
        {
          if (errno == EINTR)
            continue;
#if HAVE_MESSAGES
          MHD_DLOG (con->daemon, "Error during select (%d): `%s'\n", max,
                    STRERROR (errno));
#endif
          break;
        }
      /* call appropriate connection handler if necessary */
      if (FD_ISSET (con->socket_fd, &rs))
        con->read_handler (con);
      if ((con->socket_fd != -1) && (FD_ISSET (con->socket_fd, &ws)))
        con->write_handler (con);
      if (con->socket_fd != -1)
        con->idle_handler (con);
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

#if 0
/* TODO rm if unused - gnutls parameter adapter , used to set gnutls pull function */
static long
gnutls_pull_param_adapter (void *connection, void *other, unsigned long i)
{
  ssize_t bytes;
  bytes = ((struct MHD_Connection *) connection)->read_buffer_offset;
  MHD_handle_connection (connection);
  bytes = ((struct MHD_Connection *) connection)->read_buffer_offset - bytes;
  return bytes;

}

static long
gnutls_push_param_adapter (void *connection,
                           const void *other, unsigned long i)
{
  ssize_t bytes;
  bytes = ((struct MHD_Connection *) connection)->write_buffer_send_offset;
  MHD_handle_connection (connection);
  bytes = ((struct MHD_Connection *) connection)->write_buffer_send_offset
    - bytes;
  return bytes;
}
#endif


/**
 * Handle an individual TLS connection.
 */
#if HTTPS_SUPPORT
static void *
MHD_TLS_init_connection (void *data)
{
  struct MHD_Connection *con = data;

  if (con == NULL)
    abort ();

  /* initialize connection state */
  con->state = MHD_TLS_CONNECTION_INIT;

  gnutls_init (&con->tls_session, GNUTLS_SERVER);

  /* sets cipher priorities */
  gnutls_priority_set (con->tls_session, con->daemon->priority_cache);

  switch (con->daemon->cred_type)
    {
      /* set needed credentials for certificate authentication. */
    case MHD_GNUTLS_CRD_CERTIFICATE:
      gnutls_credentials_set (con->tls_session, MHD_GNUTLS_CRD_CERTIFICATE,
                              con->daemon->x509_cred);
      break;
    case MHD_GNUTLS_CRD_ANON:
      /* set needed credentials for anonymous authentication. */
      gnutls_credentials_set (con->tls_session, MHD_GNUTLS_CRD_ANON,
                              con->daemon->anon_cred);
      gnutls_dh_set_prime_bits (con->tls_session, 1024);
      break;
    default:

#if HAVE_MESSAGES
      MHD_DLOG (con->daemon,
                "Error: couldn't init HTTPS session. no appropriate KX algorithm found. f: %s, l: %d\n",
                __FUNCTION__, __LINE__);
#endif
      break;
    }

  /* TODO avoid gnutls blocking recv / write calls
     gnutls_transport_set_pull_function(tls_session, &recv);
     gnutls_transport_set_push_function(tls_session, &send);
   */

  gnutls_transport_set_ptr (con->tls_session,
                            (gnutls_transport_ptr_t) ((void *) con->
                                                      socket_fd));

  return MHD_handle_connection (data);
}
#endif

/**
 * Accept an incoming connection and create the MHD_Connection object for
 * it.  This function also enforces policy by way of checking with the
 * accept policy callback.
 */
static int
MHD_accept_connection (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *pos;
  struct MHD_Connection *connection;
  struct sockaddr_in6 addr6;
  struct sockaddr *addr = (struct sockaddr *) &addr6;
  socklen_t addrlen;
  unsigned int have;
  int s, res_thread_create;
#if OSX
  static int on = 1;
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
          CLOSE (s);
          /* just in case */
        }
      return MHD_NO;
    }
#if DEBUG_CONNECT
  MHD_DLOG (daemon, "Accepted connection on socket %d\n", s);
#endif
  have = 0;
  if ((daemon->per_ip_connection_limit != 0) && (daemon->max_connections > 0))
    {
      pos = daemon->connections;
      while (pos != NULL)
        {
          if ((pos->addr != NULL) && (pos->addr_len == addrlen))
            {
              if (addrlen == sizeof (struct sockaddr_in))
                {
                  const struct sockaddr_in *a1 =
                    (const struct sockaddr_in *) &addr;
                  const struct sockaddr_in *a2 =
                    (const struct sockaddr_in *) pos->addr;
                  if (0 == memcmp (&a1->sin_addr, &a2->sin_addr,
                                   sizeof (struct in_addr)))
                    have++;
                }
              if (addrlen == sizeof (struct sockaddr_in6))
                {
                  const struct sockaddr_in6 *a1 =
                    (const struct sockaddr_in6 *) &addr;
                  const struct sockaddr_in6 *a2 =
                    (const struct sockaddr_in6 *) pos->addr;
                  if (0 == memcmp (&a1->sin6_addr, &a2->sin6_addr,
                                   sizeof (struct in6_addr)))
                    have++;
                }
            }
          pos = pos->next;
        }
    }

  if ((daemon->max_connections == 0) || ((daemon->per_ip_connection_limit
                                          != 0) && (daemon->
                                                    per_ip_connection_limit <=
                                                    have)))
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

  /* apply connection acceptance policy if present */
  if ((daemon->apc != NULL)
      && (MHD_NO == daemon->apc (daemon->apc_cls, addr, addrlen)))
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
  setsockopt (s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof (on));
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

  /* set default connection handlers  */
  MHD_set_http_calbacks (connection);

#if HTTPS_SUPPORT
  if (daemon->options & MHD_USE_SSL)
    {
      MHD_set_https_calbacks (connection);
    }
#endif

  /* attempt to create handler thread */
  if (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    {
#if HTTPS_SUPPORT
      if (daemon->options & MHD_USE_SSL)
        res_thread_create = pthread_create (&connection->pid, NULL,
                                            &MHD_TLS_init_connection,
                                            connection);
      else
#endif
        {
          res_thread_create = pthread_create (&connection->pid, NULL,
                                              &MHD_handle_connection,
                                              connection);
        }
      if (res_thread_create != 0)
        {
#if HAVE_MESSAGES
          MHD_DLOG (daemon, "Failed to create a thread: %s\n",
                    STRERROR (errno));
#endif
          SHUTDOWN (s, SHUT_RDWR);
          CLOSE (s);
          free (connection->addr);
          free (connection);
          return MHD_NO;
        }
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
 */
static void
MHD_cleanup_connections (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *pos;
  struct MHD_Connection *prev;
  void *unused;

  pos = daemon->connections;
  prev = NULL;
  while (pos != NULL)
    {
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
          MHD_destroy_response (pos->response);
          MHD_pool_destroy (pos->pool);
#if HTTPS_SUPPORT
          if (pos->tls_session != 0)
            {
              gnutls_deinit (pos->tls_session);
            }
#endif
          free (pos->addr);
          free (pos);
          daemon->max_connections++;
          if (prev == NULL)
            pos = daemon->connections;
          else
            pos = prev->next;
          continue;
        }
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

  num_ready = select (max + 1, &rs, &ws, &es, may_block == MHD_NO ? &timeout
                      : NULL);

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

  /* select connection thread handling type */
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
              /* TODO call con->read handler */
              if (FD_ISSET (ds, &rs))
                pos->read_handler (pos);
              if ((pos->socket_fd != -1) && (FD_ISSET (ds, &ws)))
                pos->write_handler (pos);
              if (pos->socket_fd != -1)
                pos->idle_handler (pos);
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
  if ((daemon->shutdown != MHD_NO) || (0 != (daemon->options
                                             & MHD_USE_THREAD_PER_CONNECTION))
      || (0 != (daemon->options & MHD_USE_SELECT_INTERNALLY)))
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
MHD_start_daemon_va (unsigned int options,
                     unsigned short port, char *ip,
                     MHD_AcceptPolicyCallback apc,
                     void *apc_cls,
                     MHD_AccessHandlerCallback dh, void *dh_cls, va_list ap)
{
  const int on = 1;
  struct MHD_Daemon *retVal;

  /* listeningss sockets used by the daemon */
  int socket_fd;

  struct sockaddr_in servaddr4;
  struct sockaddr_in6 servaddr6;
  const struct sockaddr *servaddr;
  socklen_t addrlen;
  enum MHD_OPTION opt;

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
                   &on, sizeof (on)) < 0) && (options & MHD_USE_DEBUG) != 0)
    {
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

  /* allocate the mhd daemon */

  retVal = malloc (sizeof (struct MHD_Daemon));

  if (retVal == NULL)
    {
      CLOSE (socket_fd);
      return NULL;
    }

  memset (retVal, 0, sizeof (struct MHD_Daemon));
  retVal->options = options;
  retVal->port = port;
  retVal->apc = apc;
  retVal->apc_cls = apc_cls;
  retVal->socket_fd = socket_fd;
  retVal->default_handler = dh;
  retVal->default_handler_cls = dh_cls;
  retVal->max_connections = MHD_MAX_CONNECTIONS_DEFAULT;
  retVal->pool_size = MHD_POOL_SIZE_DEFAULT;
  retVal->connection_timeout = 0;       /* no timeout */
#if HTTPS_SUPPORT
  if (options & MHD_USE_SSL)
    {
      /* lock gnutls_global mutex since it uses reference counting */
      pthread_mutex_lock (&gnutls_init_mutex);
      gnutls_global_init ();
      pthread_mutex_unlock (&gnutls_init_mutex);
      /* set default priorities */
      gnutls_priority_init (&retVal->priority_cache, "", NULL);
      retVal->cred_type = MHD_GNUTLS_CRD_CERTIFICATE;
    }
#endif
  /* initializes the argument pointer variable */

  /*
   * loop through daemon options
   */
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
        case MHD_OPTION_PER_IP_CONNECTION_LIMIT:
          retVal->per_ip_connection_limit = va_arg (ap, unsigned int);
          break;
#if HTTPS_SUPPORT
        case MHD_OPTION_PROTOCOL_VERSION:
          _set_priority (&retVal->priority_cache->protocol,
                         va_arg (ap, const int *));
          break;
        case MHD_OPTION_HTTPS_KEY_PATH:
          retVal->https_key_path = va_arg (ap, const char *);
          break;
        case MHD_OPTION_HTTPS_CERT_PATH:
          retVal->https_cert_path = va_arg (ap, const char *);
          break;
        case MHD_OPTION_HTTPS_MEM_KEY:
          retVal->https_mem_key = va_arg (ap, const char *);
          break;
        case MHD_OPTION_HTTPS_MEM_CERT:
          retVal->https_mem_cert = va_arg (ap, const char *);
          break;
        case MHD_OPTION_CRED_TYPE:
          retVal->cred_type = va_arg (ap, const int);
          break;
        case MHD_OPTION_KX_PRIORITY:
          _set_priority (&retVal->priority_cache->kx,
                         va_arg (ap, const int *));
          break;
        case MHD_OPTION_CIPHER_ALGORITHM:
          _set_priority (&retVal->priority_cache->cipher,
                         va_arg (ap, const int *));
          break;
        case MHD_OPTION_MAC_ALGO:
          _set_priority (&retVal->priority_cache->mac,
                         va_arg (ap, const int *));
          break;
#endif
        default:
#if HAVE_MESSAGES
          if (opt > MHD_HTTPS_OPTION_START && opt < MHD_HTTPS_OPTION_END)
            {
              fprintf (stderr,
                       "Error: HTTPS option %d passed to non HTTPS daemon\n",
                       opt);
            }
          else
            {
              fprintf (stderr,
                       "Invalid MHD_OPTION argument! (Did you terminate the list with MHD_OPTION_END?)\n");
            }
#endif
          abort ();
        }
    }

#if HTTPS_SUPPORT
  /* initialize HTTPS daemon certificate aspects & send / recv functions */
  if (options & MHD_USE_SSL && MHD_TLS_init (retVal) != 0)
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal, "Failed to initialize HTTPS daemon\n");
#endif
      free (retVal);
      return NULL;
    }
#endif

  if (((0 != (options & MHD_USE_THREAD_PER_CONNECTION)) || (0 != (options
                                                                  &
                                                                  MHD_USE_SELECT_INTERNALLY)))
      && (0 !=
          pthread_create (&retVal->pid, NULL, &MHD_select_thread, retVal)))
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal, "Failed to create listen thread: %s\n",
                STRERROR (errno));
#endif
      free (retVal);
      CLOSE (socket_fd);
      return NULL;
    }

  return retVal;
}

struct MHD_Daemon *
MHD_start_daemon (unsigned int options,
                  unsigned short port,
                  MHD_AcceptPolicyCallback apc,
                  void *apc_cls,
                  MHD_AccessHandlerCallback dh, void *dh_cls, ...)
{
  const int on = 1;
  struct MHD_Daemon *retVal;

  /* listeningss sockets used by the daemon */
  int socket_fd;
  va_list ap;

  struct sockaddr_in servaddr4;
  struct sockaddr_in6 servaddr6;
  const struct sockaddr *servaddr;
  socklen_t addrlen;
  enum MHD_OPTION opt;

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
                   &on, sizeof (on)) < 0) && (options & MHD_USE_DEBUG) != 0)
    {
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

  /* allocate the mhd daemon */

  retVal = malloc (sizeof (struct MHD_Daemon));

  if (retVal == NULL)
    {
      CLOSE (socket_fd);
      return NULL;
    }

  memset (retVal, 0, sizeof (struct MHD_Daemon));
  retVal->options = options;
  retVal->port = port;
  retVal->apc = apc;
  retVal->apc_cls = apc_cls;
  retVal->socket_fd = socket_fd;
  retVal->default_handler = dh;
  retVal->default_handler_cls = dh_cls;
  retVal->max_connections = MHD_MAX_CONNECTIONS_DEFAULT;
  retVal->pool_size = MHD_POOL_SIZE_DEFAULT;
  retVal->connection_timeout = 0;       /* no timeout */
#if HTTPS_SUPPORT
  if (options & MHD_USE_SSL)
    {
      /* lock gnutls_global mutex since it uses reference counting */
      pthread_mutex_lock (&gnutls_init_mutex);
      gnutls_global_init ();
      pthread_mutex_unlock (&gnutls_init_mutex);
      /* set default priorities */
      gnutls_priority_init (&retVal->priority_cache, "", NULL);
      retVal->cred_type = MHD_GNUTLS_CRD_CERTIFICATE;
    }
#endif
  /* initializes the argument pointer variable */

  va_start (ap, dh_cls);

  /*
   * loop through daemon options
   */
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
        case MHD_OPTION_PER_IP_CONNECTION_LIMIT:
          retVal->per_ip_connection_limit = va_arg (ap, unsigned int);
          break;
#if HTTPS_SUPPORT
        case MHD_OPTION_PROTOCOL_VERSION:
          _set_priority (&retVal->priority_cache->protocol,
                         va_arg (ap, const int *));
          break;
        case MHD_OPTION_HTTPS_KEY_PATH:
          retVal->https_key_path = va_arg (ap, const char *);
          break;
        case MHD_OPTION_HTTPS_CERT_PATH:
          retVal->https_cert_path = va_arg (ap, const char *);
          break;
        case MHD_OPTION_HTTPS_MEM_KEY:
          retVal->https_mem_key = va_arg (ap, const char *);
          break;
        case MHD_OPTION_HTTPS_MEM_CERT:
          retVal->https_mem_cert = va_arg (ap, const char *);
          break;
        case MHD_OPTION_CRED_TYPE:
          retVal->cred_type = va_arg (ap, const int);
          break;
        case MHD_OPTION_KX_PRIORITY:
          _set_priority (&retVal->priority_cache->kx,
                         va_arg (ap, const int *));
          break;
        case MHD_OPTION_CIPHER_ALGORITHM:
          _set_priority (&retVal->priority_cache->cipher,
                         va_arg (ap, const int *));
          break;
        case MHD_OPTION_MAC_ALGO:
          _set_priority (&retVal->priority_cache->mac,
                         va_arg (ap, const int *));
          break;
#endif
        default:
#if HAVE_MESSAGES
          if (opt > MHD_HTTPS_OPTION_START && opt < MHD_HTTPS_OPTION_END)
            {
              fprintf (stderr,
                       "Error: HTTPS option %d passed to non HTTPS daemon\n",
                       opt);
            }
          else
            {
              fprintf (stderr,
                       "Invalid MHD_OPTION argument! (Did you terminate the list with MHD_OPTION_END?)\n");
            }
#endif
          abort ();
        }
    }
  va_end (ap);

  /* initialize HTTPS daemon certificate aspects & send / recv functions */
  if (options & MHD_USE_SSL && MHD_TLS_init (retVal) != 0)
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal, "Failed to initialize HTTPS daemon\n");
#endif
      free (retVal);
      return NULL;
    }

  if (((0 != (options & MHD_USE_THREAD_PER_CONNECTION)) || (0 != (options
                                                                  &
                                                                  MHD_USE_SELECT_INTERNALLY)))
      && (0 !=
          pthread_create (&retVal->pid, NULL, &MHD_select_thread, retVal)))
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal, "Failed to create listen thread: %s\n",
                STRERROR (errno));
#endif
      free (retVal);
      CLOSE (socket_fd);
      return NULL;
    }

  return retVal;
}


/*
 * start the MHD_Daemon while binding to a specific ip address.
 *
 * TODO : address adding ip parameter to MHD_start_daemon
 */
struct MHD_Daemon *
MHD_start_daemon_ip (unsigned int options,
                     unsigned short port, char *ip,
                     MHD_AcceptPolicyCallback apc,
                     void *apc_cls,
                     MHD_AccessHandlerCallback dh, void *dh_cls, ...)
{

  gnutls_global_set_log_level (5);

  struct MHD_Daemon *ret;
  va_list ap;
  va_start (ap, dh_cls);
  ret = MHD_start_daemon_va (options, port, ip, apc, apc_cls, dh, dh_cls, ap);
  va_end (ap);
  return ret;
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
  if ((0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) || (0
                                                                   !=
                                                                   (daemon->
                                                                    options &
                                                                    MHD_USE_SELECT_INTERNALLY)))
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

  /* TLS clean up */
#if HTTPS_SUPPORT
  if (daemon->options & MHD_USE_SSL)
    {
      gnutls_priority_deinit (daemon->priority_cache);

      if (daemon->x509_cred)
        gnutls_certificate_free_credentials (daemon->x509_cred);
      if (daemon->anon_cred)
        gnutls_anon_free_server_credentials (daemon->anon_cred);

      /* lock gnutls_global mutex since it uses reference counting */
      pthread_mutex_lock (&gnutls_init_mutex);
      gnutls_global_deinit ();
      pthread_mutex_unlock (&gnutls_init_mutex);
    }
#endif

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
