/*
  This file is part of libmicrohttpd
  (C) 2007, 2008, 2009, 2010 Daniel Pittman and Christian Grothoff

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
#include "platform.h"
#include "internal.h"
#include "response.h"
#include "connection.h"
#include "memorypool.h"

#if HTTPS_SUPPORT
#include "connection_https.h"
#include <gnutls/gnutls.h>
#include <gcrypt.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef LINUX
#include <sys/sendfile.h>
#endif

/**
 * Default connection limit.
 */
#ifndef WINDOWS
#define MHD_MAX_CONNECTIONS_DEFAULT FD_SETSIZE -4
#else
#define MHD_MAX_CONNECTIONS_DEFAULT FD_SETSIZE
#endif

/**
 * Default memory allowed per connection.
 */
#define MHD_POOL_SIZE_DEFAULT (32 * 1024)

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

#ifndef LINUX
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#endif

#ifdef __SYMBIAN32__
static void pthread_kill (int, int) {
  // Symbian doesn't have signals. The user of the library is required to
  // run it in an external select loop.
  abort();
}
#endif  // __SYMBIAN32__

/**
 * Default implementation of the panic function
 */
static void 
mhd_panic_std(void *cls,
	      const char *file,
	      unsigned int line,
	      const char *reason)
{
  abort ();
}


/**
 * Handler for fatal errors.
 */
MHD_PanicCallback mhd_panic;

/**
 * Closure argument for "mhd_panic".
 */
void *mhd_panic_cls;


/**
 * Trace up to and return master daemon. If the supplied daemon
 * is a master, then return the daemon itself.
 *
 * @param daemon handle to a daemon 
 * @return master daemon handle
 */
static struct MHD_Daemon*
MHD_get_master (struct MHD_Daemon *daemon)
{
  while (NULL != daemon->master)
    daemon = daemon->master;
  return daemon;
}

/**
 * Maintain connection count for single address.
 */
struct MHD_IPCount
{
  /**
   * Address family. AF_INET or AF_INET6 for now.
   */
  int family;

  /**
   * Actual address.
   */
  union
  {
    /**
     * IPv4 address.
     */ 
    struct in_addr ipv4;
#if HAVE_IPV6
    /**
     * IPv6 address.
     */ 
    struct in6_addr ipv6;
#endif
  } addr;

  /**
   * Counter.
   */
  unsigned int count;
};

/**
 * Lock shared structure for IP connection counts
 *
 * @param daemon handle to daemon where lock is
 */
static void
MHD_ip_count_lock(struct MHD_Daemon *daemon)
{
  if (0 != pthread_mutex_lock(&daemon->per_ip_connection_mutex))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Failed to acquire IP connection limit mutex\n");
#endif
      abort();
    }
}

/**
 * Unlock shared structure for IP connection counts
 *
 * @param daemon handle to daemon where lock is
 */
static void
MHD_ip_count_unlock(struct MHD_Daemon *daemon)
{
  if (0 != pthread_mutex_unlock(&daemon->per_ip_connection_mutex))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Failed to release IP connection limit mutex\n");
#endif
      abort();
    }
}

/**
 * Tree comparison function for IP addresses (supplied to tsearch() family).
 * We compare everything in the struct up through the beginning of the
 * 'count' field.
 * 
 * @param a1 first address to compare
 * @param a2 second address to compare
 * @return -1, 0 or 1 depending on result of compare
 */
static int
MHD_ip_addr_compare(const void *a1, const void *a2)
{
  return memcmp (a1, a2, offsetof(struct MHD_IPCount, count));
}

/**
 * Parse address and initialize 'key' using the address.
 *
 * @param addr address to parse
 * @param addrlen number of bytes in addr
 * @param key where to store the parsed address
 * @return MHD_YES on success and MHD_NO otherwise (e.g., invalid address type)
 */
static int
MHD_ip_addr_to_key(const struct sockaddr *addr, socklen_t addrlen,
                   struct MHD_IPCount *key)
{
  memset(key, 0, sizeof(*key));

  /* IPv4 addresses */
  if (addrlen == sizeof(struct sockaddr_in))
    {
      const struct sockaddr_in *addr4 = (const struct sockaddr_in*)addr;
      key->family = AF_INET;
      memcpy (&key->addr.ipv4, &addr4->sin_addr, sizeof(addr4->sin_addr));
      return MHD_YES;
    }

#if HAVE_IPV6
  /* IPv6 addresses */
  if (addrlen == sizeof (struct sockaddr_in6))
    {
      const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6*)addr;
      key->family = AF_INET6;
      memcpy (&key->addr.ipv6, &addr6->sin6_addr, sizeof(addr6->sin6_addr));
      return MHD_YES;
    }
#endif

  /* Some other address */
  return MHD_NO;
}

/**
 * Check if IP address is over its limit.
 *
 * @param daemon handle to daemon where connection counts are tracked
 * @param addr address to add (or increment counter)
 * @param addrlen number of bytes in addr
 * @return Return MHD_YES if IP below limit, MHD_NO if IP has surpassed limit.
 *   Also returns MHD_NO if fails to allocate memory.
 */
static int
MHD_ip_limit_add(struct MHD_Daemon *daemon,
                 const struct sockaddr *addr,
		 socklen_t addrlen)
{
  struct MHD_IPCount *key;
  void *node;
  int result;

  daemon = MHD_get_master (daemon);

  /* Ignore if no connection limit assigned */
  if (daemon->per_ip_connection_limit == 0)
    return MHD_YES;

  key = malloc (sizeof(*key));
  if (NULL == key)
    return MHD_NO;

  /* Initialize key */
  if (MHD_NO == MHD_ip_addr_to_key (addr, addrlen, key))
    {
      /* Allow unhandled address types through */
      free (key);
      return MHD_YES;
    }

  MHD_ip_count_lock (daemon);

  /* Search for the IP address */
  node = (void*)TSEARCH (key, &daemon->per_ip_connection_count, MHD_ip_addr_compare);
  if (!node)
    {
#if HAVE_MESSAGES
      MHD_DLOG(daemon,
               "Failed to add IP connection count node\n");
#endif      
      MHD_ip_count_unlock (daemon);
      free (key);
      return MHD_NO;
    }
  node = *(void**)node;

  /* If we got an existing node back, free the one we created */
  if (node != key)
    free(key);
  key = (struct MHD_IPCount*)node;

  /* Test if there is room for another connection; if so,
   * increment count */
  result = (key->count < daemon->per_ip_connection_limit);
  if (result == MHD_YES)
    ++key->count;

  MHD_ip_count_unlock (daemon);
  return result;
}

/**
 * Decrement connection count for IP address, removing from table
 * count reaches 0
 *
 * @param daemon handle to daemon where connection counts are tracked
 * @param addr address to remove (or decrement counter)
 * @param addrlen number of bytes in addr
 */
static void
MHD_ip_limit_del(struct MHD_Daemon *daemon,
                 const struct sockaddr *addr,
		 socklen_t addrlen)
{
  struct MHD_IPCount search_key;
  struct MHD_IPCount *found_key;
  void *node;

  daemon = MHD_get_master (daemon);

  /* Ignore if no connection limit assigned */
  if (daemon->per_ip_connection_limit == 0)
    return;

  /* Initialize search key */
  if (MHD_NO == MHD_ip_addr_to_key (addr, addrlen, &search_key))
    return;

  MHD_ip_count_lock (daemon);

  /* Search for the IP address */
  node = (void*)TFIND (&search_key, &daemon->per_ip_connection_count, MHD_ip_addr_compare);

  /* Something's wrong if we couldn't find an IP address
   * that was previously added */
  if (!node)
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
                "Failed to find previously-added IP address\n");
#endif
      abort();
    }
  found_key = (struct MHD_IPCount*)*(void**)node;

  /* Validate existing count for IP address */
  if (found_key->count == 0)
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
                "Previously-added IP address had 0 count\n");
#endif
      abort();
    }

  /* Remove the node entirely if count reduces to 0 */
  if (--found_key->count == 0)
    {
      TDELETE (found_key, &daemon->per_ip_connection_count, MHD_ip_addr_compare);
      free (found_key);
    }

  MHD_ip_count_unlock (daemon);
}

#if HTTPS_SUPPORT
static pthread_mutex_t MHD_gnutls_init_mutex;

/**
 * Callback for receiving data from the socket.
 *
 * @param connection the MHD connection structure
 * @param other where to write received data to
 * @param i maximum size of other (in bytes)
 * @return number of bytes actually received
 */
static ssize_t
recv_tls_adapter (struct MHD_Connection *connection, void *other, size_t i)
{
  int res;
  res = gnutls_record_recv (connection->tls_session, other, i);
  if ( (res == GNUTLS_E_AGAIN) ||
       (res == GNUTLS_E_INTERRUPTED) )
    {
      errno = EINTR;
      return -1;
    }
  return res;
}


/**
 * Callback for writing data to the socket.
 *
 * @param connection the MHD connection structure
 * @param other data to write
 * @param i number of bytes to write
 * @return actual number of bytes written
 */
static ssize_t
send_tls_adapter (struct MHD_Connection *connection,
                  const void *other, size_t i)
{
  int res;
  res = gnutls_record_send (connection->tls_session, other, i);
  if ( (res == GNUTLS_E_AGAIN) ||
       (res == GNUTLS_E_INTERRUPTED) )
    {
      errno = EINTR;
      return -1;
    }
  return res;
}


/**
 * Read and setup our certificate and key.
 *
 * @param daemon handle to daemon to initialize
 * @return 0 on success
 */
static int
MHD_init_daemon_certificate (struct MHD_Daemon *daemon)
{
  gnutls_datum_t key;
  gnutls_datum_t cert;

  /* certificate & key loaded from memory */
  if (daemon->https_mem_cert && daemon->https_mem_key)
    {
      key.data = (unsigned char *) daemon->https_mem_key;
      key.size = strlen (daemon->https_mem_key);
      cert.data = (unsigned char *) daemon->https_mem_cert;
      cert.size = strlen (daemon->https_mem_cert);

      return gnutls_certificate_set_x509_key_mem (daemon->x509_cred,
						  &cert, &key,
						  GNUTLS_X509_FMT_PEM);
    }
#if HAVE_MESSAGES
  MHD_DLOG (daemon, "You need to specify a certificate and key location\n");
#endif
  return -1;
}

/**
 * Initialize security aspects of the HTTPS daemon
 *
 * @param daemon handle to daemon to initialize
 * @return 0 on success
 */
static int
MHD_TLS_init (struct MHD_Daemon *daemon)
{
  switch (daemon->cred_type)
    {
    case GNUTLS_CRD_CERTIFICATE:
      if (0 !=
          gnutls_certificate_allocate_credentials (&daemon->x509_cred))
        return GNUTLS_E_MEMORY_ERROR;
      return MHD_init_daemon_certificate (daemon);
    default:
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
                "Error: invalid credentials type %d specified.\n",
                daemon->cred_type);
#endif
      return -1;
    }
}
#endif

/**
 * Obtain the select sets for this daemon.
 *
 * @param daemon daemon to get sets from
 * @param read_fd_set read set
 * @param write_fd_set write set
 * @param except_fd_set except set
 * @param max_fd increased to largest FD added (if larger
 *               than existing value); can be NULL
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
      || (except_fd_set == NULL) || (max_fd == NULL)
      || (-1 == (fd = daemon->socket_fd)) || (daemon->shutdown == MHD_YES)
      || ((daemon->options & MHD_USE_THREAD_PER_CONNECTION) != 0)
      || ((daemon->options & MHD_USE_POLL) != 0))
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
 * connection when MHD_USE_THREAD_PER_CONNECTION is set.
 * 
 * @param data the 'struct MHD_Connection' this thread will handle
 * @return always NULL
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
#ifdef HAVE_POLL_H
  struct MHD_Pollfd mp;
  struct pollfd p;
#endif

  timeout = con->daemon->connection_timeout;
  while ((!con->daemon->shutdown) && (con->socket_fd != -1)) {
      tv.tv_usec = 0;
      if ( (timeout > (time (NULL) - con->last_activity)) ||
	   (timeout == 0) )
	{
	  /* in case we are missing the SIGALRM, keep going after
	     at most 1s; see http://lists.gnu.org/archive/html/libmicrohttpd/2009-10/msg00013.html */
	  tv.tv_sec = 1;
	  if ((con->state == MHD_CONNECTION_NORMAL_BODY_UNREADY) ||
	      (con->state == MHD_CONNECTION_CHUNKED_BODY_UNREADY))
	    {
	      /* do not block (we're waiting for our callback to succeed) */
	      tv.tv_sec = 0;
	    }
	}
      else
	{
	  tv.tv_sec = 0;
	}
#ifdef HAVE_POLL_H
      if (0 == (con->daemon->options & MHD_USE_POLL)) {
#else
      {
#endif
	/* use select */
        FD_ZERO (&rs);
        FD_ZERO (&ws);
        FD_ZERO (&es);
        max = 0;
        MHD_connection_get_fdset (con, &rs, &ws, &es, &max);
        num_ready = SELECT (max + 1, &rs, &ws, &es, &tv);
        if (num_ready < 0) {
            if (errno == EINTR)
              continue;
#if HAVE_MESSAGES
            MHD_DLOG (con->daemon, "Error during select (%d): `%s'\n", max,
                      STRERROR (errno));
#endif
            break;
        }
        /* call appropriate connection handler if necessary */
        if ((con->socket_fd != -1) && (FD_ISSET (con->socket_fd, &rs)))
          con->read_handler (con);
        if ((con->socket_fd != -1) && (FD_ISSET (con->socket_fd, &ws)))
          con->write_handler (con);
        if (con->socket_fd != -1)
          con->idle_handler (con);
      }
#ifdef HAVE_POLL_H
      else
      {
        /* use poll */
        memset(&mp, 0, sizeof (struct MHD_Pollfd));
        MHD_connection_get_pollfd(con, &mp);
	memset(&p, 0, sizeof (struct pollfd));
        p.fd = mp.fd;
        if (mp.events & MHD_POLL_ACTION_IN) 
          p.events |= POLLIN;        
        if (mp.events & MHD_POLL_ACTION_OUT) 
          p.events |= POLLOUT;
	/* in case we are missing the SIGALRM, keep going after
	   at most 1s */
	if (poll (&p, 1, 1000) < 0) {
          if (errno == EINTR)
            continue;
#if HAVE_MESSAGES
          MHD_DLOG (con->daemon, "Error during poll: `%s'\n", 
                    STRERROR (errno));
#endif
          break;
        }
        if ( (con->socket_fd != -1) && 
	     (0 != (p.revents & POLLIN)) ) 
          con->read_handler (con);        
        if ( (con->socket_fd != -1) && 
	     (0 != (p.revents & POLLOUT)) )
          con->write_handler (con);        
        if (con->socket_fd != -1)
          con->idle_handler (con);
	if ( (con->socket_fd != -1) &&
	     (0 != (p.revents & (POLLERR | POLLHUP))) )
          MHD_connection_close (con, MHD_REQUEST_TERMINATED_WITH_ERROR);      
      }
#endif
    }
  if (con->socket_fd != -1)
    {
#if DEBUG_CLOSE
#if HAVE_MESSAGES
      MHD_DLOG (con->daemon,
                "Processing thread terminating, closing connection\n");
#endif
#endif
      MHD_connection_close (con, MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN);
    }
  return NULL;
}

/**
 * Callback for receiving data from the socket.
 *
 * @param conn the MHD connection structure
 * @param other where to write received data to
 * @param i maximum size of other (in bytes)
 * @return number of bytes actually received
 */
static ssize_t
recv_param_adapter (struct MHD_Connection *connection, void *other, size_t i)
{
  if (connection->socket_fd == -1)
    return -1;
  if (0 != (connection->daemon->options & MHD_USE_SSL))
    return RECV (connection->socket_fd, other, i, MSG_NOSIGNAL);
  return RECV (connection->socket_fd, other, i, MSG_NOSIGNAL | MSG_DONTWAIT);
}

/**
 * Callback for writing data to the socket.
 *
 * @param conn the MHD connection structure
 * @param other data to write
 * @param i number of bytes to write
 * @return actual number of bytes written
 */
static ssize_t
send_param_adapter (struct MHD_Connection *connection,
                    const void *other, size_t i)
{
#if LINUX
  int fd;
  off_t offset;
  int ret;
#endif
  if (connection->socket_fd == -1)
    return -1;
  if (0 != (connection->daemon->options & MHD_USE_SSL))
    return SEND (connection->socket_fd, other, i, MSG_NOSIGNAL);
#if LINUX
  if ( (connection->write_buffer_append_offset ==
	connection->write_buffer_send_offset) &&
       (NULL != connection->response) &&
       (-1 != (fd = connection->response->fd)) )
    {
      /* can use sendfile */
      offset = (off_t) connection->response_write_position;
      ret = sendfile (connection->socket_fd, 
		      fd,
		      &offset,
		      connection->response->total_size - offset);
      if ( (ret == -1) &&
	   (errno == EINTR) )
	return 0;
      return ret;
    }
#endif
  return SEND (connection->socket_fd, other, i, MSG_NOSIGNAL | MSG_DONTWAIT);
}


#if HTTPS_SUPPORT
/**
 * Set if a socket should use non-blocking IO.
 * @param fd socket
 */
static void
socket_set_nonblocking (int fd)
{
#if MINGW
  u_long mode;
  mode = 1;
  if (ioctlsocket (fd, FIONBIO, &mode) == SOCKET_ERROR)
    {
      SetErrnoFromWinsockError (WSAGetLastError ());
#if HAVE_MESSAGES
      FPRINTF(stderr, "Failed to make socket non-blocking: %s\n", 
	      STRERROR (errno));
#endif
    }
#else

  /* not MINGW */
  int flags = fcntl (fd, F_GETFL);
  if ( (flags == -1) ||
       (0 != fcntl (fd, F_SETFL, flags | O_NONBLOCK)) )
    {
#if HAVE_MESSAGES
      FPRINTF(stderr, "Failed to make socket non-blocking: %s\n", 
	      STRERROR (errno));
#endif
    }
#endif
}
#endif


/**
 * Accept an incoming connection and create the MHD_Connection object for
 * it.  This function also enforces policy by way of checking with the
 * accept policy callback.
 * 
 * @param daemon handle with the listen socket
 * @return MHD_YES on success
 */
static int
MHD_accept_connection (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *connection;
#if HAVE_INET6
  struct sockaddr_in6 addrstorage;
#else
  struct sockaddr_in addrstorage;
#endif
  struct sockaddr *addr = (struct sockaddr *) &addrstorage;
  socklen_t addrlen;
  int s;
  int res_thread_create;
#if OSX
  static int on = 1;
#endif

  addrlen = sizeof (addrstorage);
  memset (addr, 0, sizeof (addrstorage));

  s = ACCEPT (daemon->socket_fd, addr, &addrlen);
  if ((s == -1) || (addrlen <= 0))
    {
#if HAVE_MESSAGES
      /* This could be a common occurance with multiple worker threads */
      if ((EAGAIN != errno) && (EWOULDBLOCK != errno))
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
#ifndef WINDOWS
  if ( (s >= FD_SETSIZE) &&
       (0 == (daemon->options & MHD_USE_POLL)) )
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Socket descriptor larger than FD_SETSIZE: %d > %d\n",
		s,
		FD_SETSIZE);
#endif
      CLOSE (s);
      return MHD_NO;
    }
#endif


#if HAVE_MESSAGES
#if DEBUG_CONNECT
  MHD_DLOG (daemon, "Accepted connection on socket %d\n", s);
#endif
#endif
  if ((daemon->max_connections == 0)
      || (MHD_ip_limit_add (daemon, addr, addrlen) == MHD_NO))
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
      MHD_ip_limit_del (daemon, addr, addrlen);
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
  if (NULL == connection)
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Error allocating memory: %s\n", STRERROR (errno));
#endif
      SHUTDOWN (s, SHUT_RDWR);
      CLOSE (s);
      MHD_ip_limit_del (daemon, addr, addrlen);
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
      MHD_ip_limit_del (daemon, addr, addrlen);
      free (connection);
      return MHD_NO;
    }
  memcpy (connection->addr, addr, addrlen);
  connection->addr_len = addrlen;
  connection->socket_fd = s;
  connection->daemon = daemon;
  connection->last_activity = time (NULL);

  /* set default connection handlers  */
  MHD_set_http_callbacks_ (connection);
  connection->recv_cls = &recv_param_adapter;
  connection->send_cls = &send_param_adapter;
#if HTTPS_SUPPORT
  if (0 != (daemon->options & MHD_USE_SSL))
    {
      connection->recv_cls = &recv_tls_adapter;
      connection->send_cls = &send_tls_adapter;
      connection->state = MHD_TLS_CONNECTION_INIT;
      MHD_set_https_callbacks (connection);
      gnutls_init (&connection->tls_session, GNUTLS_SERVER);
      gnutls_priority_set (connection->tls_session,
			   daemon->priority_cache);
      if (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
	{
	  /* use non-blocking IO for gnutls */
	  socket_set_nonblocking (connection->socket_fd);
	}
      switch (connection->daemon->cred_type)
        {
          /* set needed credentials for certificate authentication. */
        case GNUTLS_CRD_CERTIFICATE:
          gnutls_credentials_set (connection->tls_session,
				  GNUTLS_CRD_CERTIFICATE,
				  connection->daemon->x509_cred);
          break;
        default:
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Failed to setup TLS credentials: unknown credential type %d\n",
                    connection->daemon->cred_type);
#endif
          SHUTDOWN (s, SHUT_RDWR);
          CLOSE (s);
          MHD_ip_limit_del (daemon, addr, addrlen);
          free (connection->addr);
          free (connection);
          mhd_panic (mhd_panic_cls, __FILE__, __LINE__, 
#if HAVE_MESSAGES
		     "Unknown credential type"
#else
		     NULL
#endif
		     );
 	  return MHD_NO;
        }
      gnutls_transport_set_ptr (connection->tls_session,
				(gnutls_transport_ptr_t) connection);
      gnutls_transport_set_pull_function (connection->tls_session,
					  (gnutls_pull_func) &
                                               recv_param_adapter);
      gnutls_transport_set_push_function (connection->tls_session,
					  (gnutls_push_func) &
                                               send_param_adapter);
    }
#endif

  /* attempt to create handler thread */
  if (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    {
      res_thread_create = pthread_create (&connection->pid, NULL,
                                          &MHD_handle_connection, connection);
      if (res_thread_create != 0)
        {
#if HAVE_MESSAGES
          MHD_DLOG (daemon, "Failed to create a thread: %s\n",
                    STRERROR (res_thread_create));
#endif
          SHUTDOWN (s, SHUT_RDWR);
          CLOSE (s);
          MHD_ip_limit_del (daemon, addr, addrlen);
          free (connection->addr);
          free (connection);
          return MHD_NO;
        }
    }
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
 * @param daemon daemon to clean up
 */
static void
MHD_cleanup_connections (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *pos;
  struct MHD_Connection *prev;
  void *unused;
  int rc;

  pos = daemon->connections;
  prev = NULL;
  while (pos != NULL)
    {
      if ((pos->socket_fd == -1) ||
          (((0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
            (daemon->shutdown) && (pos->socket_fd != -1))))
        {
          if (prev == NULL)
            daemon->connections = pos->next;
          else
            prev->next = pos->next;
          if (0 != (pos->daemon->options & MHD_USE_THREAD_PER_CONNECTION))
            {
	      pthread_kill (pos->pid, SIGALRM);
              if (0 != (rc = pthread_join (pos->pid, &unused)))
		{
#if HAVE_MESSAGES
		  MHD_DLOG (daemon, "Failed to join a thread: %s\n",
			    STRERROR (rc));
#endif
		  abort();
		}
            }
          MHD_pool_destroy (pos->pool);
#if HTTPS_SUPPORT
          if (pos->tls_session != NULL)
            gnutls_deinit (pos->tls_session);
#endif
          MHD_ip_limit_del (daemon, (struct sockaddr*)pos->addr, pos->addr_len);
	  if (pos->response != NULL)
	    {
	      MHD_destroy_response (pos->response);
	      pos->response = NULL;
	    }
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
 * @param daemon daemon to query for timeout
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
#if HTTPS_SUPPORT
      if (  (0 != (daemon->options & MHD_USE_SSL)) &&
	    (0 != gnutls_record_check_pending (pos->tls_session)) )
	earliest_deadline = now;
#endif
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
 * @param daemon daemon to run select loop for
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

  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
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

      /* If we're at the connection limit, no need to
         accept new connections. */
      if ( (daemon->max_connections == 0) && (daemon->socket_fd != -1) )
        FD_CLR(daemon->socket_fd, &rs);
    }
  else
    {
      /* accept only, have one thread per connection */
      max = daemon->socket_fd;
      if (max == -1)
        return MHD_NO;
      FD_SET (max, &rs);
    }

  /* in case we are missing the SIGALRM, keep going after
     at most 1s; see http://lists.gnu.org/archive/html/libmicrohttpd/2009-10/msg00013.html */
  timeout.tv_usec = 0;
  timeout.tv_sec = 1;
  if (may_block == MHD_NO)
    {
      timeout.tv_usec = 0;
      timeout.tv_sec = 0;
    }
  else
    {
      /* ltimeout is in ms */
      if ( (MHD_YES == MHD_get_timeout (daemon, &ltimeout)) &&
	   (ltimeout < 1000) )
	{
          timeout.tv_usec = ltimeout * 1000;
          timeout.tv_sec = 0;
        }
    }
  num_ready = SELECT (max + 1, &rs, &ws, &es, &timeout);

  if (daemon->shutdown == MHD_YES)
    return MHD_NO;
  if (num_ready < 0)
    {
      if (errno == EINTR)
        return MHD_YES;
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "select failed: %s\n", STRERROR (errno));
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
 * Poll for new connection. Used only with THREAD_PER_CONNECTION
 *
 * @param daemon daemon to run poll loop for
 */
static int
MHD_poll (struct MHD_Daemon *daemon)
{
#ifdef HAVE_POLL_H
  struct pollfd p;

  if (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) 
    return MHD_NO;
  p.fd = daemon->socket_fd;
  p.events = POLLIN;
  p.revents = 0;

  if (poll(&p, 1, 1000) < 0) {
    if (errno == EINTR)
      return MHD_YES;
#if HAVE_MESSAGES
    MHD_DLOG (daemon, "poll failed: %s\n", STRERROR (errno));
#endif
    return MHD_NO;
  }
  /* handle shutdown cases */
  if (daemon->shutdown == MHD_YES) 
    return MHD_NO;  
  if (daemon->socket_fd < 0) 
    return MHD_YES; 
  if (0 != (p.revents & POLLIN)) 
    MHD_accept_connection (daemon);
  return MHD_YES;
#else
  return MHD_NO;
#endif
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
 *
 * @param cls 'struct MHD_Deamon' to run select loop in a thread for
 * @return always NULL (on shutdown)
 */
static void *
MHD_select_thread (void *cls)
{
  struct MHD_Daemon *daemon = cls;
  while (daemon->shutdown == MHD_NO)
    {
      if ((daemon->options & MHD_USE_POLL) == 0) 
	MHD_select (daemon, MHD_YES);
      else 
	MHD_poll(daemon);      
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
                  uint16_t port,
                  MHD_AcceptPolicyCallback apc,
                  void *apc_cls,
                  MHD_AccessHandlerCallback dh, void *dh_cls, ...)
{
  struct MHD_Daemon *ret;
  va_list ap;

  va_start (ap, dh_cls);
  ret = MHD_start_daemon_va (options, port, apc, apc_cls, dh, dh_cls, ap);
  va_end (ap);
  return ret;
}


typedef void (*VfprintfFunctionPointerType)(void *, const char *, va_list);


/**
 * Parse a list of options given as varargs.
 * 
 * @param daemon the daemon to initialize
 * @param servaddr where to store the server's listen address
 * @param ap the options
 * @return MHD_YES on success, MHD_NO on error
 */
static int
parse_options_va (struct MHD_Daemon *daemon,
		  const struct sockaddr **servaddr,
		  va_list ap);


/**
 * Parse a list of options given as varargs.
 * 
 * @param daemon the daemon to initialize
 * @param servaddr where to store the server's listen address
 * @param ... the options
 * @return MHD_YES on success, MHD_NO on error
 */
static int
parse_options (struct MHD_Daemon *daemon,
	       const struct sockaddr **servaddr,
	       ...)
{
  va_list ap;
  int ret;

  va_start (ap, servaddr);
  ret = parse_options_va (daemon, servaddr, ap);
  va_end (ap);
  return ret;
}


/**
 * Parse a list of options given as varargs.
 * 
 * @param daemon the daemon to initialize
 * @param servaddr where to store the server's listen address
 * @param ap the options
 * @return MHD_YES on success, MHD_NO on error
 */
static int
parse_options_va (struct MHD_Daemon *daemon,
		  const struct sockaddr **servaddr,
		  va_list ap)
{
  enum MHD_OPTION opt;
  struct MHD_OptionItem *oa;
  unsigned int i;
#if HTTPS_SUPPORT
  int ret;
  const char *pstr;
#endif
  
  while (MHD_OPTION_END != (opt = va_arg (ap, enum MHD_OPTION)))
    {
      switch (opt)
        {
        case MHD_OPTION_CONNECTION_MEMORY_LIMIT:
          daemon->pool_size = va_arg (ap, size_t);
          break;
        case MHD_OPTION_CONNECTION_LIMIT:
          daemon->max_connections = va_arg (ap, unsigned int);
          break;
        case MHD_OPTION_CONNECTION_TIMEOUT:
          daemon->connection_timeout = va_arg (ap, unsigned int);
          break;
        case MHD_OPTION_NOTIFY_COMPLETED:
          daemon->notify_completed =
            va_arg (ap, MHD_RequestCompletedCallback);
          daemon->notify_completed_cls = va_arg (ap, void *);
          break;
        case MHD_OPTION_PER_IP_CONNECTION_LIMIT:
          daemon->per_ip_connection_limit = va_arg (ap, unsigned int);
          break;
        case MHD_OPTION_SOCK_ADDR:
          *servaddr = va_arg (ap, const struct sockaddr *);
          break;
        case MHD_OPTION_URI_LOG_CALLBACK:
          daemon->uri_log_callback =
            va_arg (ap, LogCallback);
          daemon->uri_log_callback_cls = va_arg (ap, void *);
          break;
        case MHD_OPTION_THREAD_POOL_SIZE:
          daemon->worker_pool_size = va_arg (ap, unsigned int);
	  if (daemon->worker_pool_size >= SIZE_MAX / sizeof (struct MHD_Daemon))
	    {
#if HAVE_MESSAGES
	      FPRINTF (stderr,
		       "Specified thread pool size (%u) too big\n",
		       daemon->worker_pool_size);
#endif
	      return MHD_NO;
	    }
          break;
#if HTTPS_SUPPORT
        case MHD_OPTION_HTTPS_MEM_KEY:
	  if (0 != (daemon->options & MHD_USE_SSL))
	    daemon->https_mem_key = va_arg (ap, const char *);
#if HAVE_MESSAGES
	  else
	    FPRINTF (stderr,
		     "MHD HTTPS option %d passed to MHD but MHD_USE_SSL not set\n",
		     opt);	  
#endif
          break;
        case MHD_OPTION_HTTPS_MEM_CERT:
	  if (0 != (daemon->options & MHD_USE_SSL))
	    daemon->https_mem_cert = va_arg (ap, const char *);
#if HAVE_MESSAGES
	  else
	    FPRINTF (stderr,
		     "MHD HTTPS option %d passed to MHD but MHD_USE_SSL not set\n",
		     opt);	  
#endif
          break;
	case MHD_OPTION_HTTPS_CRED_TYPE:
	  daemon->cred_type = va_arg (ap, gnutls_credentials_type_t);
	  break;
        case MHD_OPTION_HTTPS_PRIORITIES:
	  ret = gnutls_priority_init (&daemon->priority_cache,
				      pstr = va_arg (ap, const char*),
				      NULL);
#if HAVE_MESSAGES
	  if (ret != GNUTLS_E_SUCCESS)
	    FPRINTF (stderr,
		     "Setting priorities to `%s' failed: %s\n",
		     pstr,
		     gnutls_strerror (ret));
#endif	  
	  if (ret != GNUTLS_E_SUCCESS)
	    return MHD_NO;
          break;
#endif
#ifdef DAUTH_SUPPORT
	case MHD_OPTION_DIGEST_AUTH_RANDOM:
	  daemon->digest_auth_rand_size = va_arg (ap, size_t);
	  daemon->digest_auth_random = va_arg (ap, const char *);
	  break;
	case MHD_OPTION_NONCE_NC_SIZE:
	  daemon->nonce_nc_size = va_arg (ap, unsigned int);
	  break;
#endif
	case MHD_OPTION_LISTEN_SOCKET:
	  daemon->socket_fd = va_arg (ap, int);	  
	  break;
        case MHD_OPTION_EXTERNAL_LOGGER:
#if HAVE_MESSAGES
          daemon->custom_error_log =
            va_arg (ap, VfprintfFunctionPointerType);
          daemon->custom_error_log_cls = va_arg (ap, void *);
#else
          va_arg (ap, VfprintfFunctionPointerType);
          va_arg (ap, void *);
#endif
          break;
	case MHD_OPTION_ARRAY:
	  oa = va_arg (ap, struct MHD_OptionItem*);
	  i = 0;
	  while (MHD_OPTION_END != (opt = oa[i].option))
	    {
	      switch (opt)
		{
		  /* all options taking 'size_t' */
		case MHD_OPTION_CONNECTION_MEMORY_LIMIT:
		  if (MHD_YES != parse_options (daemon,
						servaddr,
						opt,
						(size_t) oa[i].value,
						MHD_OPTION_END))
		    return MHD_NO;
		  break;
		  /* all options taking 'unsigned int' */
		case MHD_OPTION_NONCE_NC_SIZE:
		case MHD_OPTION_CONNECTION_LIMIT:
		case MHD_OPTION_CONNECTION_TIMEOUT:
		case MHD_OPTION_PER_IP_CONNECTION_LIMIT:
		case MHD_OPTION_THREAD_POOL_SIZE:
		  if (MHD_YES != parse_options (daemon,
						servaddr,
						opt,
						(unsigned int) oa[i].value,
						MHD_OPTION_END))
		    return MHD_NO;
		  break;
		  /* all options taking 'int' or 'enum' */
		case MHD_OPTION_HTTPS_CRED_TYPE:
		case MHD_OPTION_LISTEN_SOCKET:
		  if (MHD_YES != parse_options (daemon,
						servaddr,
						opt,
						(int) oa[i].value,
						MHD_OPTION_END))
		    return MHD_NO;
		  break;
		  /* all options taking one pointer */
		case MHD_OPTION_SOCK_ADDR:
		case MHD_OPTION_HTTPS_MEM_KEY:
		case MHD_OPTION_HTTPS_MEM_CERT:
		case MHD_OPTION_HTTPS_PRIORITIES:
		case MHD_OPTION_ARRAY:
		  if (MHD_YES != parse_options (daemon,
						servaddr,
						opt,
						oa[i].ptr_value,
						MHD_OPTION_END))
		    return MHD_NO;
		  break;
		  /* all options taking two pointers */
		case MHD_OPTION_NOTIFY_COMPLETED:
		case MHD_OPTION_URI_LOG_CALLBACK:
		case MHD_OPTION_EXTERNAL_LOGGER:
		case MHD_OPTION_UNESCAPE_CALLBACK:
		  if (MHD_YES != parse_options (daemon,
						servaddr,
						opt,
						(void *) oa[i].value,
						oa[i].ptr_value,
						MHD_OPTION_END))
		    return MHD_NO;
		  break;
		  /* options taking size_t-number followed by pointer */
		case MHD_OPTION_DIGEST_AUTH_RANDOM:
		  if (MHD_YES != parse_options (daemon,
						servaddr,
						opt,
						(size_t) oa[i].value,
						oa[i].ptr_value,
						MHD_OPTION_END))
		    return MHD_NO;		  
		default:
		  return MHD_NO;
		}
	      i++;
	    }
	  break;
        case MHD_OPTION_UNESCAPE_CALLBACK:
          daemon->unescape_callback =
            va_arg (ap, UnescapeCallback);
          daemon->unescape_callback_cls = va_arg (ap, void *);
          break;
        default:
#if HAVE_MESSAGES
          if ((opt >= MHD_OPTION_HTTPS_MEM_KEY) &&
              (opt <= MHD_OPTION_HTTPS_PRIORITIES))
            {
              FPRINTF (stderr,
                       "MHD HTTPS option %d passed to MHD compiled without HTTPS support\n",
                       opt);
            }
          else
            {
              FPRINTF (stderr,
                       "Invalid option %d! (Did you terminate the list with MHD_OPTION_END?)\n",
                       opt);
            }
#endif
	  return MHD_NO;
        }
    }  
  return MHD_YES;
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
                     uint16_t port,
                     MHD_AcceptPolicyCallback apc,
                     void *apc_cls,
                     MHD_AccessHandlerCallback dh, void *dh_cls,
		     va_list ap)
{
  const int on = 1;
  struct MHD_Daemon *retVal;
  int socket_fd;
  struct sockaddr_in servaddr4;
#if HAVE_INET6
  struct sockaddr_in6 servaddr6;
#endif
  const struct sockaddr *servaddr = NULL;
  socklen_t addrlen;
  unsigned int i;
  int res_thread_create;

  if ((port == 0) || (dh == NULL))
    return NULL;
  retVal = malloc (sizeof (struct MHD_Daemon));
  if (retVal == NULL)
    return NULL;
  memset (retVal, 0, sizeof (struct MHD_Daemon));
#if HTTPS_SUPPORT
  if (options & MHD_USE_SSL)
    {
      gnutls_priority_init (&retVal->priority_cache,
			    "NORMAL",
			    NULL);
    }
#endif
  retVal->socket_fd = -1;
  retVal->options = (enum MHD_OPTION)options;
  retVal->port = port;
  retVal->apc = apc;
  retVal->apc_cls = apc_cls;
  retVal->default_handler = dh;
  retVal->default_handler_cls = dh_cls;
  retVal->max_connections = MHD_MAX_CONNECTIONS_DEFAULT;
  retVal->pool_size = MHD_POOL_SIZE_DEFAULT;
  retVal->unescape_callback = &MHD_http_unescape;
  retVal->connection_timeout = 0;       /* no timeout */
#ifdef DAUTH_SUPPORT
  retVal->digest_auth_rand_size = 0;
  retVal->digest_auth_random = NULL;
  retVal->nonce_nc_size = 4; /* tiny */
#endif
#if HAVE_MESSAGES
  retVal->custom_error_log =
    (void (*)(void *, const char *, va_list)) &vfprintf;
  retVal->custom_error_log_cls = stderr;
#endif
#if HTTPS_SUPPORT
  if (options & MHD_USE_SSL)
    {
      /* lock MHD_gnutls_global mutex since it uses reference counting */
      if (0 != pthread_mutex_lock (&MHD_gnutls_init_mutex))
	{
#if HAVE_MESSAGES
	  MHD_DLOG (retVal, "Failed to aquire gnutls mutex\n");
#endif
          mhd_panic (mhd_panic_cls, __FILE__, __LINE__, NULL);
	}
      if (0 != pthread_mutex_unlock (&MHD_gnutls_init_mutex))
	{
#if HAVE_MESSAGES
	  MHD_DLOG (retVal, "Failed to release gnutls mutex\n");
#endif
	  mhd_panic (mhd_panic_cls, __FILE__, __LINE__, NULL);
	}
      retVal->cred_type = GNUTLS_CRD_CERTIFICATE;
    }
#endif

  if (MHD_YES != parse_options_va (retVal, &servaddr, ap))
    {
      free (retVal);
      return NULL;
    }

#ifdef DAUTH_SUPPORT
  if (retVal->nonce_nc_size > 0) 
    {
      if ( ( (size_t) (retVal->nonce_nc_size * sizeof(struct MHD_NonceNc))) / 
	   sizeof(struct MHD_NonceNc) != retVal->nonce_nc_size)
	{
#if HAVE_MESSAGES
	  MHD_DLOG (retVal,
		    "Specified value for NC_SIZE too large\n");
#endif
	  free (retVal);
	  return NULL;	  
	}
      retVal->nnc = malloc (retVal->nonce_nc_size * sizeof(struct MHD_NonceNc));
      if (NULL == retVal->nnc)
	    {
#if HAVE_MESSAGES
	      MHD_DLOG (retVal,
			"Failed to allocate memory for nonce-nc map: %s\n",
			STRERROR (errno));
#endif
	      free (retVal);
	      return NULL;
	    }
    }
  if (0 != pthread_mutex_init (&retVal->nnc_lock, NULL))
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal,
		"MHD failed to initialize nonce-nc mutex\n");
#endif
      free (retVal);
      return NULL;
    }
#endif

  /* poll support currently only works with MHD_USE_THREAD_PER_CONNECTION */
  if ( (0 != (options & MHD_USE_POLL)) && 
       (0 == (options & MHD_USE_THREAD_PER_CONNECTION)) ) 
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal,
		"MHD poll support only works with MHD_USE_THREAD_PER_CONNECTION\n");
#endif
      free (retVal);
      return NULL;
    }

  /* Thread pooling currently works only with internal select thread model */
  if ( (0 == (options & MHD_USE_SELECT_INTERNALLY)) && 
       (retVal->worker_pool_size > 0) )
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal,
		"MHD thread pooling only works with MHD_USE_SELECT_INTERNALLY\n");
#endif
      free (retVal);
      return NULL;
    }

#ifdef __SYMBIAN32__
  if (0 != (options & (MHD_USE_SELECT_INTERNALLY | MHD_USE_THREAD_PER_CONNECTION)))
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal,
		"Threaded operations are not supported on Symbian.\n");
#endif
      free (retVal);
      return NULL;
    }
#endif
  if (retVal->socket_fd == -1)
    {
      if ((options & MHD_USE_IPv6) != 0)
#if HAVE_INET6
	socket_fd = SOCKET (PF_INET6, SOCK_STREAM, 0);
#else
      {
#if HAVE_MESSAGES
	MHD_DLOG (retVal, 
		  "AF_INET6 not supported\n");
#endif
	free (retVal);
	return NULL;
      }
#endif
      else
	socket_fd = SOCKET (PF_INET, SOCK_STREAM, 0);
      if (socket_fd == -1)
	{
#if HAVE_MESSAGES
	  if ((options & MHD_USE_DEBUG) != 0)
	    MHD_DLOG (retVal, 
		      "Call to socket failed: %s\n", 
		      STRERROR (errno));
#endif
	  free (retVal);
	  return NULL;
	}
      if ((SETSOCKOPT (socket_fd,
		       SOL_SOCKET,
		       SO_REUSEADDR,
		       &on, sizeof (on)) < 0) && ((options & MHD_USE_DEBUG) != 0))
	{
#if HAVE_MESSAGES
	  MHD_DLOG (retVal, 
		    "setsockopt failed: %s\n", 
		    STRERROR (errno));
#endif
	}
      
      /* check for user supplied sockaddr */
#if HAVE_INET6
      if ((options & MHD_USE_IPv6) != 0)
	addrlen = sizeof (struct sockaddr_in6);
      else
#endif
	addrlen = sizeof (struct sockaddr_in);
      if (NULL == servaddr)
	{
#if HAVE_INET6
	  if ((options & MHD_USE_IPv6) != 0)
	    {
	      memset (&servaddr6, 0, sizeof (struct sockaddr_in6));
	      servaddr6.sin6_family = AF_INET6;
	      servaddr6.sin6_port = htons (port);
	      servaddr = (struct sockaddr *) &servaddr6;
	    }
	  else
#endif
	    {
	      memset (&servaddr4, 0, sizeof (struct sockaddr_in));
	      servaddr4.sin_family = AF_INET;
	      servaddr4.sin_port = htons (port);
	      servaddr = (struct sockaddr *) &servaddr4;
	    }
	}
      retVal->socket_fd = socket_fd;

      if ((options & MHD_USE_IPv6) != 0)
	{
#ifdef IPPROTO_IPV6
#ifdef IPV6_V6ONLY
	  /* Note: "IPV6_V6ONLY" is declared by Windows Vista ff., see "IPPROTO_IPV6 Socket Options" 
	     (http://msdn.microsoft.com/en-us/library/ms738574%28v=VS.85%29.aspx); 
	     and may also be missing on older POSIX systems; good luck if you have any of those,
	     your IPv6 socket may then also bind against IPv4... */
#ifndef WINDOWS
	  const int on = 1;
	  setsockopt (socket_fd, 
		      IPPROTO_IPV6, IPV6_V6ONLY, 
		      &on, sizeof (on));
#else
	  const char on = 1;
	  setsockopt (socket_fd, 
		      IPPROTO_IPV6, IPV6_V6ONLY, 
		      &on, sizeof (on));
#endif
#endif
#endif
	}
      if (BIND (socket_fd, servaddr, addrlen) == -1)
	{
#if HAVE_MESSAGES
	  if ((options & MHD_USE_DEBUG) != 0)
	    MHD_DLOG (retVal,
		      "Failed to bind to port %u: %s\n", 
		      (unsigned int) port, 
		      STRERROR (errno));
#endif
	  CLOSE (socket_fd);
	  free (retVal);
	  return NULL;
	}
      
      if (LISTEN (socket_fd, 20) < 0)
	{
#if HAVE_MESSAGES
	  if ((options & MHD_USE_DEBUG) != 0)
	    MHD_DLOG (retVal,
		      "Failed to listen for connections: %s\n", 
		      STRERROR (errno));
#endif
	  CLOSE (socket_fd);
	  free (retVal);
	  return NULL;
	}      
    }
  else
    {
      socket_fd = retVal->socket_fd;
    }
#ifndef WINDOWS
  if ( (socket_fd >= FD_SETSIZE) &&
       (0 == (options & MHD_USE_POLL)) )
    {
#if HAVE_MESSAGES
      if ((options & MHD_USE_DEBUG) != 0)
        MHD_DLOG (retVal,
		  "Socket descriptor larger than FD_SETSIZE: %d > %d\n",
		  socket_fd,
		  FD_SETSIZE);
#endif
      CLOSE (socket_fd);
      free (retVal);
      return NULL;
    }
#endif

  if (0 != pthread_mutex_init (&retVal->per_ip_connection_mutex, NULL))
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal,
               "MHD failed to initialize IP connection limit mutex\n");
#endif
      CLOSE (socket_fd);
      free (retVal);
      return NULL;
    }

#if HTTPS_SUPPORT
  /* initialize HTTPS daemon certificate aspects & send / recv functions */
  if ((0 != (options & MHD_USE_SSL)) && (0 != MHD_TLS_init (retVal)))
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal, 
		"Failed to initialize TLS support\n");
#endif
      CLOSE (socket_fd);
      pthread_mutex_destroy (&retVal->per_ip_connection_mutex);
      free (retVal);
      return NULL;
    }
#endif
  if ( ( (0 != (options & MHD_USE_THREAD_PER_CONNECTION)) ||
	 ( (0 != (options & MHD_USE_SELECT_INTERNALLY)) &&
	   (0 == retVal->worker_pool_size)) ) && 
       (0 != (res_thread_create =
	      pthread_create (&retVal->pid, NULL, &MHD_select_thread, retVal))))
    {
#if HAVE_MESSAGES
      MHD_DLOG (retVal,
                "Failed to create listen thread: %s\n", 
		STRERROR (res_thread_create));
#endif
      pthread_mutex_destroy (&retVal->per_ip_connection_mutex);
      free (retVal);
      CLOSE (socket_fd);
      return NULL;
    }
  if (retVal->worker_pool_size > 0)
    {
#ifndef MINGW
      int sk_flags;
#else
      unsigned long sk_flags;
#endif

      /* Coarse-grained count of connections per thread (note error
       * due to integer division). Also keep track of how many
       * connections are leftover after an equal split. */
      unsigned int conns_per_thread = retVal->max_connections
                                      / retVal->worker_pool_size;
      unsigned int leftover_conns = retVal->max_connections
                                    % retVal->worker_pool_size;

      i = 0; /* we need this in case fcntl or malloc fails */

      /* Accept must be non-blocking. Multiple children may wake up
       * to handle a new connection, but only one will win the race.
       * The others must immediately return. */
#ifndef MINGW
      sk_flags = fcntl (socket_fd, F_GETFL);
      if (sk_flags < 0)
        goto thread_failed;
      if (fcntl (socket_fd, F_SETFL, sk_flags | O_NONBLOCK) < 0)
        goto thread_failed;
#else
      sk_flags = 1;
#if HAVE_PLIBC_FD
      if (ioctlsocket (plibc_fd_get_handle (socket_fd), FIONBIO, &sk_flags) ==
          SOCKET_ERROR)
#else
      if (ioctlsocket (socket_fd, FIONBIO, &sk_flags) == SOCKET_ERROR)
#endif // PLIBC_FD
        goto thread_failed;
#endif // MINGW

      /* Allocate memory for pooled objects */
      retVal->worker_pool = malloc (sizeof (struct MHD_Daemon)
                                    * retVal->worker_pool_size);
      if (NULL == retVal->worker_pool)
        goto thread_failed;

      /* Start the workers in the pool */
      for (i = 0; i < retVal->worker_pool_size; ++i)
        {
          /* Create copy of the Daemon object for each worker */
          struct MHD_Daemon *d = &retVal->worker_pool[i];
          memcpy (d, retVal, sizeof (struct MHD_Daemon));

          /* Adjust pooling params for worker daemons; note that memcpy()
             has already copied MHD_USE_SELECT_INTERNALLY thread model into
             the worker threads. */
          d->master = retVal;
          d->worker_pool_size = 0;
          d->worker_pool = NULL;

          /* Divide available connections evenly amongst the threads.
           * Thread indexes in [0, leftover_conns) each get one of the
           * leftover connections. */
          d->max_connections = conns_per_thread;
          if (i < leftover_conns)
            ++d->max_connections;

          /* Spawn the worker thread */
          if (0 != (res_thread_create = pthread_create (&d->pid, NULL, &MHD_select_thread, d)))
            {
#if HAVE_MESSAGES
              MHD_DLOG (retVal,
                        "Failed to create pool thread: %s\n", 
			STRERROR (res_thread_create));
#endif
              /* Free memory for this worker; cleanup below handles
               * all previously-created workers. */
              goto thread_failed;
            }
        }
    }
  return retVal;

thread_failed:
  /* If no worker threads created, then shut down normally. Calling
     MHD_stop_daemon (as we do below) doesn't work here since it
     assumes a 0-sized thread pool means we had been in the default
     MHD_USE_SELECT_INTERNALLY mode. */
  if (i == 0)
    {
      CLOSE (socket_fd);
      pthread_mutex_destroy (&retVal->per_ip_connection_mutex);
      if (NULL != retVal->worker_pool)
        free (retVal->worker_pool);
      free (retVal);
      return NULL;
    }

  /* Shutdown worker threads we've already created. Pretend
     as though we had fully initialized our daemon, but
     with a smaller number of threads than had been
     requested. */
  retVal->worker_pool_size = i - 1;
  MHD_stop_daemon (retVal);
  return NULL;
}

/**
 * Close all connections for the daemon
 */
static void
MHD_close_connections (struct MHD_Daemon *daemon)
{
  while (daemon->connections != NULL)
    {
      if (-1 != daemon->connections->socket_fd)
        {
#if DEBUG_CLOSE
#if HAVE_MESSAGES
          MHD_DLOG (daemon, "MHD shutdown, closing active connections\n");
#endif
#endif
          MHD_connection_close (daemon->connections,
                                MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN);
        }
      MHD_cleanup_connections (daemon);
    }
}

/**
 * Shutdown an http daemon
 */
void
MHD_stop_daemon (struct MHD_Daemon *daemon)
{
  void *unused;
  int fd;
  unsigned int i;
  int rc;

  if (daemon == NULL)
    return;
  daemon->shutdown = MHD_YES;
  fd = daemon->socket_fd;
  daemon->socket_fd = -1;

  /* Prepare workers for shutdown */
  for (i = 0; i < daemon->worker_pool_size; ++i)
    {
      daemon->worker_pool[i].shutdown = MHD_YES;
      daemon->worker_pool[i].socket_fd = -1;
    }

#if OSX
  /* without this, either (thread pool = 0) threads would get stuck or
   * CLOSE would get stuck if attempted before (thread pool > 0)
   * threads have ended */
  SHUTDOWN (fd, SHUT_RDWR);
#else
#if DEBUG_CLOSE
#if HAVE_MESSAGES
  MHD_DLOG (daemon, "MHD shutdown, closing listen socket\n");
#endif
#endif
  CLOSE (fd);
#endif

  /* Signal workers to stop and clean them up */
  for (i = 0; i < daemon->worker_pool_size; ++i)
    pthread_kill (daemon->worker_pool[i].pid, SIGALRM);
  for (i = 0; i < daemon->worker_pool_size; ++i)
    {
      if (0 != (rc = pthread_join (daemon->worker_pool[i].pid, &unused)))
	{
#if HAVE_MESSAGES
	  MHD_DLOG (daemon, "Failed to join a thread: %s\n",
		    STRERROR (rc));
#endif
	  abort();
	}
      MHD_close_connections (&daemon->worker_pool[i]);
    }
  free (daemon->worker_pool);

  if ((0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) ||
      ((0 != (daemon->options & MHD_USE_SELECT_INTERNALLY))
        && (0 == daemon->worker_pool_size)))
    {
      pthread_kill (daemon->pid, SIGALRM);
      if (0 != (rc = pthread_join (daemon->pid, &unused)))
	{
#if HAVE_MESSAGES
	  MHD_DLOG (daemon, "Failed to join a thread: %s\n",
		    STRERROR (rc));
#endif
	  abort();
	}
    }
  MHD_close_connections (daemon);

#if OSX
#if DEBUG_CLOSE
#if HAVE_MESSAGES
  MHD_DLOG (daemon, "MHD shutdown, closing listen socket\n");
#endif
#endif
  CLOSE (fd);
#endif

  /* TLS clean up */
#if HTTPS_SUPPORT
  if (daemon->options & MHD_USE_SSL)
    {
      gnutls_priority_deinit (daemon->priority_cache);
      if (daemon->x509_cred)
        gnutls_certificate_free_credentials (daemon->x509_cred);
      /* lock MHD_gnutls_global mutex since it uses reference counting */
      if (0 != pthread_mutex_lock (&MHD_gnutls_init_mutex))
	{
#if HAVE_MESSAGES
	  MHD_DLOG (daemon, "Failed to aquire gnutls mutex\n");
#endif
	  abort();
	}
      if (0 != pthread_mutex_unlock (&MHD_gnutls_init_mutex))
	{
#if HAVE_MESSAGES
	  MHD_DLOG (daemon, "Failed to release gnutls mutex\n");
#endif
	  abort();
	}
    }
#endif

#ifdef DAUTH_SUPPORT
  free (daemon->nnc);
  pthread_mutex_destroy (&daemon->nnc_lock);
#endif
  pthread_mutex_destroy (&daemon->per_ip_connection_mutex);
  free (daemon);
}

/**
 * Obtain information about the given daemon
 * (not fully implemented!).
 *
 * @param daemon what daemon to get information about
 * @param infoType what information is desired?
 * @param ... depends on infoType
 * @return NULL if this information is not available
 *         (or if the infoType is unknown)
 */
const union MHD_DaemonInfo *
MHD_get_daemon_info (struct MHD_Daemon *daemon,
                     enum MHD_DaemonInfoType infoType, ...)
{
  switch (infoType)
    {
    case MHD_DAEMON_INFO_LISTEN_FD:
      return (const union MHD_DaemonInfo *) &daemon->socket_fd;
   default:
      return NULL;
    };
}

/**
 * Sets the global error handler to a different implementation.  "cb"
 * will only be called in the case of typically fatal, serious
 * internal consistency issues.  These issues should only arise in the
 * case of serious memory corruption or similar problems with the
 * architecture.  While "cb" is allowed to return and MHD will then
 * try to continue, this is never safe.
 *
 * The default implementation that is used if no panic function is set
 * simply calls "abort".  Alternative implementations might call
 * "exit" or other similar functions.
 *
 * @param cb new error handler
 * @param cls passed to error handler
 */
void MHD_set_panic_func (MHD_PanicCallback cb, void *cls)
{
  mhd_panic = cb;
  mhd_panic_cls = cls;
}

/**
 * Obtain the version of this library
 *
 * @return static version string, e.g. "0.4.1"
 */
const char *
MHD_get_version (void)
{
  return PACKAGE_VERSION;
}

#ifndef WINDOWS

static struct sigaction sig;

static struct sigaction old;

static void
sigalrmHandler (int sig)
{
}
#endif

#ifdef __GNUC__
#define ATTRIBUTE_CONSTRUCTOR __attribute__ ((constructor))
#define ATTRIBUTE_DESTRUCTOR __attribute__ ((destructor))
#else  // !__GNUC__
#define ATTRIBUTE_CONSTRUCTOR
#define ATTRIBUTE_DESTRUCTOR
#endif  // __GNUC__

#if HTTPS_SUPPORT
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

/**
 * Initialize the signal handler for SIGALRM
 * and do other setup work.
 */
void ATTRIBUTE_CONSTRUCTOR MHD_init ()
{
  mhd_panic = &mhd_panic_std;
  mhd_panic_cls = NULL;

#ifndef WINDOWS
  /* make sure SIGALRM does not kill us */
  memset (&sig, 0, sizeof (struct sigaction));
  memset (&old, 0, sizeof (struct sigaction));
  sig.sa_flags = SA_NODEFER;
  sig.sa_handler = &sigalrmHandler;
  sigaction (SIGALRM, &sig, &old);
#else
  plibc_init ("GNU", "libmicrohttpd");
#endif
#if HTTPS_SUPPORT
  gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  gnutls_global_init ();
  if (0 != pthread_mutex_init(&MHD_gnutls_init_mutex, NULL))
    abort();
#endif
}

void ATTRIBUTE_DESTRUCTOR MHD_fini ()
{
#if HTTPS_SUPPORT
  gnutls_global_deinit ();
  if (0 != pthread_mutex_destroy(&MHD_gnutls_init_mutex))
    mhd_panic (mhd_panic_cls, __FILE__, __LINE__, NULL);
#endif
#ifndef WINDOWS
  sigaction (SIGALRM, &old, &sig);
#else
  plibc_shutdown ();
#endif
}

/* end of daemon.c */
