/*
  This file is part of libmicrohttpd
  (C) 2007-2013 Daniel Pittman and Christian Grothoff

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
 * @file microhttpd/daemon.c
 * @brief  A minimal-HTTP server library
 * @author Daniel Pittman
 * @author Christian Grothoff
 */
#include "platform.h"
#include "internal.h"
#include "response.h"
#include "connection.h"
#include "memorypool.h"
#include <limits.h>

#if HAVE_SEARCH_H
#include <search.h>
#else
#include "tsearch.h"
#endif

#if HTTPS_SUPPORT
#include "connection_https.h"
#include <gcrypt.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef LINUX
#include <sys/sendfile.h>
#endif

#ifndef HAVE_ACCEPT4
#define HAVE_ACCEPT4 0
#endif

/**
 * Default connection limit.
 */
#ifndef WINDOWS
#define MHD_MAX_CONNECTIONS_DEFAULT FD_SETSIZE - 4
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
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#ifndef EPOLL_CLOEXEC
#define EPOLL_CLOEXEC 0
#endif


/**
 * Default implementation of the panic function,
 * prints an error message and aborts.
 *
 * @param cls unused
 * @param file name of the file with the problem
 * @param line line number with the problem
 * @param reason error message with details
 */
static void
mhd_panic_std (void *cls,
	       const char *file,
	       unsigned int line,
	       const char *reason)
{
#if HAVE_MESSAGES
  fprintf (stderr, "Fatal error in GNU libmicrohttpd %s:%u: %s\n",
	   file, line, reason);
#endif
  abort ();
}


/**
 * Handler for fatal errors.
 */
HIDDEN_SYMBOL
MHD_PanicCallback mhd_panic;

/**
 * Closure argument for "mhd_panic".
 */
HIDDEN_SYMBOL
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
 * Lock shared structure for IP connection counts and connection DLLs.
 *
 * @param daemon handle to daemon where lock is
 */
static void
MHD_ip_count_lock (struct MHD_Daemon *daemon)
{
  if (0 != pthread_mutex_lock(&daemon->per_ip_connection_mutex))
    {
      MHD_PANIC ("Failed to acquire IP connection limit mutex\n");
    }
}


/**
 * Unlock shared structure for IP connection counts and connection DLLs.
 *
 * @param daemon handle to daemon where lock is
 */
static void
MHD_ip_count_unlock (struct MHD_Daemon *daemon)
{
  if (0 != pthread_mutex_unlock(&daemon->per_ip_connection_mutex))
    {
      MHD_PANIC ("Failed to release IP connection limit mutex\n");
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
MHD_ip_addr_compare (const void *a1, const void *a2)
{
  return memcmp (a1, a2, offsetof (struct MHD_IPCount, count));
}


/**
 * Parse address and initialize 'key' using the address.
 *
 * @param addr address to parse
 * @param addrlen number of bytes in addr
 * @param key where to store the parsed address
 * @return #MHD_YES on success and #MHD_NO otherwise (e.g., invalid address type)
 */
static int
MHD_ip_addr_to_key (const struct sockaddr *addr,
		    socklen_t addrlen,
		    struct MHD_IPCount *key)
{
  memset(key, 0, sizeof(*key));

  /* IPv4 addresses */
  if (sizeof (struct sockaddr_in) == addrlen)
    {
      const struct sockaddr_in *addr4 = (const struct sockaddr_in*) addr;
      key->family = AF_INET;
      memcpy (&key->addr.ipv4, &addr4->sin_addr, sizeof(addr4->sin_addr));
      return MHD_YES;
    }

#if HAVE_IPV6
  /* IPv6 addresses */
  if (sizeof (struct sockaddr_in6) == addrlen)
    {
      const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6*) addr;
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
 * @return Return #MHD_YES if IP below limit, #MHD_NO if IP has surpassed limit.
 *   Also returns #MHD_NO if fails to allocate memory.
 */
static int
MHD_ip_limit_add (struct MHD_Daemon *daemon,
		  const struct sockaddr *addr,
		  socklen_t addrlen)
{
  struct MHD_IPCount *key;
  void **nodep;
  void *node;
  int result;

  daemon = MHD_get_master (daemon);
  /* Ignore if no connection limit assigned */
  if (0 == daemon->per_ip_connection_limit)
    return MHD_YES;

  if (NULL == (key = malloc (sizeof(*key))))
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
  if (NULL == (nodep = TSEARCH (key,
				&daemon->per_ip_connection_count,
				&MHD_ip_addr_compare)))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Failed to add IP connection count node\n");
#endif
      MHD_ip_count_unlock (daemon);
      free (key);
      return MHD_NO;
    }
  node = *nodep;
  /* If we got an existing node back, free the one we created */
  if (node != key)
    free(key);
  key = (struct MHD_IPCount *) node;
  /* Test if there is room for another connection; if so,
   * increment count */
  result = (key->count < daemon->per_ip_connection_limit);
  if (MHD_YES == result)
    ++key->count;

  MHD_ip_count_unlock (daemon);
  return result;
}


/**
 * Decrement connection count for IP address, removing from table
 * count reaches 0.
 *
 * @param daemon handle to daemon where connection counts are tracked
 * @param addr address to remove (or decrement counter)
 * @param addrlen number of bytes in @a addr
 */
static void
MHD_ip_limit_del (struct MHD_Daemon *daemon,
		  const struct sockaddr *addr,
		  socklen_t addrlen)
{
  struct MHD_IPCount search_key;
  struct MHD_IPCount *found_key;
  void **nodep;

  daemon = MHD_get_master (daemon);
  /* Ignore if no connection limit assigned */
  if (0 == daemon->per_ip_connection_limit)
    return;
  /* Initialize search key */
  if (MHD_NO == MHD_ip_addr_to_key (addr, addrlen, &search_key))
    return;

  MHD_ip_count_lock (daemon);

  /* Search for the IP address */
  if (NULL == (nodep = TFIND (&search_key,
			      &daemon->per_ip_connection_count,
			      &MHD_ip_addr_compare)))
    {
      /* Something's wrong if we couldn't find an IP address
       * that was previously added */
      MHD_PANIC ("Failed to find previously-added IP address\n");
    }
  found_key = (struct MHD_IPCount *) *nodep;
  /* Validate existing count for IP address */
  if (0 == found_key->count)
    {
      MHD_PANIC ("Previously-added IP address had 0 count\n");
    }
  /* Remove the node entirely if count reduces to 0 */
  if (0 == --found_key->count)
    {
      TDELETE (found_key,
	       &daemon->per_ip_connection_count,
	       &MHD_ip_addr_compare);
      free (found_key);
    }

  MHD_ip_count_unlock (daemon);
}


#if HTTPS_SUPPORT
/**
 * Callback for receiving data from the socket.
 *
 * @param connection the MHD_Connection structure
 * @param other where to write received data to
 * @param i maximum size of other (in bytes)
 * @return number of bytes actually received
 */
static ssize_t
recv_tls_adapter (struct MHD_Connection *connection, void *other, size_t i)
{
  int res;

  if (MHD_YES == connection->tls_read_ready)
    {
      connection->daemon->num_tls_read_ready--;
      connection->tls_read_ready = MHD_NO;
    }
  res = gnutls_record_recv (connection->tls_session, other, i);
  if ( (GNUTLS_E_AGAIN == res) ||
       (GNUTLS_E_INTERRUPTED == res) )
    {
      errno = EINTR;
#if EPOLL_SUPPORT
      connection->epoll_state &= ~MHD_EPOLL_STATE_READ_READY;
#endif
      return -1;
    }
  if (res < 0)
    {
      /* Likely 'GNUTLS_E_INVALID_SESSION' (client communication
	 disrupted); set errno to something caller will interpret
	 correctly as a hard error */
      errno = EPIPE;
      return res;
    }
  if (res == i)
    {
      connection->tls_read_ready = MHD_YES;
      connection->daemon->num_tls_read_ready++;
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
  if ( (GNUTLS_E_AGAIN == res) ||
       (GNUTLS_E_INTERRUPTED == res) )
    {
      errno = EINTR;
#if EPOLL_SUPPORT
      connection->epoll_state &= ~MHD_EPOLL_STATE_WRITE_READY;
#endif
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

#if GNUTLS_VERSION_MAJOR >= 3
  if (NULL != daemon->cert_callback)
    {
      gnutls_certificate_set_retrieve_function2 (daemon->x509_cred,
                                                 daemon->cert_callback);
    }
#endif
  if (NULL != daemon->https_mem_trust)
    {
      cert.data = (unsigned char *) daemon->https_mem_trust;
      cert.size = strlen (daemon->https_mem_trust);
      if (gnutls_certificate_set_x509_trust_mem (daemon->x509_cred, &cert,
						 GNUTLS_X509_FMT_PEM) < 0)
	{
#if HAVE_MESSAGES
	  MHD_DLOG(daemon,
		   "Bad trust certificate format\n");
#endif
	  return -1;
	}
    }

  /* certificate & key loaded from memory */
  if ( (NULL != daemon->https_mem_cert) &&
       (NULL != daemon->https_mem_key) )
    {
      key.data = (unsigned char *) daemon->https_mem_key;
      key.size = strlen (daemon->https_mem_key);
      cert.data = (unsigned char *) daemon->https_mem_cert;
      cert.size = strlen (daemon->https_mem_cert);

      return gnutls_certificate_set_x509_key_mem (daemon->x509_cred,
						  &cert, &key,
						  GNUTLS_X509_FMT_PEM);
    }
#if GNUTLS_VERSION_MAJOR >= 3
  if (NULL != daemon->cert_callback)
    return 0;
#endif
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
 * Add @a fd to the @a set.  If @a fd is
 * greater than @a max_fd, set @a max_fd to @a fd.
 *
 * @param fd file descriptor to add to the @a set
 * @param set set to modify
 * @param max_fd maximum value to potentially update
 */
static void
add_to_fd_set (int fd,
	       fd_set *set,
	       int *max_fd)
{
  FD_SET (fd, set);
  if ( (NULL != max_fd) &&
       (fd > *max_fd) )
    *max_fd = fd;
}


/**
 * Obtain the `select()` sets for this daemon.
 *
 * @param daemon daemon to get sets from
 * @param read_fd_set read set
 * @param write_fd_set write set
 * @param except_fd_set except set
 * @param max_fd increased to largest FD added (if larger
 *               than existing value); can be NULL
 * @return #MHD_YES on success, #MHD_NO if this
 *         daemon was not started with the right
 *         options for this call.
 * @ingroup event
 */
int
MHD_get_fdset (struct MHD_Daemon *daemon,
               fd_set *read_fd_set,
               fd_set *write_fd_set,
	       fd_set *except_fd_set,
	       int *max_fd)
{
  struct MHD_Connection *pos;
  int fd;

  if ( (NULL == daemon)
       || (NULL == read_fd_set)
       || (NULL == write_fd_set)
       || (NULL == except_fd_set)
       || (NULL == max_fd)
       || (MHD_YES == daemon->shutdown)
       || (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
       || (0 != (daemon->options & MHD_USE_POLL)))
    return MHD_NO;
#if EPOLL_SUPPORT
  if (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY))
    {
      /* we're in epoll mode, use the epoll FD as a stand-in for
	 the entire event set */

      if (daemon->epoll_fd >= FD_SETSIZE)
	return MHD_NO; /* poll fd too big, fail hard */
      FD_SET (daemon->epoll_fd, read_fd_set);
      if ((*max_fd) < daemon->epoll_fd)
	*max_fd = daemon->epoll_fd;
      return MHD_YES;
    }
#endif
  fd = daemon->socket_fd;
  if (-1 != fd)
  {
    FD_SET (fd, read_fd_set);
    /* update max file descriptor */
    if ((*max_fd) < fd)
      *max_fd = fd;
  }
  for (pos = daemon->connections_head; NULL != pos; pos = pos->next)
    {
      switch (pos->event_loop_info)
	{
	case MHD_EVENT_LOOP_INFO_READ:
	  add_to_fd_set (pos->socket_fd, read_fd_set, max_fd);
	  break;
	case MHD_EVENT_LOOP_INFO_WRITE:
	  add_to_fd_set (pos->socket_fd, write_fd_set, max_fd);
	  if (pos->read_buffer_size > pos->read_buffer_offset)
	    add_to_fd_set (pos->socket_fd, read_fd_set, max_fd);
	  break;
	case MHD_EVENT_LOOP_INFO_BLOCK:
	  if (pos->read_buffer_size > pos->read_buffer_offset)
	    add_to_fd_set (pos->socket_fd, read_fd_set, max_fd);
	  break;
	case MHD_EVENT_LOOP_INFO_CLEANUP:
	  /* this should never happen */
	  break;
	}
    }
#if DEBUG_CONNECT
#if HAVE_MESSAGES
  MHD_DLOG (daemon, "Maximum socket in select set: %d\n", *max_fd);
#endif
#endif
  return MHD_YES;
}


/**
 * Main function of the thread that handles an individual
 * connection when #MHD_USE_THREAD_PER_CONNECTION is set.
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
  int max;
  struct timeval tv;
  struct timeval *tvp;
  unsigned int timeout;
  time_t now;
#ifdef HAVE_POLL_H
  struct pollfd p[1];
#endif

  timeout = con->daemon->connection_timeout;
  while ( (MHD_YES != con->daemon->shutdown) &&
	  (MHD_CONNECTION_CLOSED != con->state) )
    {
      tvp = NULL;
      if (timeout > 0)
	{
	  now = MHD_monotonic_time();
	  if (now - con->last_activity > timeout)
	    tv.tv_sec = 0;
	  else
	    tv.tv_sec = timeout - (now - con->last_activity);
	  tv.tv_usec = 0;
	  tvp = &tv;
	}
#if HTTPS_SUPPORT
      if (MHD_YES == con->tls_read_ready)
	{
	  /* do not block (more data may be inside of TLS buffers waiting for us) */
	  tv.tv_sec = 0;
	  tv.tv_usec = 0;
	  tvp = &tv;
	}
#endif
      if (0 == (con->daemon->options & MHD_USE_POLL))
	{
	  /* use select */
	  FD_ZERO (&rs);
	  FD_ZERO (&ws);
	  max = 0;
	  switch (con->event_loop_info)
	    {
	    case MHD_EVENT_LOOP_INFO_READ:
	      add_to_fd_set (con->socket_fd, &rs, &max);
	      break;
	    case MHD_EVENT_LOOP_INFO_WRITE:
	      add_to_fd_set (con->socket_fd, &ws, &max);
	      if (con->read_buffer_size > con->read_buffer_offset)
		add_to_fd_set (con->socket_fd, &rs, &max);
	      break;
	    case MHD_EVENT_LOOP_INFO_BLOCK:
	      if (con->read_buffer_size > con->read_buffer_offset)
		add_to_fd_set (con->socket_fd, &rs, &max);
	      tv.tv_sec = 0;
	      tv.tv_usec = 0;
	      tvp = &tv;
	      break;
	    case MHD_EVENT_LOOP_INFO_CLEANUP:
	      /* how did we get here!? */
	      goto exit;
	    }
	  num_ready = SELECT (max + 1, &rs, &ws, NULL, tvp);
	  if (num_ready < 0)
	    {
	      if (EINTR == errno)
		continue;
#if HAVE_MESSAGES
	      MHD_DLOG (con->daemon,
			"Error during select (%d): `%s'\n",
			max,
			STRERROR (errno));
#endif
	      break;
	    }
	  /* call appropriate connection handler if necessary */
	  if ( (FD_ISSET (con->socket_fd, &rs))
#if HTTPS_SUPPORT
	       || (MHD_YES == con->tls_read_ready)
#endif
	       )
	    con->read_handler (con);
	  if (FD_ISSET (con->socket_fd, &ws))
	    con->write_handler (con);
	  if (MHD_NO == con->idle_handler (con))
	    goto exit;
	}
#ifdef HAVE_POLL_H
      else
	{
	  /* use poll */
	  memset (&p, 0, sizeof (p));
	  p[0].fd = con->socket_fd;
	  switch (con->event_loop_info)
	    {
	    case MHD_EVENT_LOOP_INFO_READ:
	      p[0].events |= POLLIN;
	      break;
	    case MHD_EVENT_LOOP_INFO_WRITE:
	      p[0].events |= POLLOUT;
	      if (con->read_buffer_size > con->read_buffer_offset)
		p[0].events |= POLLIN;
	      break;
	    case MHD_EVENT_LOOP_INFO_BLOCK:
	      if (con->read_buffer_size > con->read_buffer_offset)
		p[0].events |= POLLIN;
	      tv.tv_sec = 0;
	      tv.tv_usec = 0;
	      tvp = &tv;
	      break;
	    case MHD_EVENT_LOOP_INFO_CLEANUP:
	      /* how did we get here!? */
	      goto exit;
	    }
	  if (poll (p, 1,
		    (NULL == tvp) ? -1 : tv.tv_sec * 1000) < 0)
	    {
	      if (EINTR == errno)
		continue;
#if HAVE_MESSAGES
	      MHD_DLOG (con->daemon, "Error during poll: `%s'\n",
			STRERROR (errno));
#endif
	      break;
	    }
	  if ( (0 != (p[0].revents & POLLIN))
#if HTTPS_SUPPORT
	       || (MHD_YES == con->tls_read_ready)
#endif
	       )
	    con->read_handler (con);
	  if (0 != (p[0].revents & POLLOUT))
	    con->write_handler (con);
	  if (0 != (p[0].revents & (POLLERR | POLLHUP)))
	    MHD_connection_close (con, MHD_REQUEST_TERMINATED_WITH_ERROR);
	  if (MHD_NO == con->idle_handler (con))
	    goto exit;
	}
#endif
    }
  if (MHD_CONNECTION_IN_CLEANUP != con->state)
    {
#if DEBUG_CLOSE
#if HAVE_MESSAGES
      MHD_DLOG (con->daemon,
                "Processing thread terminating, closing connection\n");
#endif
#endif
      if (MHD_CONNECTION_CLOSED != con->state)
	MHD_connection_close (con,
			      MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN);
      con->idle_handler (con);
    }
exit:
  if (NULL != con->response)
    {
      MHD_destroy_response (con->response);
      con->response = NULL;
    }
  return NULL;
}


/**
 * Callback for receiving data from the socket.
 *
 * @param connection the MHD connection structure
 * @param other where to write received data to
 * @param i maximum size of other (in bytes)
 * @return number of bytes actually received
 */
static ssize_t
recv_param_adapter (struct MHD_Connection *connection,
		    void *other,
		    size_t i)
{
  ssize_t ret;

  if ( (-1 == connection->socket_fd) ||
       (MHD_CONNECTION_CLOSED == connection->state) )
    {
      errno = ENOTCONN;
      return -1;
    }
  ret = RECV (connection->socket_fd, other, i, MSG_NOSIGNAL);
#if EPOLL_SUPPORT
  if (ret < (ssize_t) i)
    {
      /* partial read --- no longer read-ready */
      connection->epoll_state &= ~MHD_EPOLL_STATE_READ_READY;
    }
#endif
  return ret;
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
send_param_adapter (struct MHD_Connection *connection,
                    const void *other,
		    size_t i)
{
  ssize_t ret;
#if LINUX
  int fd;
  off_t offset;
  off_t left;
#endif

  if ( (-1 == connection->socket_fd) ||
       (MHD_CONNECTION_CLOSED == connection->state) )
    {
      errno = ENOTCONN;
      return -1;
    }
  if (0 != (connection->daemon->options & MHD_USE_SSL))
    return SEND (connection->socket_fd, other, i, MSG_NOSIGNAL);
#if LINUX
  if ( (connection->write_buffer_append_offset ==
	connection->write_buffer_send_offset) &&
       (NULL != connection->response) &&
       (-1 != (fd = connection->response->fd)) )
    {
      /* can use sendfile */
      offset = (off_t) connection->response_write_position + connection->response->fd_off;
      left = connection->response->total_size - connection->response_write_position;
      if (left > SSIZE_MAX)
	left = SSIZE_MAX; /* cap at return value limit */
      if (-1 != (ret = sendfile (connection->socket_fd,
				 fd,
				 &offset,
				 (size_t) left)))
	{
#if EPOLL_SUPPORT
	  if (ret < left)
	    {
	      /* partial write --- no longer write-ready */
	      connection->epoll_state &= ~MHD_EPOLL_STATE_WRITE_READY;
	    }
#endif
	  return ret;
	}
      if ( (EINTR == errno) || (EAGAIN == errno) )
	return 0;
      if ( (EINVAL == errno) || (EBADF == errno) )
	return -1;
      /* None of the 'usual' sendfile errors occurred, so we should try
	 to fall back to 'SEND'; see also this thread for info on
	 odd libc/Linux behavior with sendfile:
	 http://lists.gnu.org/archive/html/libmicrohttpd/2011-02/msg00015.html */
    }
#endif
  ret = SEND (connection->socket_fd, other, i, MSG_NOSIGNAL);
#if EPOLL_SUPPORT
  if (ret < (ssize_t) i)
    {
      /* partial write --- no longer write-ready */
      connection->epoll_state &= ~MHD_EPOLL_STATE_WRITE_READY;
    }
#endif
  return ret;
}


/**
 * Signature of main function for a thread.
 *
 * @param cls closure argument for the function
 * @return termination code from the thread
 */
typedef void *(*ThreadStartRoutine)(void *cls);


/**
 * Create a thread and set the attributes according to our options.
 *
 * @param thread handle to initialize
 * @param daemon daemon with options
 * @param start_routine main function of thread
 * @param arg argument for start_routine
 * @return 0 on success
 */
static int
create_thread (pthread_t *thread,
	       const struct MHD_Daemon *daemon,
	       ThreadStartRoutine start_routine,
	       void *arg)
{
  pthread_attr_t attr;
  pthread_attr_t *pattr;
  int ret;

  if (0 != daemon->thread_stack_size)
    {
      if (0 != (ret = pthread_attr_init (&attr)))
	goto ERR;
      if (0 != (ret = pthread_attr_setstacksize (&attr, daemon->thread_stack_size)))
	{
	  pthread_attr_destroy (&attr);
	  goto ERR;
	}
      pattr = &attr;
    }
  else
    {
      pattr = NULL;
    }
  ret = pthread_create (thread, pattr,
			start_routine, arg);
#if (__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)
#if LINUX
  (void) pthread_setname_np (*thread, "libmicrohttpd");
#endif
#endif
  if (0 != daemon->thread_stack_size)
    pthread_attr_destroy (&attr);
  return ret;
 ERR:
#if HAVE_MESSAGES
  MHD_DLOG (daemon,
	    "Failed to set thread stack size\n");
#endif
  errno = EINVAL;
  return ret;
}


/**
 * Add another client connection to the set of connections
 * managed by MHD.  This API is usually not needed (since
 * MHD will accept inbound connections on the server socket).
 * Use this API in special cases, for example if your HTTP
 * server is behind NAT and needs to connect out to the
 * HTTP client.
 *
 * The given client socket will be managed (and closed!) by MHD after
 * this call and must no longer be used directly by the application
 * afterwards.
 *
 * Per-IP connection limits are ignored when using this API.
 *
 * @param daemon daemon that manages the connection
 * @param client_socket socket to manage (MHD will expect
 *        to receive an HTTP request from this socket next).
 * @param addr IP address of the client
 * @param addrlen number of bytes in @a addr
 * @param external_add perform additional operations needed due
 *        to the application calling us directly
 * @return #MHD_YES on success, #MHD_NO if this daemon could
 *        not handle the connection (i.e. malloc failed, etc).
 *        The socket will be closed in any case; 'errno' is
 *        set to indicate further details about the error.
 */
static int
internal_add_connection (struct MHD_Daemon *daemon,
			 int client_socket,
			 const struct sockaddr *addr,
			 socklen_t addrlen,
			 int external_add)
{
  struct MHD_Connection *connection;
  int res_thread_create;
  unsigned int i;
  int eno;
#if OSX
  static int on = 1;
#endif
  if (NULL != daemon->worker_pool)
    {
      /* have a pool, try to find a pool with capacity; we use the
	 socket as the initial offset into the pool for load
	 balancing */
      for (i=0;i<daemon->worker_pool_size;i++)
	if (0 < daemon->worker_pool[(i + client_socket) % daemon->worker_pool_size].max_connections)
	  return internal_add_connection (&daemon->worker_pool[(i + client_socket) % daemon->worker_pool_size],
					  client_socket,
					  addr, addrlen,
					  external_add);
      /* all pools are at their connection limit, must refuse */
      if (0 != CLOSE (client_socket))
	MHD_PANIC ("close failed\n");
#if ENFILE
      errno = ENFILE;
#endif
      return MHD_NO;
    }

#ifndef WINDOWS
  if ( (client_socket >= FD_SETSIZE) &&
       (0 == (daemon->options & (MHD_USE_POLL | MHD_USE_EPOLL_LINUX_ONLY))) )
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Socket descriptor larger than FD_SETSIZE: %d > %d\n",
		client_socket,
		FD_SETSIZE);
#endif
      if (0 != CLOSE (client_socket))
	MHD_PANIC ("close failed\n");
#if EINVAL
      errno = EINVAL;
#endif
      return MHD_NO;
    }
#endif


#if HAVE_MESSAGES
#if DEBUG_CONNECT
  MHD_DLOG (daemon, "Accepted connection on socket %d\n", client_socket);
#endif
#endif
  if ( (0 == daemon->max_connections) ||
       (MHD_NO == MHD_ip_limit_add (daemon, addr, addrlen)) )
    {
      /* above connection limit - reject */
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
                "Server reached connection limit (closing inbound connection)\n");
#endif
      if (0 != CLOSE (client_socket))
	MHD_PANIC ("close failed\n");
#if ENFILE
      errno = ENFILE;
#endif
      return MHD_NO;
    }

  /* apply connection acceptance policy if present */
  if ( (NULL != daemon->apc) &&
       (MHD_NO == daemon->apc (daemon->apc_cls,
			       addr, addrlen)) )
    {
#if DEBUG_CLOSE
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Connection rejected, closing connection\n");
#endif
#endif
      if (0 != CLOSE (client_socket))
	MHD_PANIC ("close failed\n");
      MHD_ip_limit_del (daemon, addr, addrlen);
#if EACCESS
      errno = EACCESS;
#endif
      return MHD_NO;
    }

#if OSX
#ifdef SOL_SOCKET
#ifdef SO_NOSIGPIPE
  setsockopt (client_socket,
	      SOL_SOCKET, SO_NOSIGPIPE,
	      &on, sizeof (on));
#endif
#endif
#endif

  if (NULL == (connection = malloc (sizeof (struct MHD_Connection))))
    {
      eno = errno;
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Error allocating memory: %s\n",
		STRERROR (errno));
#endif
      if (0 != CLOSE (client_socket))
	MHD_PANIC ("close failed\n");
      MHD_ip_limit_del (daemon, addr, addrlen);
      errno = eno;
      return MHD_NO;
    }
  memset (connection, 0, sizeof (struct MHD_Connection));
  connection->pool = MHD_pool_create (daemon->pool_size);
  if (NULL == connection->pool)
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Error allocating memory: %s\n",
		STRERROR (errno));
#endif
      if (0 != CLOSE (client_socket))
	MHD_PANIC ("close failed\n");
      MHD_ip_limit_del (daemon, addr, addrlen);
      free (connection);
#if ENOMEM
      errno = ENOMEM;
#endif
      return MHD_NO;
    }

  connection->connection_timeout = daemon->connection_timeout;
  if (NULL == (connection->addr = malloc (addrlen)))
    {
      eno = errno;
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Error allocating memory: %s\n",
		STRERROR (errno));
#endif
      if (0 != CLOSE (client_socket))
	MHD_PANIC ("close failed\n");
      MHD_ip_limit_del (daemon, addr, addrlen);
      MHD_pool_destroy (connection->pool);
      free (connection);
      errno = eno;
      return MHD_NO;
    }
  memcpy (connection->addr, addr, addrlen);
  connection->addr_len = addrlen;
  connection->socket_fd = client_socket;
  connection->daemon = daemon;
  connection->last_activity = MHD_monotonic_time();

  /* set default connection handlers  */
  MHD_set_http_callbacks_ (connection);
  connection->recv_cls = &recv_param_adapter;
  connection->send_cls = &send_param_adapter;

  if (0 == (connection->daemon->options & MHD_USE_EPOLL_TURBO))
    {
      /* non-blocking sockets are required on most systems and for GNUtls;
	 however, they somehow cause serious problems on CYGWIN (#1824);
	 in turbo mode, we assume that non-blocking was already set
	 by 'accept4' or whoever calls 'MHD_add_connection' */
#ifdef CYGWIN
      if (0 != (daemon->options & MHD_USE_SSL))
#endif
	{
	  /* make socket non-blocking */
#ifndef MINGW
	  int flags = fcntl (connection->socket_fd, F_GETFL);
	  if ( (-1 == flags) ||
	       (0 != fcntl (connection->socket_fd, F_SETFL, flags | O_NONBLOCK)) )
	    {
#if HAVE_MESSAGES
	      MHD_DLOG (daemon,
			"Failed to make socket %d non-blocking: %s\n",
			connection->socket_fd,
			STRERROR (errno));
#endif
	    }
#else
	  unsigned long flags = 1;
	  if (0 != ioctlsocket (connection->socket_fd, FIONBIO, &flags))
	    {
#if HAVE_MESSAGES
	      MHD_DLOG (daemon,
			"Failed to make socket non-blocking: %s\n",
			STRERROR (errno));
#endif
	    }
#endif
	}
    }

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
      switch (daemon->cred_type)
        {
          /* set needed credentials for certificate authentication. */
        case GNUTLS_CRD_CERTIFICATE:
          gnutls_credentials_set (connection->tls_session,
				  GNUTLS_CRD_CERTIFICATE,
				  daemon->x509_cred);
          break;
        default:
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Failed to setup TLS credentials: unknown credential type %d\n",
                    daemon->cred_type);
#endif
          if (0 != CLOSE (client_socket))
	    MHD_PANIC ("close failed\n");
          MHD_ip_limit_del (daemon, addr, addrlen);
          free (connection->addr);
          free (connection);
          MHD_PANIC ("Unknown credential type");
#if EINVAL
	  errno = EINVAL;
#endif
 	  return MHD_NO;
        }
      gnutls_transport_set_ptr (connection->tls_session,
				(gnutls_transport_ptr_t) connection);
      gnutls_transport_set_pull_function (connection->tls_session,
					  (gnutls_pull_func) &recv_param_adapter);
      gnutls_transport_set_push_function (connection->tls_session,
					  (gnutls_push_func) &send_param_adapter);

      if (daemon->https_mem_trust)
	  gnutls_certificate_server_set_request (connection->tls_session,
						 GNUTLS_CERT_REQUEST);
    }
#endif

  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_lock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to acquire cleanup mutex\n");
  XDLL_insert (daemon->normal_timeout_head,
	       daemon->normal_timeout_tail,
	       connection);
  DLL_insert (daemon->connections_head,
	      daemon->connections_tail,
	      connection);
  if  ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
	(0 != pthread_mutex_unlock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to release cleanup mutex\n");

  /* attempt to create handler thread */
  if (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    {
      res_thread_create = create_thread (&connection->pid, daemon,
					 &MHD_handle_connection, connection);
      if (0 != res_thread_create)
        {
	  eno = errno;
#if HAVE_MESSAGES
          MHD_DLOG (daemon, "Failed to create a thread: %s\n",
                    STRERROR (res_thread_create));
#endif
	  goto cleanup;
        }
    }
  else
    if ( (MHD_YES == external_add) &&
	 (-1 != daemon->wpipe[1]) &&
	 (1 != WRITE (daemon->wpipe[1], "n", 1)) )
      {
#if HAVE_MESSAGES
	MHD_DLOG (daemon,
		  "failed to signal new connection via pipe");
#endif
      }
#if EPOLL_SUPPORT
  if (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY))
    {
      if (0 == (daemon->options & MHD_USE_EPOLL_TURBO))
	{
	  struct epoll_event event;

	  event.events = EPOLLIN | EPOLLOUT | EPOLLET;
	  event.data.ptr = connection;
	  if (0 != epoll_ctl (daemon->epoll_fd,
			      EPOLL_CTL_ADD,
			      client_socket,
			      &event))
	    {
	      eno = errno;
#if HAVE_MESSAGES
              MHD_DLOG (daemon,
                        "Call to epoll_ctl failed: %s\n",
                        STRERROR (errno));
#endif
	      goto cleanup;
	    }
	  connection->epoll_state |= MHD_EPOLL_STATE_IN_EPOLL_SET;
	}
      else
	{
	  connection->epoll_state |= MHD_EPOLL_STATE_READ_READY | MHD_EPOLL_STATE_WRITE_READY
	    | MHD_EPOLL_STATE_IN_EREADY_EDLL;
	  EDLL_insert (daemon->eready_head,
		       daemon->eready_tail,
		       connection);
	}
    }
#endif
  daemon->max_connections--;
  return MHD_YES;
 cleanup:
  if (0 != CLOSE (client_socket))
    MHD_PANIC ("close failed\n");
  MHD_ip_limit_del (daemon, addr, addrlen);
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_lock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to acquire cleanup mutex\n");
  DLL_remove (daemon->connections_head,
	      daemon->connections_tail,
	      connection);
  XDLL_remove (daemon->normal_timeout_head,
	       daemon->normal_timeout_tail,
	       connection);
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_unlock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to release cleanup mutex\n");
  MHD_pool_destroy (connection->pool);
  free (connection->addr);
  free (connection);
#if EINVAL
  errno = eno;
#endif
  return MHD_NO;
}


/**
 * Suspend handling of network data for a given connection.  This can
 * be used to dequeue a connection from MHD's event loop (external
 * select, internal select or thread pool; not applicable to
 * thread-per-connection!) for a while.
 *
 * If you use this API in conjunction with a internal select or a
 * thread pool, you must set the option #MHD_USE_PIPE_FOR_SHUTDOWN to
 * ensure that a resumed connection is immediately processed by MHD.
 *
 * Suspended connections continue to count against the total number of
 * connections allowed (per daemon, as well as per IP, if such limits
 * are set).  Suspended connections will NOT time out; timeouts will
 * restart when the connection handling is resumed.  While a
 * connection is suspended, MHD will not detect disconnects by the
 * client.
 *
 * The only safe time to suspend a connection is from the
 * #MHD_AccessHandlerCallback.
 *
 * Finally, it is an API violation to call #MHD_stop_daemon while
 * having suspended connections (this will at least create memory and
 * socket leaks or lead to undefined behavior).  You must explicitly
 * resume all connections before stopping the daemon.
 *
 * @param connection the connection to suspend
 */
void
MHD_suspend_connection (struct MHD_Connection *connection)
{
  struct MHD_Daemon *daemon;

  daemon = connection->daemon;
  if (MHD_USE_SUSPEND_RESUME != (daemon->options & MHD_USE_SUSPEND_RESUME))
    MHD_PANIC ("Cannot suspend connections without enabling MHD_USE_SUSPEND_RESUME!\n");
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_lock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to acquire cleanup mutex\n");
  DLL_remove (daemon->connections_head,
              daemon->connections_tail,
              connection);
  DLL_insert (daemon->suspended_connections_head,
              daemon->suspended_connections_tail,
              connection);
  if (connection->connection_timeout == daemon->connection_timeout)
    XDLL_remove (daemon->normal_timeout_head,
                 daemon->normal_timeout_tail,
                 connection);
  else
    XDLL_remove (daemon->manual_timeout_head,
                 daemon->manual_timeout_tail,
                 connection);
#if EPOLL_SUPPORT
  if (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY))
    {
      if (0 != (connection->epoll_state & MHD_EPOLL_STATE_IN_EREADY_EDLL))
        {
          EDLL_remove (daemon->eready_head,
                       daemon->eready_tail,
                       connection);
        }
      if (0 != (connection->epoll_state & MHD_EPOLL_STATE_IN_EPOLL_SET))
        {
          if (0 != epoll_ctl (daemon->epoll_fd,
                              EPOLL_CTL_DEL,
                              connection->socket_fd,
                              NULL))
            MHD_PANIC ("Failed to remove FD from epoll set\n");
          connection->epoll_state &= ~MHD_EPOLL_STATE_IN_EPOLL_SET;
        }
      connection->epoll_state |= MHD_EPOLL_STATE_SUSPENDED;
    }
#endif
  connection->suspended = MHD_YES;
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_unlock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to release cleanup mutex\n");
}


/**
 * Resume handling of network data for suspended connection.  It is
 * safe to resume a suspended connection at any time.  Calling this function
 * on a connection that was not previously suspended will result
 * in undefined behavior.
 *
 * @param connection the connection to resume
 */
void
MHD_resume_connection (struct MHD_Connection *connection)
{
  struct MHD_Daemon *daemon;

  daemon = connection->daemon;
  if (MHD_USE_SUSPEND_RESUME != (daemon->options & MHD_USE_SUSPEND_RESUME))
    MHD_PANIC ("Cannot resume connections without enabling MHD_USE_SUSPEND_RESUME!\n");
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_lock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to acquire cleanup mutex\n");
  connection->resuming = MHD_YES;
  daemon->resuming = MHD_YES;
  if ( (-1 != daemon->wpipe[1]) &&
       (1 != WRITE (daemon->wpipe[1], "r", 1)) )
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
                "failed to signal resume via pipe");
#endif
    }
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_unlock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to release cleanup mutex\n");
}

/**
 * Run through the suspended connections and move any that are no
 * longer suspended back to the active state.
 *
 * @param daemon daemon context
 */
static void
resume_suspended_connections (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *pos;
  struct MHD_Connection *next = NULL;

  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_lock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to acquire cleanup mutex\n");

  if (MHD_YES == daemon->resuming)
    next = daemon->suspended_connections_head;

  while (NULL != (pos = next))
    {
      next = pos->next;
      if (MHD_NO == pos->resuming)
        continue;

      DLL_remove (daemon->suspended_connections_head,
                  daemon->suspended_connections_tail,
                  pos);
      DLL_insert (daemon->connections_head,
                  daemon->connections_tail,
                  pos);
      if (pos->connection_timeout == daemon->connection_timeout)
        XDLL_insert (daemon->normal_timeout_head,
                     daemon->normal_timeout_tail,
                     pos);
      else
        XDLL_insert (daemon->manual_timeout_head,
                     daemon->manual_timeout_tail,
                     pos);
#if EPOLL_SUPPORT
      if (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY))
        {
          if (0 != (pos->epoll_state & MHD_EPOLL_STATE_IN_EREADY_EDLL))
            {
              EDLL_insert (daemon->eready_head,
                           daemon->eready_tail,
                           pos);
            }
          else
            {
              struct epoll_event event;

              event.events = EPOLLIN | EPOLLOUT | EPOLLET;
              event.data.ptr = pos;
              if (0 != epoll_ctl (daemon->epoll_fd,
                                  EPOLL_CTL_ADD,
                                  pos->socket_fd,
                                  &event))
                MHD_PANIC ("Failed to add FD to epoll set\n");
              else
                pos->epoll_state |= MHD_EPOLL_STATE_IN_EPOLL_SET;
            }
          pos->epoll_state &= ~MHD_EPOLL_STATE_SUSPENDED;
        }
#endif
      pos->suspended = MHD_NO;
      pos->resuming = MHD_NO;
    }
  daemon->resuming = MHD_NO;
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_unlock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to release cleanup mutex\n");
}


/**
 * Change socket options to be non-blocking, non-inheritable.
 *
 * @param daemon daemon context
 * @param sock socket to manipulate
 */
static void
make_nonblocking_noninheritable (struct MHD_Daemon *daemon,
				 int sock)
{
  int nonblock;

#ifdef HAVE_SOCK_NONBLOCK
  nonblock = SOCK_NONBLOCK;
#else
  nonblock = 0;
#endif
#ifdef CYGWIN
  if (0 == (daemon->options & MHD_USE_SSL))
    nonblock = 0;
#endif

#ifdef WINDOWS
  DWORD dwFlags;
  unsigned long flags = 1;

  if (0 != ioctlsocket (sock, FIONBIO, &flags))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Failed to make socket non-blocking: %s\n",
		STRERROR (errno));
#endif
    }
  if (!GetHandleInformation ((HANDLE) sock, &dwFlags) ||
      ((dwFlags != dwFlags & ~HANDLE_FLAG_INHERIT) &&
       !SetHandleInformation ((HANDLE) sock, HANDLE_FLAG_INHERIT, 0)))
    {
#if HAVE_MESSAGES
      SetErrnoFromWinError (GetLastError ());
      MHD_DLOG (daemon,
		"Failed to make socket non-inheritable: %s\n",
		STRERROR (errno));
#endif
    }
#else
  int flags;

  nonblock = O_NONBLOCK;
#ifdef CYGWIN
  if (0 == (daemon->options & MHD_USE_SSL))
    nonblock = 0;
#endif
  flags = fcntl (sock, F_GETFD);
  if ( ( (-1 == flags) ||
	 ( (flags != (flags | FD_CLOEXEC)) &&
	   (0 != fcntl (sock, F_SETFD, flags | nonblock | FD_CLOEXEC)) ) ) )
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Failed to make socket non-inheritable: %s\n",
		STRERROR (errno));
#endif
    }
#endif
}


/**
 * Add another client connection to the set of connections managed by
 * MHD.  This API is usually not needed (since MHD will accept inbound
 * connections on the server socket).  Use this API in special cases,
 * for example if your HTTP server is behind NAT and needs to connect
 * out to the HTTP client, or if you are building a proxy.
 *
 * If you use this API in conjunction with a internal select or a
 * thread pool, you must set the option
 * #MHD_USE_PIPE_FOR_SHUTDOWN to ensure that the freshly added
 * connection is immediately processed by MHD.
 *
 * The given client socket will be managed (and closed!) by MHD after
 * this call and must no longer be used directly by the application
 * afterwards.
 *
 * Per-IP connection limits are ignored when using this API.
 *
 * @param daemon daemon that manages the connection
 * @param client_socket socket to manage (MHD will expect
 *        to receive an HTTP request from this socket next).
 * @param addr IP address of the client
 * @param addrlen number of bytes in @a addr
 * @return #MHD_YES on success, #MHD_NO if this daemon could
 *        not handle the connection (i.e. `malloc()` failed, etc).
 *        The socket will be closed in any case; `errno` is
 *        set to indicate further details about the error.
 * @ingroup specialized
 */
int
MHD_add_connection (struct MHD_Daemon *daemon,
		    int client_socket,
		    const struct sockaddr *addr,
		    socklen_t addrlen)
{
  make_nonblocking_noninheritable (daemon,
				   client_socket);
  return internal_add_connection (daemon,
				  client_socket,
				  addr, addrlen,
				  MHD_YES);
}


/**
 * Accept an incoming connection and create the MHD_Connection object for
 * it.  This function also enforces policy by way of checking with the
 * accept policy callback.
 *
 * @param daemon handle with the listen socket
 * @return MHD_YES on success (connections denied by policy or due
 *         to 'out of memory' and similar errors) are still considered
 *         successful as far as MHD_accept_connection is concerned);
 *         a return code of MHD_NO only refers to the actual
 *         'accept' system call.
 */
static int
MHD_accept_connection (struct MHD_Daemon *daemon)
{
#if HAVE_INET6
  struct sockaddr_in6 addrstorage;
#else
  struct sockaddr_in addrstorage;
#endif
  struct sockaddr *addr = (struct sockaddr *) &addrstorage;
  socklen_t addrlen;
  int s;
  int fd;
  int nonblock;

  addrlen = sizeof (addrstorage);
  memset (addr, 0, sizeof (addrstorage));
  if (-1 == (fd = daemon->socket_fd))
    return MHD_NO;
#ifdef HAVE_SOCK_NONBLOCK
  nonblock = SOCK_NONBLOCK;
#else
  nonblock = 0;
#endif
#ifdef CYGWIN
  if (0 == (daemon->options & MHD_USE_SSL))
    nonblock = 0;
#endif
#if HAVE_ACCEPT4
  s = accept4 (fd, addr, &addrlen, SOCK_CLOEXEC | nonblock);
#else
  s = ACCEPT (fd, addr, &addrlen);
#endif
  if ((-1 == s) || (addrlen <= 0))
    {
#if HAVE_MESSAGES
      /* This could be a common occurance with multiple worker threads */
      if ((EAGAIN != errno) && (EWOULDBLOCK != errno))
        MHD_DLOG (daemon,
		  "Error accepting connection: %s\n",
		  STRERROR (errno));
#endif
      if (-1 != s)
        {
          if (0 != CLOSE (s))
	    MHD_PANIC ("close failed\n");
          /* just in case */
        }
      return MHD_NO;
    }
  if ( (! HAVE_ACCEPT4) || (0 == SOCK_CLOEXEC) )
    make_nonblocking_noninheritable (daemon, s);
#if HAVE_MESSAGES
#if DEBUG_CONNECT
  MHD_DLOG (daemon, "Accepted connection on socket %d\n", s);
#endif
#endif
  (void) internal_add_connection (daemon, s,
				  addr, addrlen,
				  MHD_NO);
  return MHD_YES;
}


/**
 * Free resources associated with all closed connections.
 * (destroy responses, free buffers, etc.).  All closed
 * connections are kept in the "cleanup" doubly-linked list.
 *
 * @param daemon daemon to clean up
 */
static void
MHD_cleanup_connections (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *pos;
  void *unused;
  int rc;

  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_lock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to acquire cleanup mutex\n");
  while (NULL != (pos = daemon->cleanup_head))
    {
      DLL_remove (daemon->cleanup_head,
		  daemon->cleanup_tail,
		  pos);
      if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
	   (MHD_NO == pos->thread_joined) )
	{
	  if (0 != (rc = pthread_join (pos->pid, &unused)))
	    {
	      MHD_PANIC ("Failed to join a thread\n");
	    }
	}
      MHD_pool_destroy (pos->pool);
#if HTTPS_SUPPORT
      if (pos->tls_session != NULL)
	gnutls_deinit (pos->tls_session);
#endif
      MHD_ip_limit_del (daemon,
			(struct sockaddr *) pos->addr,
			pos->addr_len);
#if EPOLL_SUPPORT
      if (0 != (pos->epoll_state & MHD_EPOLL_STATE_IN_EREADY_EDLL))
	{
	  EDLL_remove (daemon->eready_head,
		       daemon->eready_tail,
		       pos);
	  pos->epoll_state &= ~MHD_EPOLL_STATE_IN_EREADY_EDLL;
	}
      if ( (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY)) &&
	   (-1 != daemon->epoll_fd) &&
	   (0 != (pos->epoll_state & MHD_EPOLL_STATE_IN_EPOLL_SET)) )
	{
	  /* epoll documentation suggests that closing a FD
	     automatically removes it from the epoll set; however,
	     this is not true as if we fail to do manually remove it,
	     we are still seeing an event for this fd in epoll,
	     causing grief (use-after-free...) --- at least on my
	     system. */
	  if (0 != epoll_ctl (daemon->epoll_fd,
			      EPOLL_CTL_DEL,
			      pos->socket_fd,
			      NULL))
	    MHD_PANIC ("Failed to remove FD from epoll set\n");
	  pos->epoll_state &= ~MHD_EPOLL_STATE_IN_EPOLL_SET;
	}
#endif
      if (NULL != pos->response)
	{
	  MHD_destroy_response (pos->response);
	  pos->response = NULL;
	}
      if (-1 != pos->socket_fd)
	{
#ifdef WINDOWS
	  SHUTDOWN (pos->socket_fd, SHUT_WR);
#endif
	  if (0 != CLOSE (pos->socket_fd))
	    MHD_PANIC ("close failed\n");
	}
      if (NULL != pos->addr)
	free (pos->addr);
      free (pos);
      daemon->max_connections++;
    }
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_unlock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to release cleanup mutex\n");
}


/**
 * Obtain timeout value for `select()` for this daemon (only needed if
 * connection timeout is used).  The returned value is how long
 * `select()` or `poll()` should at most block, not the timeout value set
 * for connections.  This function MUST NOT be called if MHD is
 * running with #MHD_USE_THREAD_PER_CONNECTION.
 *
 * @param daemon daemon to query for timeout
 * @param timeout set to the timeout (in milliseconds)
 * @return #MHD_YES on success, #MHD_NO if timeouts are
 *        not used (or no connections exist that would
 *        necessiate the use of a timeout right now).
 * @ingroup event
 */
int
MHD_get_timeout (struct MHD_Daemon *daemon,
		 MHD_UNSIGNED_LONG_LONG *timeout)
{
  time_t earliest_deadline;
  time_t now;
  struct MHD_Connection *pos;
  int have_timeout;

  if (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "Illegal call to MHD_get_timeout\n");
#endif
      return MHD_NO;
    }

#if HTTPS_SUPPORT
  if (0 != daemon->num_tls_read_ready)
    {
      /* if there is any TLS connection with data ready for
	 reading, we must not block in the event loop */
      *timeout = 0;
      return MHD_YES;
    }
#endif

  have_timeout = MHD_NO;
  earliest_deadline = 0; /* avoid compiler warnings */
  for (pos = daemon->manual_timeout_head; NULL != pos; pos = pos->nextX)
    {
      if (0 != pos->connection_timeout)
	{
	  if ( (! have_timeout) ||
	       (earliest_deadline > pos->last_activity + pos->connection_timeout) )
	    earliest_deadline = pos->last_activity + pos->connection_timeout;
#if HTTPS_SUPPORT
	  if (  (0 != (daemon->options & MHD_USE_SSL)) &&
		(0 != gnutls_record_check_pending (pos->tls_session)) )
	    earliest_deadline = 0;
#endif
	  have_timeout = MHD_YES;
	}
    }
  /* normal timeouts are sorted, so we only need to look at the 'head' */
  pos = daemon->normal_timeout_head;
  if ( (NULL != pos) &&
       (0 != pos->connection_timeout) )
    {
      if ( (! have_timeout) ||
	   (earliest_deadline > pos->last_activity + pos->connection_timeout) )
	earliest_deadline = pos->last_activity + pos->connection_timeout;
#if HTTPS_SUPPORT
      if (  (0 != (daemon->options & MHD_USE_SSL)) &&
	    (0 != gnutls_record_check_pending (pos->tls_session)) )
	earliest_deadline = 0;
#endif
      have_timeout = MHD_YES;
    }

  if (MHD_NO == have_timeout)
    return MHD_NO;
  now = MHD_monotonic_time();
  if (earliest_deadline < now)
    *timeout = 0;
  else
    *timeout = 1000 * (1 + earliest_deadline - now);
  return MHD_YES;
}


/**
 * Run webserver operations. This method should be called by clients
 * in combination with #MHD_get_fdset if the client-controlled select
 * method is used.
 *
 * You can use this function instead of #MHD_run if you called
 * `select()` on the result from #MHD_get_fdset.  File descriptors in
 * the sets that are not controlled by MHD will be ignored.  Calling
 * this function instead of #MHD_run is more efficient as MHD will
 * not have to call `select()` again to determine which operations are
 * ready.
 *
 * @param daemon daemon to run select loop for
 * @param read_fd_set read set
 * @param write_fd_set write set
 * @param except_fd_set except set (not used, can be NULL)
 * @return #MHD_NO on serious errors, #MHD_YES on success
 * @ingroup event
 */
int
MHD_run_from_select (struct MHD_Daemon *daemon,
		     const fd_set *read_fd_set,
		     const fd_set *write_fd_set,
		     const fd_set *except_fd_set)
{
  int ds;
  char tmp;
  struct MHD_Connection *pos;
  struct MHD_Connection *next;

#if EPOLL_SUPPORT
  if (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY))
    {
      /* we're in epoll mode, the epoll FD stands for
	 the entire event set! */
      if (daemon->epoll_fd >= FD_SETSIZE)
	return MHD_NO; /* poll fd too big, fail hard */
      if (FD_ISSET (daemon->epoll_fd, read_fd_set))
	return MHD_run (daemon);
      return MHD_YES;
    }
#endif

  /* select connection thread handling type */
  if ( (-1 != (ds = daemon->socket_fd)) &&
       (FD_ISSET (ds, read_fd_set)) )
    (void) MHD_accept_connection (daemon);
  /* drain signaling pipe to avoid spinning select */
  if ( (-1 != daemon->wpipe[0]) &&
       (FD_ISSET (daemon->wpipe[0], read_fd_set)) )
    (void) read (daemon->wpipe[0], &tmp, sizeof (tmp));

  if (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    {
      /* do not have a thread per connection, process all connections now */
      next = daemon->connections_head;
      while (NULL != (pos = next))
        {
	  next = pos->next;
          ds = pos->socket_fd;
          if (-1 == ds)
	    continue;
	  switch (pos->event_loop_info)
	    {
	    case MHD_EVENT_LOOP_INFO_READ:
	      if ( (FD_ISSET (ds, read_fd_set))
#if HTTPS_SUPPORT
		   || (MHD_YES == pos->tls_read_ready)
#endif
		   )
		pos->read_handler (pos);
	      break;
	    case MHD_EVENT_LOOP_INFO_WRITE:
	      if ( (FD_ISSET (ds, read_fd_set)) &&
		   (pos->read_buffer_size > pos->read_buffer_offset) )
		pos->read_handler (pos);
	      if (FD_ISSET (ds, write_fd_set))
		pos->write_handler (pos);
	      break;
	    case MHD_EVENT_LOOP_INFO_BLOCK:
	      if ( (FD_ISSET (ds, read_fd_set)) &&
		   (pos->read_buffer_size > pos->read_buffer_offset) )
		pos->read_handler (pos);
	      break;
	    case MHD_EVENT_LOOP_INFO_CLEANUP:
	      /* should never happen */
	      break;
	    }
	  pos->idle_handler (pos);
        }
    }
  MHD_cleanup_connections (daemon);
  return MHD_YES;
}


/**
 * Main internal select() call.  Will compute select sets, call select()
 * and then #MHD_run_from_select with the result.
 *
 * @param daemon daemon to run select() loop for
 * @param may_block #MHD_YES if blocking, #MHD_NO if non-blocking
 * @return #MHD_NO on serious errors, #MHD_YES on success
 */
static int
MHD_select (struct MHD_Daemon *daemon,
	    int may_block)
{
  int num_ready;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct timeval timeout;
  struct timeval *tv;
  MHD_UNSIGNED_LONG_LONG ltimeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  if (MHD_YES == daemon->shutdown)
    return MHD_NO;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  max = -1;
  if (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    {
      if (MHD_USE_SUSPEND_RESUME == (daemon->options & MHD_USE_SUSPEND_RESUME))
        resume_suspended_connections (daemon);

      /* single-threaded, go over everything */
      if (MHD_NO == MHD_get_fdset (daemon, &rs, &ws, &es, &max))
        return MHD_NO;

      /* If we're at the connection limit, no need to
         accept new connections. */
      if ( (0 == daemon->max_connections) &&
	   (-1 != daemon->socket_fd) )
        FD_CLR (daemon->socket_fd, &rs);
    }
  else
    {
      /* accept only, have one thread per connection */
      if (-1 != daemon->socket_fd)
	{
	  max = daemon->socket_fd;
	  FD_SET (daemon->socket_fd, &rs);
	}
    }
  if (-1 != daemon->wpipe[0])
    {
      FD_SET (daemon->wpipe[0], &rs);
      /* update max file descriptor */
      if (max < daemon->wpipe[0])
	max = daemon->wpipe[0];
    }

  tv = NULL;
  if (MHD_NO == may_block)
    {
      timeout.tv_usec = 0;
      timeout.tv_sec = 0;
      tv = &timeout;
    }
  else if ( (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
	    (MHD_YES == MHD_get_timeout (daemon, &ltimeout)) )
    {
      /* ltimeout is in ms */
      timeout.tv_usec = (ltimeout % 1000) * 1000;
      timeout.tv_sec = ltimeout / 1000;
      tv = &timeout;
    }
  if (-1 == max)
    return MHD_YES;
  num_ready = SELECT (max + 1, &rs, &ws, &es, tv);
  if (MHD_YES == daemon->shutdown)
    return MHD_NO;
  if (num_ready < 0)
    {
      if (EINTR == errno)
        return MHD_YES;
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "select failed: %s\n", STRERROR (errno));
#endif
      return MHD_NO;
    }
  return MHD_run_from_select (daemon, &rs, &ws, &es);
}


#ifdef HAVE_POLL_H
/**
 * Process all of our connections and possibly the server
 * socket using poll().
 *
 * @param daemon daemon to run poll loop for
 * @param may_block #MHD_YES if blocking, #MHD_NO if non-blocking
 * @return #MHD_NO on serious errors, #MHD_YES on success
 */
static int
MHD_poll_all (struct MHD_Daemon *daemon,
	      int may_block)
{
  unsigned int num_connections;
  struct MHD_Connection *pos;
  struct MHD_Connection *next;

  if (MHD_USE_SUSPEND_RESUME == (daemon->options & MHD_USE_SUSPEND_RESUME))
    resume_suspended_connections (daemon);

  /* count number of connections and thus determine poll set size */
  num_connections = 0;
  for (pos = daemon->connections_head; NULL != pos; pos = pos->next)
    num_connections++;
  {
    struct pollfd p[2 + num_connections];
    MHD_UNSIGNED_LONG_LONG ltimeout;
    unsigned int i;
    int timeout;
    unsigned int poll_server;
    int poll_listen;

    memset (p, 0, sizeof (p));
    poll_server = 0;
    poll_listen = -1;
    if ( (-1 != daemon->socket_fd) &&
	 (0 != daemon->max_connections) )
      {
	/* only listen if we are not at the connection limit */
	p[poll_server].fd = daemon->socket_fd;
	p[poll_server].events = POLLIN;
	p[poll_server].revents = 0;
	poll_listen = (int) poll_server;
	poll_server++;
      }
    if (-1 != daemon->wpipe[0])
      {
	p[poll_server].fd = daemon->wpipe[0];
	p[poll_server].events = POLLIN;
	p[poll_server].revents = 0;
	poll_server++;
      }
    if (may_block == MHD_NO)
      timeout = 0;
    else if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) ||
	      (MHD_YES != MHD_get_timeout (daemon, &ltimeout)) )
      timeout = -1;
    else
      timeout = (ltimeout > INT_MAX) ? INT_MAX : (int) ltimeout;

    i = 0;
    for (pos = daemon->connections_head; NULL != pos; pos = pos->next)
      {
	p[poll_server+i].fd = pos->socket_fd;
	switch (pos->event_loop_info)
	  {
	  case MHD_EVENT_LOOP_INFO_READ:
	    p[poll_server+i].events |= POLLIN;
	    break;
	  case MHD_EVENT_LOOP_INFO_WRITE:
	    p[poll_server+i].events |= POLLOUT;
	    if (pos->read_buffer_size > pos->read_buffer_offset)
	      p[poll_server+i].events |= POLLIN;
	    break;
	  case MHD_EVENT_LOOP_INFO_BLOCK:
	    if (pos->read_buffer_size > pos->read_buffer_offset)
	      p[poll_server+i].events |= POLLIN;
	    break;
	  case MHD_EVENT_LOOP_INFO_CLEANUP:
	    /* should never happen */
	    break;
	  }
	i++;
      }
    if (0 == poll_server + num_connections)
      return MHD_YES;
    if (poll (p, poll_server + num_connections, timeout) < 0)
      {
	if (EINTR == errno)
	  return MHD_YES;
#if HAVE_MESSAGES
	MHD_DLOG (daemon,
		  "poll failed: %s\n",
		  STRERROR (errno));
#endif
	return MHD_NO;
      }
    /* handle shutdown */
    if (MHD_YES == daemon->shutdown)
      return MHD_NO;
    i = 0;
    next = daemon->connections_head;
    while (NULL != (pos = next))
      {
	next = pos->next;
	switch (pos->event_loop_info)
	  {
	  case MHD_EVENT_LOOP_INFO_READ:
	    /* first, sanity checks */
	    if (i >= num_connections)
	      break; /* connection list changed somehow, retry later ... */
	    if (p[poll_server+i].fd != pos->socket_fd)
	      break; /* fd mismatch, something else happened, retry later ... */
	    /* normal handling */
	    if (0 != (p[poll_server+i].revents & POLLIN))
	      pos->read_handler (pos);
	    pos->idle_handler (pos);
	    i++;
	    break;
	  case MHD_EVENT_LOOP_INFO_WRITE:
	    /* first, sanity checks */
	    if (i >= num_connections)
	      break; /* connection list changed somehow, retry later ... */
	    if (p[poll_server+i].fd != pos->socket_fd)
	      break; /* fd mismatch, something else happened, retry later ... */
	    /* normal handling */
	    if (0 != (p[poll_server+i].revents & POLLIN))
	      pos->read_handler (pos);
	    if (0 != (p[poll_server+i].revents & POLLOUT))
	      pos->write_handler (pos);
	    pos->idle_handler (pos);
	    i++;
	    break;
	  case MHD_EVENT_LOOP_INFO_BLOCK:
	    if (0 != (p[poll_server+i].revents & POLLIN))
	      pos->read_handler (pos);
	    pos->idle_handler (pos);
	    break;
	  case MHD_EVENT_LOOP_INFO_CLEANUP:
	    /* should never happen */
	    break;
	  }
      }
    /* handle 'listen' FD */
    if ( (-1 != poll_listen) &&
	 (0 != (p[poll_listen].revents & POLLIN)) )
      (void) MHD_accept_connection (daemon);
  }
  return MHD_YES;
}


/**
 * Process only the listen socket using poll().
 *
 * @param daemon daemon to run poll loop for
 * @param may_block #MHD_YES if blocking, #MHD_NO if non-blocking
 * @return #MHD_NO on serious errors, #MHD_YES on success
 */
static int
MHD_poll_listen_socket (struct MHD_Daemon *daemon,
			int may_block)
{
  struct pollfd p[2];
  int timeout;
  unsigned int poll_count;
  int poll_listen;

  memset (&p, 0, sizeof (p));
  poll_count = 0;
  poll_listen = -1;
  if (-1 != daemon->socket_fd)
    {
      p[poll_count].fd = daemon->socket_fd;
      p[poll_count].events = POLLIN;
      p[poll_count].revents = 0;
      poll_listen = poll_count;
      poll_count++;
    }
  if (-1 != daemon->wpipe[0])
    {
      p[poll_count].fd = daemon->wpipe[0];
      p[poll_count].events = POLLIN;
      p[poll_count].revents = 0;
      poll_count++;
    }
  if (MHD_NO == may_block)
    timeout = 0;
  else
    timeout = -1;
  if (0 == poll_count)
    return MHD_YES;
  if (poll (p, poll_count, timeout) < 0)
    {
      if (EINTR == errno)
	return MHD_YES;
#if HAVE_MESSAGES
      MHD_DLOG (daemon, "poll failed: %s\n", STRERROR (errno));
#endif
      return MHD_NO;
    }
  /* handle shutdown */
  if (MHD_YES == daemon->shutdown)
    return MHD_NO;
  if ( (-1 != poll_listen) &&
       (0 != (p[poll_listen].revents & POLLIN)) )
    (void) MHD_accept_connection (daemon);
  return MHD_YES;
}
#endif


/**
 * Do poll()-based processing.
 *
 * @param daemon daemon to run poll()-loop for
 * @param may_block #MHD_YES if blocking, #MHD_NO if non-blocking
 * @return #MHD_NO on serious errors, #MHD_YES on success
 */
static int
MHD_poll (struct MHD_Daemon *daemon,
	  int may_block)
{
#ifdef HAVE_POLL_H
  if (MHD_YES == daemon->shutdown)
    return MHD_NO;
  if (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    return MHD_poll_all (daemon, may_block);
  else
    return MHD_poll_listen_socket (daemon, may_block);
#else
  return MHD_NO;
#endif
}


#if EPOLL_SUPPORT

/**
 * How many events to we process at most per epoll() call?  Trade-off
 * between required stack-size and number of system calls we have to
 * make; 128 should be way enough to avoid more than one system call
 * for most scenarios, and still be moderate in stack size
 * consumption.  Embedded systems might want to choose a smaller value
 * --- but why use epoll() on such a system in the first place?
 */
#define MAX_EVENTS 128


/**
 * Do epoll()-based processing (this function is allowed to
 * block if @a may_block is set to #MHD_YES).
 *
 * @param daemon daemon to run poll loop for
 * @param may_block #MHD_YES if blocking, #MHD_NO if non-blocking
 * @return #MHD_NO on serious errors, #MHD_YES on success
 */
static int
MHD_epoll (struct MHD_Daemon *daemon,
	   int may_block)
{
  struct MHD_Connection *pos;
  struct MHD_Connection *next;
  struct epoll_event events[MAX_EVENTS];
  struct epoll_event event;
  int timeout_ms;
  MHD_UNSIGNED_LONG_LONG timeout_ll;
  int num_events;
  unsigned int i;
  unsigned int series_length;
  char tmp;

  if (-1 == daemon->epoll_fd)
    return MHD_NO; /* we're down! */
  if (MHD_YES == daemon->shutdown)
    return MHD_NO;
  if ( (-1 != daemon->socket_fd) &&
       (0 != daemon->max_connections) &&
       (MHD_NO == daemon->listen_socket_in_epoll) )
    {
      event.events = EPOLLIN;
      event.data.ptr = daemon;
      if (0 != epoll_ctl (daemon->epoll_fd,
			  EPOLL_CTL_ADD,
			  daemon->socket_fd,
			  &event))
	{
#if HAVE_MESSAGES
	  if (0 != (daemon->options & MHD_USE_DEBUG))
	    MHD_DLOG (daemon,
		      "Call to epoll_ctl failed: %s\n",
		      STRERROR (errno));
#endif
	  return MHD_NO;
	}
      daemon->listen_socket_in_epoll = MHD_YES;
    }
  if ( (MHD_YES == daemon->listen_socket_in_epoll) &&
       (0 == daemon->max_connections) )
    {
      /* we're at the connection limit, disable listen socket
	 for event loop for now */
      if (0 != epoll_ctl (daemon->epoll_fd,
			  EPOLL_CTL_DEL,
			  daemon->socket_fd,
			  NULL))
	MHD_PANIC ("Failed to remove listen FD from epoll set\n");
      daemon->listen_socket_in_epoll = MHD_NO;
    }
  if (MHD_YES == may_block)
    {
      if (MHD_YES == MHD_get_timeout (daemon,
				      &timeout_ll))
	{
	  if (timeout_ll >= (MHD_UNSIGNED_LONG_LONG) INT_MAX)
	    timeout_ms = INT_MAX;
	  else
	    timeout_ms = (int) timeout_ll;
	}
      else
	timeout_ms = -1;
    }
  else
    timeout_ms = 0;

  /* drain 'epoll' event queue; need to iterate as we get at most
     MAX_EVENTS in one system call here; in practice this should
     pretty much mean only one round, but better an extra loop here
     than unfair behavior... */
  num_events = MAX_EVENTS;
  while (MAX_EVENTS == num_events)
    {
      /* update event masks */
      num_events = epoll_wait (daemon->epoll_fd,
			       events, MAX_EVENTS, timeout_ms);
      if (-1 == num_events)
	{
	  if (EINTR == errno)
	    return MHD_YES;
#if HAVE_MESSAGES
	  if (0 != (daemon->options & MHD_USE_DEBUG))
	    MHD_DLOG (daemon,
		      "Call to epoll_wait failed: %s\n",
		      STRERROR (errno));
#endif
	  return MHD_NO;
	}
      for (i=0;i<(unsigned int) num_events;i++)
	{
	  if (NULL == events[i].data.ptr)
	    continue; /* shutdown signal! */
      if ( (-1 != daemon->wpipe[0]) &&
           (daemon->wpipe[0] == events[i].data.fd) )
        {
          (void) read (daemon->wpipe[0], &tmp, sizeof (tmp));
          continue;
        }
	  if (daemon != events[i].data.ptr)
	    {
	      /* this is an event relating to a 'normal' connection,
		 remember the event and if appropriate mark the
		 connection as 'eready'. */
	      pos = events[i].data.ptr;
	      if (0 != (events[i].events & EPOLLIN))
		{
		  pos->epoll_state |= MHD_EPOLL_STATE_READ_READY;
		  if ( ( (MHD_EVENT_LOOP_INFO_READ == pos->event_loop_info) ||
			 (pos->read_buffer_size > pos->read_buffer_offset) ) &&
		       (0 == (pos->epoll_state & MHD_EPOLL_STATE_IN_EREADY_EDLL) ) )
		    {
		      EDLL_insert (daemon->eready_head,
				   daemon->eready_tail,
				   pos);
		      pos->epoll_state |= MHD_EPOLL_STATE_IN_EREADY_EDLL;
		    }
		}
	      if (0 != (events[i].events & EPOLLOUT))
		{
		  pos->epoll_state |= MHD_EPOLL_STATE_WRITE_READY;
		  if ( (MHD_EVENT_LOOP_INFO_WRITE == pos->event_loop_info) &&
		       (0 == (pos->epoll_state & MHD_EPOLL_STATE_IN_EREADY_EDLL) ) )
		    {
		      EDLL_insert (daemon->eready_head,
				   daemon->eready_tail,
				   pos);
		      pos->epoll_state |= MHD_EPOLL_STATE_IN_EREADY_EDLL;
		    }
		}
	    }
	  else /* must be listen socket */
	    {
	      /* run 'accept' until it fails or we are not allowed to take
		 on more connections */
	      series_length = 0;
	      while ( (MHD_YES == MHD_accept_connection (daemon)) &&
		      (0 != daemon->max_connections) &&
		      (series_length < 128) )
		      series_length++;
	    }
	}
    }

  /* we handle resumes here because we may have ready connections
     that will not be placed into the epoll list immediately. */
  if (MHD_USE_SUSPEND_RESUME == (daemon->options & MHD_USE_SUSPEND_RESUME))
    resume_suspended_connections (daemon);

  /* process events for connections */
  while (NULL != (pos = daemon->eready_tail))
    {
      EDLL_remove (daemon->eready_head,
		   daemon->eready_tail,
		   pos);
      pos->epoll_state &= ~MHD_EPOLL_STATE_IN_EREADY_EDLL;
      if (MHD_EVENT_LOOP_INFO_READ == pos->event_loop_info)
	pos->read_handler (pos);
      if (MHD_EVENT_LOOP_INFO_WRITE == pos->event_loop_info)
	pos->write_handler (pos);
      pos->idle_handler (pos);
    }
  /* Finally, handle timed-out connections; we need to do this here
     as the epoll mechanism won't call the 'idle_handler' on everything,
     as the other event loops do.  As timeouts do not get an explicit
     event, we need to find those connections that might have timed out
     here.

     Connections with custom timeouts must all be looked at, as we
     do not bother to sort that (presumably very short) list. */
  next = daemon->manual_timeout_head;
  while (NULL != (pos = next))
    {
      next = pos->nextX;
      pos->idle_handler (pos);
    }
  /* Connections with the default timeout are sorted by prepending
     them to the head of the list whenever we touch the connection;
     thus it sufficies to iterate from the tail until the first
     connection is NOT timed out */
  next = daemon->normal_timeout_tail;
  while (NULL != (pos = next))
    {
      next = pos->prevX;
      pos->idle_handler (pos);
      if (MHD_CONNECTION_CLOSED != pos->state)
	break; /* sorted by timeout, no need to visit the rest! */
    }
  return MHD_YES;
}
#endif


/**
 * Run webserver operations (without blocking unless in client
 * callbacks).  This method should be called by clients in combination
 * with #MHD_get_fdset if the client-controlled select method is used.
 *
 * This function is a convenience method, which is useful if the
 * fd_sets from #MHD_get_fdset were not directly passed to `select()`;
 * with this function, MHD will internally do the appropriate `select()`
 * call itself again.  While it is always safe to call #MHD_run (in
 * external select mode), you should call #MHD_run_from_select if
 * performance is important (as it saves an expensive call to
 * `select()`).
 *
 * @param daemon daemon to run
 * @return #MHD_YES on success, #MHD_NO if this
 *         daemon was not started with the right
 *         options for this call.
 * @ingroup event
 */
int
MHD_run (struct MHD_Daemon *daemon)
{
  if ( (MHD_YES == daemon->shutdown) ||
       (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) ||
       (0 != (daemon->options & MHD_USE_SELECT_INTERNALLY)) )
    return MHD_NO;
  if (0 != (daemon->options & MHD_USE_POLL))
  {
    MHD_poll (daemon, MHD_NO);
    MHD_cleanup_connections (daemon);
  }
#if EPOLL_SUPPORT
  else if (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY))
  {
    MHD_epoll (daemon, MHD_NO);
    MHD_cleanup_connections (daemon);
  }
#endif
  else
  {
    MHD_select (daemon, MHD_NO);
    /* MHD_select does MHD_cleanup_connections already */
  }
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

  while (MHD_YES != daemon->shutdown)
    {
      if (0 != (daemon->options & MHD_USE_POLL))
	MHD_poll (daemon, MHD_YES);
#if EPOLL_SUPPORT
      else if (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY))
	MHD_epoll (daemon, MHD_YES);
#endif
      else
	MHD_select (daemon, MHD_YES);
      MHD_cleanup_connections (daemon);
    }
  return NULL;
}


/**
 * Start a webserver on the given port.  Variadic version of
 * #MHD_start_daemon_va.
 *
 * @param flags combination of `enum MHD_FLAG` values
 * @param port port to bind to
 * @param apc callback to call to check which clients
 *        will be allowed to connect; you can pass NULL
 *        in which case connections from any IP will be
 *        accepted
 * @param apc_cls extra argument to @a apc
 * @param dh handler called for all requests (repeatedly)
 * @param dh_cls extra argument to @a dh
 * @return NULL on error, handle to daemon on success
 * @ingroup event
 */
struct MHD_Daemon *
MHD_start_daemon (unsigned int flags,
                  uint16_t port,
                  MHD_AcceptPolicyCallback apc,
                  void *apc_cls,
                  MHD_AccessHandlerCallback dh, void *dh_cls, ...)
{
  struct MHD_Daemon *daemon;
  va_list ap;

  va_start (ap, dh_cls);
  daemon = MHD_start_daemon_va (flags, port, apc, apc_cls, dh, dh_cls, ap);
  va_end (ap);
  return daemon;
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
 * #MHD_USE_PIPE_FOR_SHUTDOWN when using this API.  If this daemon is
 * in one of those modes and this option was not given to
 * #MHD_start_daemon, this function will return -1.
 *
 * @param daemon daemon to stop accepting new connections for
 * @return old listen socket on success, -1 if the daemon was
 *         already not listening anymore
 * @ingroup specialized
 */
int
MHD_quiesce_daemon (struct MHD_Daemon *daemon)
{
  unsigned int i;
  int ret;

  ret = daemon->socket_fd;
  if (-1 == ret)
    return -1;
  if ( (-1 == daemon->wpipe[1]) &&
       (0 != (daemon->options & MHD_USE_SELECT_INTERNALLY)) )
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Using MHD_quiesce_daemon in this mode requires MHD_USE_PIPE_FOR_SHUTDOWN\n");
#endif
      return -1;
    }

  if (NULL != daemon->worker_pool)
    for (i = 0; i < daemon->worker_pool_size; i++)
      {
	daemon->worker_pool[i].socket_fd = -1;
#if EPOLL_SUPPORT
	if ( (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY)) &&
	     (-1 != daemon->worker_pool[i].epoll_fd) &&
	     (MHD_YES == daemon->worker_pool[i].listen_socket_in_epoll) )
	  {
	    if (0 != epoll_ctl (daemon->worker_pool[i].epoll_fd,
				EPOLL_CTL_DEL,
				ret,
				NULL))
	      MHD_PANIC ("Failed to remove listen FD from epoll set\n");
	    daemon->worker_pool[i].listen_socket_in_epoll = MHD_NO;
	  }
#endif
      }
  daemon->socket_fd = -1;
#if EPOLL_SUPPORT
  if ( (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY)) &&
       (-1 != daemon->epoll_fd) &&
       (MHD_YES == daemon->listen_socket_in_epoll) )
    {
      if (0 != epoll_ctl (daemon->epoll_fd,
			  EPOLL_CTL_DEL,
			  ret,
			  NULL))
	MHD_PANIC ("Failed to remove listen FD from epoll set\n");
      daemon->listen_socket_in_epoll = MHD_NO;
    }
#endif
  return ret;
}


/**
 * Signature of the MHD custom logger function.
 *
 * @param cls closure
 * @param format format string
 * @param va arguments to the format string (fprintf-style)
 */
typedef void (*VfprintfFunctionPointerType)(void *cls,
					    const char *format,
					    va_list va);


/**
 * Parse a list of options given as varargs.
 *
 * @param daemon the daemon to initialize
 * @param servaddr where to store the server's listen address
 * @param ap the options
 * @return #MHD_YES on success, #MHD_NO on error
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
 * @return #MHD_YES on success, #MHD_NO on error
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
 * @return #MHD_YES on success, #MHD_NO on error
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

  while (MHD_OPTION_END != (opt = (enum MHD_OPTION) va_arg (ap, int)))
    {
      switch (opt)
        {
        case MHD_OPTION_CONNECTION_MEMORY_LIMIT:
          daemon->pool_size = va_arg (ap, size_t);
          break;
        case MHD_OPTION_CONNECTION_MEMORY_INCREMENT:
          daemon->pool_increment= va_arg (ap, size_t);
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
	  if (daemon->worker_pool_size >= (SIZE_MAX / sizeof (struct MHD_Daemon)))
	    {
#if HAVE_MESSAGES
	      MHD_DLOG (daemon,
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
	    MHD_DLOG (daemon,
		      "MHD HTTPS option %d passed to MHD but MHD_USE_SSL not set\n",
		      opt);
#endif
          break;
        case MHD_OPTION_HTTPS_MEM_CERT:
	  if (0 != (daemon->options & MHD_USE_SSL))
	    daemon->https_mem_cert = va_arg (ap, const char *);
#if HAVE_MESSAGES
	  else
	    MHD_DLOG (daemon,
		      "MHD HTTPS option %d passed to MHD but MHD_USE_SSL not set\n",
		      opt);
#endif
          break;
        case MHD_OPTION_HTTPS_MEM_TRUST:
	  if (0 != (daemon->options & MHD_USE_SSL))
	    daemon->https_mem_trust = va_arg (ap, const char *);
#if HAVE_MESSAGES
	  else
	    MHD_DLOG (daemon,
		      "MHD HTTPS option %d passed to MHD but MHD_USE_SSL not set\n",
		      opt);
#endif
          break;
	case MHD_OPTION_HTTPS_CRED_TYPE:
	  daemon->cred_type = (gnutls_credentials_type_t) va_arg (ap, int);
	  break;
        case MHD_OPTION_HTTPS_PRIORITIES:
	  if (0 != (daemon->options & MHD_USE_SSL))
	    {
	      gnutls_priority_deinit (daemon->priority_cache);
	      ret = gnutls_priority_init (&daemon->priority_cache,
					  pstr = va_arg (ap, const char*),
					  NULL);
	      if (ret != GNUTLS_E_SUCCESS)
	      {
#if HAVE_MESSAGES
		MHD_DLOG (daemon,
			  "Setting priorities to `%s' failed: %s\n",
			  pstr,
			  gnutls_strerror (ret));
#endif
		daemon->priority_cache = NULL;
		return MHD_NO;
	      }
	    }
          break;
        case MHD_OPTION_HTTPS_CERT_CALLBACK:
#if GNUTLS_VERSION_MAJOR < 3
#if HAVE_MESSAGES
          MHD_DLOG (daemon,
                    "MHD_OPTION_HTTPS_CERT_CALLBACK requires building MHD with GnuTLS >= 3.0\n");
#endif
          return MHD_NO;
#else
          if (0 != (daemon->options & MHD_USE_SSL))
            daemon->cert_callback = va_arg (ap, gnutls_certificate_retrieve_function2 *);
          break;
#endif
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
        case MHD_OPTION_THREAD_STACK_SIZE:
          daemon->thread_stack_size = va_arg (ap, size_t);
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
		case MHD_OPTION_CONNECTION_MEMORY_INCREMENT:
		case MHD_OPTION_THREAD_STACK_SIZE:
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
		case MHD_OPTION_HTTPS_MEM_TRUST:
		case MHD_OPTION_HTTPS_PRIORITIES:
		case MHD_OPTION_ARRAY:
                case MHD_OPTION_HTTPS_CERT_CALLBACK:
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
		  break;
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
          if (((opt >= MHD_OPTION_HTTPS_MEM_KEY) &&
              (opt <= MHD_OPTION_HTTPS_PRIORITIES)) || (opt == MHD_OPTION_HTTPS_MEM_TRUST))
            {
              MHD_DLOG (daemon,
			"MHD HTTPS option %d passed to MHD compiled without HTTPS support\n",
			opt);
            }
          else
            {
              MHD_DLOG (daemon,
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
 * Create a listen socket, if possible with SOCK_CLOEXEC flag set.
 *
 * @param daemon daemon for which we create the socket
 * @param domain socket domain (i.e. PF_INET)
 * @param type socket type (usually SOCK_STREAM)
 * @param protocol desired protocol, 0 for default
 */
static int
create_socket (struct MHD_Daemon *daemon,
	       int domain, int type, int protocol)
{
  int ctype = type | SOCK_CLOEXEC;
  int fd;

  /* use SOCK_STREAM rather than ai_socktype: some getaddrinfo
   * implementations do not set ai_socktype, e.g. RHL6.2. */
  fd = SOCKET (domain, ctype, protocol);
  if ( (-1 == fd) && (EINVAL == errno) && (0 != SOCK_CLOEXEC) )
  {
    ctype = type;
    fd = SOCKET(domain, type, protocol);
  }
  if (-1 == fd)
    return -1;
  if (type == ctype)
    make_nonblocking_noninheritable (daemon, fd);
  return fd;
}


#if EPOLL_SUPPORT
/**
 * Setup epoll() FD for the daemon and initialize it to listen
 * on the listen FD.
 *
 * @param daemon daemon to initialize for epoll()
 * @return #MHD_YES on success, #MHD_NO on failure
 */
static int
setup_epoll_to_listen (struct MHD_Daemon *daemon)
{
  struct epoll_event event;

  daemon->epoll_fd = epoll_create1 (EPOLL_CLOEXEC);
  if (-1 == daemon->epoll_fd)
    {
#if HAVE_MESSAGES
      if (0 != (daemon->options & MHD_USE_DEBUG))
	MHD_DLOG (daemon,
		  "Call to epoll_create1 failed: %s\n",
		  STRERROR (errno));
#endif
      return MHD_NO;
    }
  if (0 == EPOLL_CLOEXEC)
    make_nonblocking_noninheritable (daemon,
				     daemon->epoll_fd);
  if (-1 == daemon->socket_fd)
    return MHD_YES; /* non-listening daemon */
  event.events = EPOLLIN;
  event.data.ptr = daemon;
  if (0 != epoll_ctl (daemon->epoll_fd,
		      EPOLL_CTL_ADD,
		      daemon->socket_fd,
		      &event))
    {
#if HAVE_MESSAGES
      if (0 != (daemon->options & MHD_USE_DEBUG))
	MHD_DLOG (daemon,
		  "Call to epoll_ctl failed: %s\n",
		  STRERROR (errno));
#endif
      return MHD_NO;
    }
  if ( (-1 != daemon->wpipe[0]) &&
       (MHD_USE_SUSPEND_RESUME == (daemon->options & MHD_USE_SUSPEND_RESUME)) )
    {
      event.events = EPOLLIN | EPOLLET;
      event.data.ptr = NULL;
      event.data.fd = daemon->wpipe[0];
      if (0 != epoll_ctl (daemon->epoll_fd,
                          EPOLL_CTL_ADD,
                          daemon->wpipe[0],
                          &event))
        {
#if HAVE_MESSAGES
          if (0 != (daemon->options & MHD_USE_DEBUG))
            MHD_DLOG (daemon,
                      "Call to epoll_ctl failed: %s\n",
                      STRERROR (errno));
#endif
          return MHD_NO;
        }
    }
  daemon->listen_socket_in_epoll = MHD_YES;
  return MHD_YES;
}
#endif


/**
 * Start a webserver on the given port.
 *
 * @param flags combination of `enum MHD_FLAG` values
 * @param port port to bind to (in host byte order)
 * @param apc callback to call to check which clients
 *        will be allowed to connect; you can pass NULL
 *        in which case connections from any IP will be
 *        accepted
 * @param apc_cls extra argument to @a apc
 * @param dh handler called for all requests (repeatedly)
 * @param dh_cls extra argument to @a dh
 * @param ap list of options (type-value pairs,
 *        terminated with #MHD_OPTION_END).
 * @return NULL on error, handle to daemon on success
 * @ingroup event
 */
struct MHD_Daemon *
MHD_start_daemon_va (unsigned int flags,
                     uint16_t port,
                     MHD_AcceptPolicyCallback apc,
                     void *apc_cls,
                     MHD_AccessHandlerCallback dh, void *dh_cls,
		     va_list ap)
{
  const int on = 1;
  struct MHD_Daemon *daemon;
  int socket_fd;
  struct sockaddr_in servaddr4;
#if HAVE_INET6
  struct sockaddr_in6 servaddr6;
#endif
  const struct sockaddr *servaddr = NULL;
  socklen_t addrlen;
  unsigned int i;
  int res_thread_create;
  int use_pipe;

#ifndef HAVE_INET6
  if (0 != (flags & MHD_USE_IPv6))
    return NULL;
#endif
#ifndef HAVE_POLL_H
  if (0 != (flags & MHD_USE_POLL))
    return NULL;
#endif
#if ! HTTPS_SUPPORT
  if (0 != (flags & MHD_USE_SSL))
    return NULL;
#endif
  if (NULL == dh)
    return NULL;
  if (NULL == (daemon = malloc (sizeof (struct MHD_Daemon))))
    return NULL;
  memset (daemon, 0, sizeof (struct MHD_Daemon));
#if EPOLL_SUPPORT
  daemon->epoll_fd = -1;
#endif
  /* try to open listen socket */
#if HTTPS_SUPPORT
  if (0 != (flags & MHD_USE_SSL))
    {
      gnutls_priority_init (&daemon->priority_cache,
			    "NORMAL",
			    NULL);
    }
#endif
  daemon->socket_fd = -1;
  daemon->options = (enum MHD_OPTION) flags;
#if WINDOWS
  /* Winsock is broken with respect to 'shutdown';
     this disables us calling 'shutdown' on W32. */
  daemon->options |= MHD_USE_EPOLL_TURBO;
#endif
  daemon->port = port;
  daemon->apc = apc;
  daemon->apc_cls = apc_cls;
  daemon->default_handler = dh;
  daemon->default_handler_cls = dh_cls;
  daemon->max_connections = MHD_MAX_CONNECTIONS_DEFAULT;
  daemon->pool_size = MHD_POOL_SIZE_DEFAULT;
  daemon->pool_increment = MHD_BUF_INC_SIZE;
  daemon->unescape_callback = &MHD_http_unescape;
  daemon->connection_timeout = 0;       /* no timeout */
  daemon->wpipe[0] = -1;
  daemon->wpipe[1] = -1;
#if HAVE_MESSAGES
  daemon->custom_error_log = (MHD_LogCallback) &vfprintf;
  daemon->custom_error_log_cls = stderr;
#endif
#ifdef HAVE_LISTEN_SHUTDOWN
  use_pipe = (0 != (daemon->options & (MHD_USE_NO_LISTEN_SOCKET | MHD_USE_PIPE_FOR_SHUTDOWN)));
#else
  use_pipe = 1; /* yes, must use pipe to signal shutdown */
#endif
  if (0 == (flags & (MHD_USE_SELECT_INTERNALLY | MHD_USE_THREAD_PER_CONNECTION)))
    use_pipe = 0; /* useless if we are using 'external' select */
  if ( (use_pipe) &&
#ifdef WINDOWS
       (0 != SOCKETPAIR (AF_INET, SOCK_STREAM, IPPROTO_TCP, daemon->wpipe))
#else
       (0 != PIPE (daemon->wpipe))
#endif
    )
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Failed to create control pipe: %s\n",
		STRERROR (errno));
#endif
      free (daemon);
      return NULL;
    }
#ifndef WINDOWS
  if ( (0 == (flags & MHD_USE_POLL)) &&
       (1 == use_pipe) &&
       (daemon->wpipe[0] >= FD_SETSIZE) )
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"file descriptor for control pipe exceeds maximum value\n");
#endif
      if (0 != CLOSE (daemon->wpipe[0]))
	MHD_PANIC ("close failed\n");
      if (0 != CLOSE (daemon->wpipe[1]))
	MHD_PANIC ("close failed\n");
      free (daemon);
      return NULL;
    }
#endif
#ifdef DAUTH_SUPPORT
  daemon->digest_auth_rand_size = 0;
  daemon->digest_auth_random = NULL;
  daemon->nonce_nc_size = 4; /* tiny */
#endif
#if HTTPS_SUPPORT
  if (0 != (flags & MHD_USE_SSL))
    {
      daemon->cred_type = GNUTLS_CRD_CERTIFICATE;
    }
#endif


  if (MHD_YES != parse_options_va (daemon, &servaddr, ap))
    {
#if HTTPS_SUPPORT
      if ( (0 != (flags & MHD_USE_SSL)) &&
	   (NULL != daemon->priority_cache) )
	gnutls_priority_deinit (daemon->priority_cache);
#endif
      free (daemon);
      return NULL;
    }
#ifdef DAUTH_SUPPORT
  if (daemon->nonce_nc_size > 0)
    {
      if ( ( (size_t) (daemon->nonce_nc_size * sizeof (struct MHD_NonceNc))) /
	   sizeof(struct MHD_NonceNc) != daemon->nonce_nc_size)
	{
#if HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    "Specified value for NC_SIZE too large\n");
#endif
#if HTTPS_SUPPORT
	  if (0 != (flags & MHD_USE_SSL))
	    gnutls_priority_deinit (daemon->priority_cache);
#endif
	  free (daemon);
	  return NULL;
	}
      daemon->nnc = malloc (daemon->nonce_nc_size * sizeof (struct MHD_NonceNc));
      if (NULL == daemon->nnc)
	{
#if HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    "Failed to allocate memory for nonce-nc map: %s\n",
		    STRERROR (errno));
#endif
#if HTTPS_SUPPORT
	  if (0 != (flags & MHD_USE_SSL))
	    gnutls_priority_deinit (daemon->priority_cache);
#endif
	  free (daemon);
	  return NULL;
	}
    }

  if (0 != pthread_mutex_init (&daemon->nnc_lock, NULL))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"MHD failed to initialize nonce-nc mutex\n");
#endif
#if HTTPS_SUPPORT
      if (0 != (flags & MHD_USE_SSL))
	gnutls_priority_deinit (daemon->priority_cache);
#endif
      free (daemon->nnc);
      free (daemon);
      return NULL;
    }
#endif

  /* Thread pooling currently works only with internal select thread model */
  if ( (0 == (flags & MHD_USE_SELECT_INTERNALLY)) &&
       (daemon->worker_pool_size > 0) )
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"MHD thread pooling only works with MHD_USE_SELECT_INTERNALLY\n");
#endif
      goto free_and_fail;
    }

  if ( (MHD_USE_SUSPEND_RESUME == (flags & MHD_USE_SUSPEND_RESUME)) &&
       (0 != (flags & MHD_USE_THREAD_PER_CONNECTION)) )
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
                "Combining MHD_USE_THREAD_PER_CONNECTION and MHD_USE_SUSPEND_RESUME is not supported.\n");
#endif
      goto free_and_fail;
    }

#ifdef __SYMBIAN32__
  if (0 != (flags & (MHD_USE_SELECT_INTERNALLY | MHD_USE_THREAD_PER_CONNECTION)))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Threaded operations are not supported on Symbian.\n");
#endif
      goto free_and_fail;
    }
#endif
#if EPOLL_SUPPORT
  if ( (0 != (flags & MHD_USE_EPOLL_LINUX_ONLY)) &&
       (0 == daemon->worker_pool_size) &&
       (0 == (daemon->options & MHD_USE_NO_LISTEN_SOCKET)) )
    {
      if (0 != (flags & MHD_USE_THREAD_PER_CONNECTION))
	{
#if HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    "Combining MHD_USE_THREAD_PER_CONNECTION and MHD_USE_EPOLL_LINUX_ONLY is not supported.\n");
#endif
	  goto free_and_fail;
	}
      if (MHD_YES != setup_epoll_to_listen (daemon))
	goto free_and_fail;
    }
#else
  if (0 != (flags & MHD_USE_EPOLL_LINUX_ONLY))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"epoll is not supported on this platform by this build.\n");
#endif
      goto free_and_fail;
    }
#endif
  if ( (-1 == daemon->socket_fd) &&
       (0 == (daemon->options & MHD_USE_NO_LISTEN_SOCKET)) )
    {
      /* try to open listen socket */
      if ((flags & MHD_USE_IPv6) != 0)
	socket_fd = create_socket (daemon,
				   PF_INET6, SOCK_STREAM, 0);
      else
	socket_fd = create_socket (daemon,
				   PF_INET, SOCK_STREAM, 0);
      if (-1 == socket_fd)
	{
#if HAVE_MESSAGES
	  if (0 != (flags & MHD_USE_DEBUG))
	    MHD_DLOG (daemon,
		      "Call to socket failed: %s\n",
		      STRERROR (errno));
#endif
	  goto free_and_fail;
	}
      if ( (0 > SETSOCKOPT (socket_fd,
			    SOL_SOCKET,
			    SO_REUSEADDR,
			    &on, sizeof (on))) &&
	   (0 != (flags & MHD_USE_DEBUG)) )
	{
#if HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    "setsockopt failed: %s\n",
		    STRERROR (errno));
#endif
	}

      /* check for user supplied sockaddr */
#if HAVE_INET6
      if (0 != (flags & MHD_USE_IPv6))
	addrlen = sizeof (struct sockaddr_in6);
      else
#endif
	addrlen = sizeof (struct sockaddr_in);
      if (NULL == servaddr)
	{
#if HAVE_INET6
	  if (0 != (flags & MHD_USE_IPv6))
	    {
	      memset (&servaddr6, 0, sizeof (struct sockaddr_in6));
	      servaddr6.sin6_family = AF_INET6;
	      servaddr6.sin6_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
	      servaddr6.sin6_len = sizeof (struct sockaddr_in6);
#endif
	      servaddr = (struct sockaddr *) &servaddr6;
	    }
	  else
#endif
	    {
	      memset (&servaddr4, 0, sizeof (struct sockaddr_in));
	      servaddr4.sin_family = AF_INET;
	      servaddr4.sin_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
	      servaddr4.sin_len = sizeof (struct sockaddr_in);
#endif
	      servaddr = (struct sockaddr *) &servaddr4;
	    }
	}
      daemon->socket_fd = socket_fd;

      if ( (0 != (flags & MHD_USE_IPv6)) &&
	   (MHD_USE_DUAL_STACK != (flags & MHD_USE_DUAL_STACK)) )
	{
#ifdef IPPROTO_IPV6
#ifdef IPV6_V6ONLY
	  /* Note: "IPV6_V6ONLY" is declared by Windows Vista ff., see "IPPROTO_IPV6 Socket Options"
	     (http://msdn.microsoft.com/en-us/library/ms738574%28v=VS.85%29.aspx);
	     and may also be missing on older POSIX systems; good luck if you have any of those,
	     your IPv6 socket may then also bind against IPv4 anyway... */
#ifndef WINDOWS
	  const int on = 1;
#else
	  const char on = 1;
#endif
	  if ( (0 > SETSOCKOPT (socket_fd,
				IPPROTO_IPV6, IPV6_V6ONLY,
				&on, sizeof (on))) &&
	       (0 != (flags & MHD_USE_DEBUG)) )
	    {
#if HAVE_MESSAGES
	      MHD_DLOG (daemon,
			"setsockopt failed: %s\n",
			STRERROR (errno));
#endif
	    }
#endif
#endif
	}
      if (-1 == BIND (socket_fd, servaddr, addrlen))
	{
#if HAVE_MESSAGES
	  if (0 != (flags & MHD_USE_DEBUG))
	    MHD_DLOG (daemon,
		      "Failed to bind to port %u: %s\n",
		      (unsigned int) port,
		      STRERROR (errno));
#endif
	  if (0 != CLOSE (socket_fd))
	    MHD_PANIC ("close failed\n");
	  goto free_and_fail;
	}
#if EPOLL_SUPPORT
      if (0 != (flags & MHD_USE_EPOLL_LINUX_ONLY))
	{
	  int sk_flags = fcntl (socket_fd, F_GETFL);
	  if (0 != fcntl (socket_fd, F_SETFL, sk_flags | O_NONBLOCK))
	    {
#if HAVE_MESSAGES
	      MHD_DLOG (daemon,
			"Failed to make listen socket non-blocking: %s\n",
			STRERROR (errno));
#endif
	      if (0 != CLOSE (socket_fd))
		MHD_PANIC ("close failed\n");
	      goto free_and_fail;
	    }
	}
#endif
      if (LISTEN (socket_fd, 32) < 0)
	{
#if HAVE_MESSAGES
	  if (0 != (flags & MHD_USE_DEBUG))
	    MHD_DLOG (daemon,
		      "Failed to listen for connections: %s\n",
		      STRERROR (errno));
#endif
	  if (0 != CLOSE (socket_fd))
	    MHD_PANIC ("close failed\n");
	  goto free_and_fail;
	}
    }
  else
    {
      socket_fd = daemon->socket_fd;
    }
#ifndef WINDOWS
  if ( (socket_fd >= FD_SETSIZE) &&
       (0 == (flags & (MHD_USE_POLL | MHD_USE_EPOLL_LINUX_ONLY)) ) )
    {
#if HAVE_MESSAGES
      if ((flags & MHD_USE_DEBUG) != 0)
        MHD_DLOG (daemon,
		  "Socket descriptor larger than FD_SETSIZE: %d > %d\n",
		  socket_fd,
		  FD_SETSIZE);
#endif
      if (0 != CLOSE (socket_fd))
	MHD_PANIC ("close failed\n");
      goto free_and_fail;
    }
#endif

  if (0 != pthread_mutex_init (&daemon->per_ip_connection_mutex, NULL))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
               "MHD failed to initialize IP connection limit mutex\n");
#endif
      if ( (-1 != socket_fd) &&
	   (0 != CLOSE (socket_fd)) )
	MHD_PANIC ("close failed\n");
      goto free_and_fail;
    }
  if (0 != pthread_mutex_init (&daemon->cleanup_connection_mutex, NULL))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
               "MHD failed to initialize IP connection limit mutex\n");
#endif
      pthread_mutex_destroy (&daemon->cleanup_connection_mutex);
      if ( (-1 != socket_fd) &&
	   (0 != CLOSE (socket_fd)) )
	MHD_PANIC ("close failed\n");
      goto free_and_fail;
    }

#if HTTPS_SUPPORT
  /* initialize HTTPS daemon certificate aspects & send / recv functions */
  if ((0 != (flags & MHD_USE_SSL)) && (0 != MHD_TLS_init (daemon)))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
		"Failed to initialize TLS support\n");
#endif
      if ( (-1 != socket_fd) &&
	   (0 != CLOSE (socket_fd)) )
	MHD_PANIC ("close failed\n");
      pthread_mutex_destroy (&daemon->cleanup_connection_mutex);
      pthread_mutex_destroy (&daemon->per_ip_connection_mutex);
      goto free_and_fail;
    }
#endif
  if ( ( (0 != (flags & MHD_USE_THREAD_PER_CONNECTION)) ||
	 ( (0 != (flags & MHD_USE_SELECT_INTERNALLY)) &&
	   (0 == daemon->worker_pool_size)) ) &&
       (0 == (daemon->options & MHD_USE_NO_LISTEN_SOCKET)) &&
       (0 != (res_thread_create =
	      create_thread (&daemon->pid, daemon, &MHD_select_thread, daemon))))
    {
#if HAVE_MESSAGES
      MHD_DLOG (daemon,
                "Failed to create listen thread: %s\n",
		STRERROR (res_thread_create));
#endif
      pthread_mutex_destroy (&daemon->cleanup_connection_mutex);
      pthread_mutex_destroy (&daemon->per_ip_connection_mutex);
      if ( (-1 != socket_fd) &&
	   (0 != CLOSE (socket_fd)) )
	MHD_PANIC ("close failed\n");
      goto free_and_fail;
    }
  if ( (daemon->worker_pool_size > 0) &&
       (0 == (daemon->options & MHD_USE_NO_LISTEN_SOCKET)) )
    {
#ifndef MINGW
      int sk_flags;
#else
      unsigned long sk_flags;
#endif

      /* Coarse-grained count of connections per thread (note error
       * due to integer division). Also keep track of how many
       * connections are leftover after an equal split. */
      unsigned int conns_per_thread = daemon->max_connections
                                      / daemon->worker_pool_size;
      unsigned int leftover_conns = daemon->max_connections
                                    % daemon->worker_pool_size;

      i = 0; /* we need this in case fcntl or malloc fails */

      /* Accept must be non-blocking. Multiple children may wake up
       * to handle a new connection, but only one will win the race.
       * The others must immediately return. */
#ifndef MINGW
      sk_flags = fcntl (socket_fd, F_GETFL);
      if (sk_flags < 0)
        goto thread_failed;
      if (0 != fcntl (socket_fd, F_SETFL, sk_flags | O_NONBLOCK))
        goto thread_failed;
#else
      sk_flags = 1;
#if HAVE_PLIBC_FD
      if (SOCKET_ERROR ==
	  ioctlsocket (plibc_fd_get_handle (socket_fd), FIONBIO, &sk_flags))
        goto thread_failed;
#else
      if (ioctlsocket (socket_fd, FIONBIO, &sk_flags) == SOCKET_ERROR)
        goto thread_failed;
#endif // PLIBC_FD
#endif // MINGW

      /* Allocate memory for pooled objects */
      daemon->worker_pool = malloc (sizeof (struct MHD_Daemon)
                                    * daemon->worker_pool_size);
      if (NULL == daemon->worker_pool)
        goto thread_failed;

      /* Start the workers in the pool */
      for (i = 0; i < daemon->worker_pool_size; ++i)
        {
          /* Create copy of the Daemon object for each worker */
          struct MHD_Daemon *d = &daemon->worker_pool[i];

          memcpy (d, daemon, sizeof (struct MHD_Daemon));
          /* Adjust pooling params for worker daemons; note that memcpy()
             has already copied MHD_USE_SELECT_INTERNALLY thread model into
             the worker threads. */
          d->master = daemon;
          d->worker_pool_size = 0;
          d->worker_pool = NULL;

          if ( (MHD_USE_SUSPEND_RESUME == (flags & MHD_USE_SUSPEND_RESUME)) &&
#ifdef WINDOWS
               (0 != SOCKETPAIR (AF_INET, SOCK_STREAM, IPPROTO_TCP, d->wpipe))
#else
               (0 != PIPE (d->wpipe))
#endif
             )
            {
#if HAVE_MESSAGES
              MHD_DLOG (daemon,
                        "Failed to create worker control pipe: %s\n",
                        STRERROR (errno));
#endif
              goto thread_failed;
            }
#ifndef WINDOWS
          if ( (0 == (flags & MHD_USE_POLL)) &&
               (MHD_USE_SUSPEND_RESUME == (flags & MHD_USE_SUSPEND_RESUME)) &&
               (d->wpipe[0] >= FD_SETSIZE) )
            {
#if HAVE_MESSAGES
              MHD_DLOG (daemon,
                        "file descriptor for worker control pipe exceeds maximum value\n");
#endif
              if (0 != CLOSE (d->wpipe[0]))
                MHD_PANIC ("close failed\n");
              if (0 != CLOSE (d->wpipe[1]))
                MHD_PANIC ("close failed\n");
              goto thread_failed;
            }
#endif

          /* Divide available connections evenly amongst the threads.
           * Thread indexes in [0, leftover_conns) each get one of the
           * leftover connections. */
          d->max_connections = conns_per_thread;
          if (i < leftover_conns)
            ++d->max_connections;
#if EPOLL_SUPPORT
	  if ( (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY)) &&
	       (MHD_YES != setup_epoll_to_listen (d)) )
	    goto thread_failed;
#endif
          /* Must init cleanup connection mutex for each worker */
          if (0 != pthread_mutex_init (&d->cleanup_connection_mutex, NULL))
            {
#if HAVE_MESSAGES
              MHD_DLOG (daemon,
                       "MHD failed to initialize cleanup connection mutex for thread worker %d\n", i);
#endif
              goto thread_failed;
            }

          /* Spawn the worker thread */
          if (0 != (res_thread_create =
		    create_thread (&d->pid, daemon, &MHD_select_thread, d)))
            {
#if HAVE_MESSAGES
              MHD_DLOG (daemon,
                        "Failed to create pool thread: %s\n",
			STRERROR (res_thread_create));
#endif
              /* Free memory for this worker; cleanup below handles
               * all previously-created workers. */
              pthread_mutex_destroy (&d->cleanup_connection_mutex);
              goto thread_failed;
            }
        }
    }
  return daemon;

thread_failed:
  /* If no worker threads created, then shut down normally. Calling
     MHD_stop_daemon (as we do below) doesn't work here since it
     assumes a 0-sized thread pool means we had been in the default
     MHD_USE_SELECT_INTERNALLY mode. */
  if (0 == i)
    {
      if ( (-1 != socket_fd) &&
	   (0 != CLOSE (socket_fd)) )
	MHD_PANIC ("close failed\n");
      pthread_mutex_destroy (&daemon->cleanup_connection_mutex);
      pthread_mutex_destroy (&daemon->per_ip_connection_mutex);
      if (NULL != daemon->worker_pool)
        free (daemon->worker_pool);
      goto free_and_fail;
    }

  /* Shutdown worker threads we've already created. Pretend
     as though we had fully initialized our daemon, but
     with a smaller number of threads than had been
     requested. */
  daemon->worker_pool_size = i - 1;
  MHD_stop_daemon (daemon);
  return NULL;

 free_and_fail:
  /* clean up basic memory state in 'daemon' and return NULL to
     indicate failure */
#if EPOLL_SUPPORT
  if (-1 != daemon->epoll_fd)
    close (daemon->epoll_fd);
#endif
#ifdef DAUTH_SUPPORT
  free (daemon->nnc);
  pthread_mutex_destroy (&daemon->nnc_lock);
#endif
#if HTTPS_SUPPORT
  if (0 != (flags & MHD_USE_SSL))
    gnutls_priority_deinit (daemon->priority_cache);
#endif
  free (daemon);
  return NULL;
}


/**
 * Close the given connection, remove it from all of its
 * DLLs and move it into the cleanup queue.
 *
 * @param pos connection to move to cleanup
 */
static void
close_connection (struct MHD_Connection *pos)
{
  struct MHD_Daemon *daemon = pos->daemon;

  MHD_connection_close (pos,
			MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN);
  if (pos->connection_timeout == pos->daemon->connection_timeout)
    XDLL_remove (daemon->normal_timeout_head,
		 daemon->normal_timeout_tail,
		 pos);
  else
    XDLL_remove (daemon->manual_timeout_head,
		 daemon->manual_timeout_tail,
		 pos);
  DLL_remove (daemon->connections_head,
	      daemon->connections_tail,
	      pos);
  pos->event_loop_info = MHD_EVENT_LOOP_INFO_CLEANUP;
  DLL_insert (daemon->cleanup_head,
	      daemon->cleanup_tail,
	      pos);
}


/**
 * Close all connections for the daemon; must only be called after
 * all of the threads have been joined and there is no more concurrent
 * activity on the connection lists.
 *
 * @param daemon daemon to close down
 */
static void
close_all_connections (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *pos;
  void *unused;
  int rc;

  /* first, make sure all threads are aware of shutdown; need to
     traverse DLLs in peace... */
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_lock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to acquire cleanup mutex\n");
  for (pos = daemon->connections_head; NULL != pos; pos = pos->nextX)
    SHUTDOWN (pos->socket_fd,
	      (pos->read_closed == MHD_YES) ? SHUT_WR : SHUT_RDWR);
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) &&
       (0 != pthread_mutex_unlock (&daemon->cleanup_connection_mutex)) )
    MHD_PANIC ("Failed to release cleanup mutex\n");

  /* now, collect threads from thread pool */
  if (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION))
    {
      while (NULL != (pos = daemon->connections_head))
	{
	  if (0 != (rc = pthread_join (pos->pid, &unused)))
	    MHD_PANIC ("Failed to join a thread\n");
	  pos->thread_joined = MHD_YES;
	}
    }

  /* now that we're alone, move everyone to cleanup */
  while (NULL != (pos = daemon->connections_head))
    close_connection (pos);
  MHD_cleanup_connections (daemon);
}


#if EPOLL_SUPPORT
/**
 * Shutdown epoll()-event loop by adding 'wpipe' to its event set.
 *
 * @param daemon daemon of which the epoll() instance must be signalled
 */
static void
epoll_shutdown (struct MHD_Daemon *daemon)
{
  struct epoll_event event;

  if (-1 == daemon->wpipe[1])
    {
      /* wpipe was required in this mode, how could this happen? */
      MHD_PANIC ("Internal error\n");
    }
  event.events = EPOLLOUT;
  event.data.ptr = NULL;
  if (0 != epoll_ctl (daemon->epoll_fd,
		      EPOLL_CTL_ADD,
		      daemon->wpipe[1],
		      &event))
    MHD_PANIC ("Failed to add wpipe to epoll set to signal termination\n");
}
#endif


/**
 * Shutdown an HTTP daemon.
 *
 * @param daemon daemon to stop
 * @ingroup event
 */
void
MHD_stop_daemon (struct MHD_Daemon *daemon)
{
  void *unused;
  int fd;
  unsigned int i;
  int rc;

  if (NULL == daemon)
    return;
  daemon->shutdown = MHD_YES;
  fd = daemon->socket_fd;
  daemon->socket_fd = -1;
  /* Prepare workers for shutdown */
  if (NULL != daemon->worker_pool)
    {
      /* MHD_USE_NO_LISTEN_SOCKET disables thread pools, hence we need to check */
      for (i = 0; i < daemon->worker_pool_size; ++i)
	{
	  daemon->worker_pool[i].shutdown = MHD_YES;
	  daemon->worker_pool[i].socket_fd = -1;
#if EPOLL_SUPPORT
	  if ( (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY)) &&
	       (-1 != daemon->worker_pool[i].epoll_fd) &&
	       (-1 == fd) )
	    epoll_shutdown (&daemon->worker_pool[i]);
#endif
	}
    }
  if (-1 != daemon->wpipe[1])
    {
      if (1 != WRITE (daemon->wpipe[1], "e", 1))
	MHD_PANIC ("failed to signal shutdown via pipe");
    }
#ifdef HAVE_LISTEN_SHUTDOWN
  else
    {
      /* fd might be -1 here due to 'MHD_quiesce_daemon' */
      if (-1 != fd)
	(void) SHUTDOWN (fd, SHUT_RDWR);
    }
#endif
#if EPOLL_SUPPORT
  if ( (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY)) &&
       (-1 != daemon->epoll_fd) &&
       (-1 == fd) )
    epoll_shutdown (daemon);
#endif

#if DEBUG_CLOSE
#if HAVE_MESSAGES
  MHD_DLOG (daemon, "MHD listen socket shutdown\n");
#endif
#endif


  /* Signal workers to stop and clean them up */
  if (NULL != daemon->worker_pool)
    {
      /* MHD_USE_NO_LISTEN_SOCKET disables thread pools, hence we need to check */
      for (i = 0; i < daemon->worker_pool_size; ++i)
	{
	  if (-1 != daemon->worker_pool[i].wpipe[1])
	    {
	      if (1 != WRITE (daemon->worker_pool[i].wpipe[1], "e", 1))
		MHD_PANIC ("failed to signal shutdown via pipe");
	    }
	  if (0 != (rc = pthread_join (daemon->worker_pool[i].pid, &unused)))
	      MHD_PANIC ("Failed to join a thread\n");
	  close_all_connections (&daemon->worker_pool[i]);
	  pthread_mutex_destroy (&daemon->worker_pool[i].cleanup_connection_mutex);
#if EPOLL_SUPPORT
	  if ( (-1 != daemon->worker_pool[i].epoll_fd) &&
	       (0 != CLOSE (daemon->worker_pool[i].epoll_fd)) )
	    MHD_PANIC ("close failed\n");
#endif
          if ( (MHD_USE_SUSPEND_RESUME == (daemon->options & MHD_USE_SUSPEND_RESUME)) )
            {
              if (-1 != daemon->worker_pool[i].wpipe[1])
                {
	           if (0 != CLOSE (daemon->worker_pool[i].wpipe[0]))
	             MHD_PANIC ("close failed\n");
	           if (0 != CLOSE (daemon->worker_pool[i].wpipe[1]))
	             MHD_PANIC ("close failed\n");
                }
	    }
	}
      free (daemon->worker_pool);
    }
  else
    {
      /* clean up master threads */
      if ((0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) ||
	  ((0 != (daemon->options & MHD_USE_SELECT_INTERNALLY))
	   && (0 == daemon->worker_pool_size)))
	{
	  if (0 != (rc = pthread_join (daemon->pid, &unused)))
	    {
	      MHD_PANIC ("Failed to join a thread\n");
	    }
	}
    }
  close_all_connections (daemon);
  if ( (-1 != fd) &&
       (0 != CLOSE (fd)) )
    MHD_PANIC ("close failed\n");

  /* TLS clean up */
#if HTTPS_SUPPORT
  if (0 != (daemon->options & MHD_USE_SSL))
    {
      gnutls_priority_deinit (daemon->priority_cache);
      if (daemon->x509_cred)
        gnutls_certificate_free_credentials (daemon->x509_cred);
    }
#endif
#if EPOLL_SUPPORT
  if ( (0 != (daemon->options & MHD_USE_EPOLL_LINUX_ONLY)) &&
       (-1 != daemon->epoll_fd) &&
       (0 != CLOSE (daemon->epoll_fd)) )
    MHD_PANIC ("close failed\n");
#endif

#ifdef DAUTH_SUPPORT
  free (daemon->nnc);
  pthread_mutex_destroy (&daemon->nnc_lock);
#endif
  pthread_mutex_destroy (&daemon->per_ip_connection_mutex);
  pthread_mutex_destroy (&daemon->cleanup_connection_mutex);

  if (-1 != daemon->wpipe[1])
    {
      if (0 != CLOSE (daemon->wpipe[0]))
	MHD_PANIC ("close failed\n");
      if (0 != CLOSE (daemon->wpipe[1]))
	MHD_PANIC ("close failed\n");
    }
  free (daemon);
}


/**
 * Obtain information about the given daemon
 * (not fully implemented!).
 *
 * @param daemon what daemon to get information about
 * @param info_type what information is desired?
 * @param ... depends on @a info_type
 * @return NULL if this information is not available
 *         (or if the @a info_type is unknown)
 * @ingroup specialized
 */
const union MHD_DaemonInfo *
MHD_get_daemon_info (struct MHD_Daemon *daemon,
		     enum MHD_DaemonInfoType info_type,
		     ...)
{
  switch (info_type)
    {
    case MHD_DAEMON_INFO_KEY_SIZE:
      return NULL; /* no longer supported */
    case MHD_DAEMON_INFO_MAC_KEY_SIZE:
      return NULL; /* no longer supported */
    case MHD_DAEMON_INFO_LISTEN_FD:
      return (const union MHD_DaemonInfo *) &daemon->socket_fd;
#if EPOLL_SUPPORT
    case MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY:
      return (const union MHD_DaemonInfo *) &daemon->epoll_fd;
#endif
    default:
      return NULL;
    };
}


/**
 * Sets the global error handler to a different implementation.  @a cb
 * will only be called in the case of typically fatal, serious
 * internal consistency issues.  These issues should only arise in the
 * case of serious memory corruption or similar problems with the
 * architecture.  While @a cb is allowed to return and MHD will then
 * try to continue, this is never safe.
 *
 * The default implementation that is used if no panic function is set
 * simply prints an error message and calls `abort()`.  Alternative
 * implementations might call `exit()` or other similar functions.
 *
 * @param cb new error handler
 * @param cls passed to @a cb
 * @ingroup logging
 */
void
MHD_set_panic_func (MHD_PanicCallback cb, void *cls)
{
  mhd_panic = cb;
  mhd_panic_cls = cls;
}


/**
 * Obtain the version of this library
 *
 * @return static version string, e.g. "0.9.9"
 * @ingroup specialized
 */
const char *
MHD_get_version (void)
{
  return PACKAGE_VERSION;
}


#ifdef __GNUC__
#define ATTRIBUTE_CONSTRUCTOR __attribute__ ((constructor))
#define ATTRIBUTE_DESTRUCTOR __attribute__ ((destructor))
#else  // !__GNUC__
#define ATTRIBUTE_CONSTRUCTOR
#define ATTRIBUTE_DESTRUCTOR
#endif  // __GNUC__

#if HTTPS_SUPPORT
#if GCRYPT_VERSION_NUMBER < 0x010600
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif
#endif


/**
 * Initialize do setup work.
 */
void ATTRIBUTE_CONSTRUCTOR
MHD_init ()
{
  mhd_panic = &mhd_panic_std;
  mhd_panic_cls = NULL;

#ifdef WINDOWS
  plibc_init ("GNU", "libmicrohttpd");
#endif
#if HTTPS_SUPPORT
#if GCRYPT_VERSION_NUMBER < 0x010600
  gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif
  gcry_check_version (NULL);
  gnutls_global_init ();
#endif
}


void ATTRIBUTE_DESTRUCTOR
MHD_fini ()
{
#if HTTPS_SUPPORT
  gnutls_global_deinit ();
#endif
#ifdef WINDOWS
  plibc_shutdown ();
#endif
}

/* end of daemon.c */

