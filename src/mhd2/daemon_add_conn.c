/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2014-2024 Evgeny Grin (Karlson2k)
  Copyright (C) 2007-2018 Daniel Pittman and Christian Grothoff

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
 * @file src/mhd2/daemon_add_conn.c
 * @brief  The implementations of MHD functions for adding new connections
 * @author Karlson2k (Evgeny Grin)
 * @author Daniel Pittman
 * @author Christian Grothoff
 *
 * @warning Imported from MHD1 with minimal changes
 * TODO:
 * + Rewrite,
 * + add per IP limit,
 * + add app policy for new conn,
 */

#include "mhd_sys_options.h"

#include "daemon_add_conn.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"
#include "sys_sockets_types.h"
#include "sys_sockets_headers.h"
#include "sys_ip_headers.h"

#include <string.h>
#ifdef MHD_USE_EPOLL
#  include <sys/epoll.h>
#endif

#include "compat_calloc.h"

#include "mhd_sockets_macros.h"
#include "mhd_sockets_funcs.h"

#include "mhd_panic.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"

#include "daemon_logger.h"
#include "mhd_mono_clock.h"
#include "mhd_mempool.h"
#include "events_process.h"

#include "response_from.h"
#include "response_destroy.h"
#include "conn_mark_ready.h"

#include "mhd_public_api.h"


/**
 * Set initial internal states for the connection to start reading and
 * processing incoming data.
 * @param c the connection to process
 */
static void
connection_set_initial_state (struct MHD_Connection *restrict c)
{
  size_t read_buf_size;

  mhd_assert (MHD_CONNECTION_INIT == c->state);

  c->conn_reuse = mhd_CONN_KEEPALIVE_POSSIBLE;
  c->event_loop_info = MHD_EVENT_LOOP_INFO_READ;

  memset (&c->rq, 0, sizeof(c->rq));
  memset (&c->rp, 0, sizeof(c->rp));

#ifndef HAVE_NULL_PTR_ALL_ZEROS
  mhd_DLINKEDL_INIT_LINKS (c, all_conn);
  mhd_DLINKEDL_INIT_LINKS (c, proc_ready);
  mhd_DLINKEDL_INIT_LINKS (c, by_timeout);
  // TODO: set all other pointers manually
#endif /* ! HAVE_NULL_PTR_ALL_ZEROS */

  c->write_buffer = NULL;
  c->write_buffer_size = 0;
  c->write_buffer_send_offset = 0;
  c->write_buffer_append_offset = 0;

  c->continue_message_write_offset = 0;

  c->read_buffer_offset = 0;
  read_buf_size = c->daemon->conns.cfg.mem_pool_size / 2;
  c->read_buffer
    = mhd_pool_allocate (c->pool,
                         read_buf_size,
                         false);
  c->read_buffer_size = read_buf_size;
}


static void
notify_app_conn (struct MHD_Daemon *restrict daemon,
                 struct MHD_Connection *restrict connection,
                 bool closed)
{
  (void) daemon, (void) connection, (void) closed;
  // TODO: implement
}


/**
 * Do basic preparation work on the new incoming connection.
 *
 * This function do all preparation that is possible outside main daemon
 * thread.
 * @remark Could be called from any thread.
 *
 * @param daemon daemon that manages the connection
 * @param client_socket socket to manage (MHD will expect
 *        to receive an HTTP request from this socket next).
 * @param addr IP address of the client
 * @param addrlen number of bytes in @a addr
 * @param external_add indicate that socket has been added externally
 * @param non_blck indicate that socket in non-blocking mode
 * @param sk_spipe_supprs indicate that the @a client_socket has
 *                         set SIGPIPE suppression
 * @param sk_is_nonip _MHD_YES if this is not a TCP/IP socket
 * @return pointer to the connection on success, NULL if this daemon could
 *        not handle the connection (i.e. malloc failed, etc).
 *        The socket will be closed in case of error; 'errno' is
 *        set to indicate further details about the error.
 */
static enum MHD_StatusCode
new_connection_prepare_ (struct MHD_Daemon *restrict daemon,
                         MHD_Socket client_socket,
                         const struct sockaddr_storage *restrict addr,
                         size_t addrlen,
                         bool external_add,
                         bool non_blck,
                         bool sk_spipe_supprs,
                         enum mhd_Tristate sk_is_nonip,
                         struct MHD_Connection **restrict conn_out)
{
  struct MHD_Connection *connection;
  *conn_out = NULL;

  if (NULL == (connection = mhd_calloc (1, sizeof (struct MHD_Connection))))
  {
    mhd_LOG_MSG (daemon, MHD_SC_CONNECTION_MALLOC_FAILURE,
                 "Failed to allocate memory for the new connection");
    mhd_socket_close (client_socket);
    return MHD_SC_CONNECTION_MALLOC_FAILURE;
  }

  if (! external_add)
  {
    connection->sk_corked = mhd_T_NO;
    connection->sk_nodelay = mhd_T_NO;
  }
  else
  {
    connection->sk_corked = mhd_T_MAYBE;
    connection->sk_nodelay = mhd_T_MAYBE;
  }

  if (0 < addrlen)
  {
    if (NULL == (connection->addr = malloc (addrlen)))
    {
      mhd_LOG_MSG (daemon, MHD_SC_CONNECTION_MALLOC_FAILURE,
                   "Failed to allocate memory for the new connection");
      mhd_socket_close (client_socket);
      free (connection);
      return MHD_SC_CONNECTION_MALLOC_FAILURE;
    }
    memcpy (connection->addr,
            addr,
            addrlen);
  }
  else
    connection->addr = NULL;
  connection->addr_len = addrlen;
  connection->socket_fd = client_socket;
  connection->sk_nonblck = non_blck;
  connection->is_nonip = sk_is_nonip;
  connection->sk_spipe_suppress = sk_spipe_supprs;
#ifdef MHD_USE_THREADS
  mhd_thread_handle_ID_set_invalid (&connection->tid);
#endif /* MHD_USE_THREADS */
  connection->daemon = daemon;
  connection->connection_timeout_ms = daemon->conns.cfg.timeout;
  connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
  if (0 != connection->connection_timeout_ms)
    connection->last_activity = MHD_monotonic_msec_counter ();

  // TODO: init TLS
  *conn_out = connection;

  return MHD_SC_OK;
}


/**
 * Finally insert the new connection to the list of connections
 * served by the daemon and start processing.
 * @remark To be called only from thread that process
 * daemon's select()/poll()/etc.
 *
 * @param daemon daemon that manages the connection
 * @param connection the newly created connection
 * @return #MHD_YES on success, #MHD_NO on error
 */
static enum MHD_StatusCode
new_connection_process_ (struct MHD_Daemon *restrict daemon,
                         struct MHD_Connection *restrict connection)
{
  enum MHD_StatusCode res;
  mhd_assert (connection->daemon == daemon);

  res = MHD_SC_OK;
  /* Allocate memory pool in the processing thread so
   * intensively used memory area is allocated in "good"
   * (for the thread) memory region. It is important with
   * NUMA and/or complex cache hierarchy. */
  connection->pool = mdh_pool_create (daemon->conns.cfg.mem_pool_size);
  if (NULL == connection->pool)
  { /* 'pool' creation failed */
    mhd_LOG_MSG (daemon, MHD_SC_POOL_MALLOC_FAILURE, \
                 "Failed to allocate memory for the connection memory pool.");
    res = MHD_SC_POOL_MALLOC_FAILURE;
  }
  else
  { /* 'pool' creation succeed */

    if (daemon->conns.block_new)
    { /* Connections limit */
      mhd_LOG_MSG (daemon, MHD_SC_LIMIT_CONNECTIONS_REACHED, \
                   "Server reached connection limit. " \
                   "Closing inbound connection.");
      res = MHD_SC_LIMIT_CONNECTIONS_REACHED;
    }
    else
    { /* Have space for new connection */
      mhd_assert (daemon->conns.count < daemon->conns.cfg.count_limit);
      daemon->conns.count++;
      daemon->conns.block_new =
        (daemon->conns.count >= daemon->conns.cfg.count_limit);
      mhd_DLINKEDL_INS_LAST (&(daemon->conns), connection, all_conn);
      if (mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION != daemon->wmode_int)
        mhd_DLINKEDL_INS_FIRST_D (&(daemon->conns.def_timeout), \
                                  connection, by_timeout);

      connection_set_initial_state (connection);

      notify_app_conn (daemon, connection, false);

#ifdef MHD_USE_THREADS
      if (mhd_DAEMON_TYPE_LISTEN_ONLY == daemon->threading.d_type)
      {
        mhd_assert ((mhd_POLL_TYPE_SELECT == daemon->events.poll_type) || \
                    (mhd_POLL_TYPE_POLL == daemon->events.poll_type));
        if (! mhd_create_named_thread (&connection->tid,
                                       "MHD-connection",
                                       daemon->threading.cfg.stack_size,
                                       &mhd_worker_connection,
                                       connection))
        {
#ifdef EAGAIN
          if (EAGAIN == errno)
          {
            mhd_LOG_MSG (daemon, MHD_SC_CONNECTION_THREAD_SYS_LIMITS_REACHED,
                         "Failed to create a new thread because it would "
                         "have exceeded the system limit on the number of "
                         "threads or no system resources available.");
            res = MHD_SC_CONNECTION_THREAD_SYS_LIMITS_REACHED;
          }
          else
#endif /* EAGAIN */
          if (1)
          {
            mhd_LOG_MSG (daemon, MHD_SC_CONNECTION_THREAD_LAUNCH_FAILURE,
                         "Failed to create a thread.");
            res = MHD_SC_CONNECTION_THREAD_LAUNCH_FAILURE;
          }
        }
        else               /* New thread has been created successfully */
          return MHD_SC_OK;  /* *** Function success exit point *** */
      }
      else
#else  /* ! MHD_USE_THREADS */
      if (1)
#endif /* ! MHD_USE_THREADS */
      { /* No 'thread-per-connection' */
#ifdef MHD_USE_THREADS
        connection->tid = daemon->threading.tid;
#endif /* MHD_USE_THREADS */
#ifdef MHD_USE_EPOLL
        if (mhd_POLL_TYPE_EPOLL == daemon->events.poll_type)
        {
          struct epoll_event event;

          event.events = EPOLLIN | EPOLLOUT | EPOLLET;
          event.data.ptr = connection;
          if (0 != epoll_ctl (daemon->events.data.epoll.e_fd,
                              EPOLL_CTL_ADD,
                              connection->socket_fd,
                              &event))
          {
            mhd_LOG_MSG (daemon, MHD_SC_EPOLL_CTL_ADD_FAILED,
                         "Failed to add connection socket to epoll.");
            res = MHD_SC_EPOLL_CTL_ADD_FAILED;
          }
          else
          {
            if (0) // TODO: implement turbo
            {
              connection->sk_ready = mhd_SOCKET_NET_STATE_RECV_READY
                                     | mhd_SOCKET_NET_STATE_SEND_READY;
              mhd_conn_mark_ready (connection, daemon);
            }
            return MHD_SC_OK;  /* *** Function success exit point *** */
          }
        }
        else /* No 'epoll' */
#endif /* MHD_USE_EPOLL */
        return MHD_SC_OK;    /* *** Function success exit point *** */
      }

      /* ** Below is a cleanup path ** */
      mhd_assert (MHD_SC_OK != res);
      notify_app_conn (daemon, connection, true);

      if (mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION != daemon->wmode_int)
        mhd_DLINKEDL_DEL_D (&(daemon->conns.def_timeout), \
                            connection, by_timeout);

      mhd_DLINKEDL_DEL (&(daemon->conns), connection, all_conn);
      daemon->conns.count--;
      daemon->conns.block_new = false;
    }
    mhd_pool_destroy (connection->pool);
  }
  /* Free resources allocated before the call of this functions */

  // TODO: TLS support

  // TODO: per IP limit

  if (NULL != connection->addr)
    free (connection->addr);
  (void) mhd_socket_close (connection->socket_fd);
  free (connection);
  mhd_assert (MHD_SC_OK != res);
  return res;  /* *** Function failure exit point *** */
}


/**
 * The given client socket will be managed (and closed!) by MHD after
 * this call and must no longer be used directly by the application
 * afterwards.
 *
 * @param daemon daemon that manages the connection
 * @param client_socket socket to manage (MHD will expect
 *        to receive an HTTP request from this socket next).
 * @param addr IP address of the client
 * @param addrlen number of bytes in @a addr
 * @param external_add perform additional operations needed due
 *        to the application calling us directly
 * @param non_blck indicate that socket in non-blocking mode
 * @param sk_spipe_supprs indicate that the @a client_socket has
 *                         set SIGPIPE suppression
 * @param sk_is_nonip _MHD_YES if this is not a TCP/IP socket
 * @return #MHD_YES on success, #MHD_NO if this daemon could
 *        not handle the connection (i.e. malloc failed, etc).
 *        The socket will be closed in any case; 'errno' is
 *        set to indicate further details about the error.
 */
static enum MHD_StatusCode
internal_add_connection (struct MHD_Daemon *daemon,
                         MHD_Socket client_socket,
                         const struct sockaddr_storage *addr,
                         size_t addrlen,
                         bool external_add,
                         bool non_blck,
                         bool sk_spipe_supprs,
                         enum mhd_Tristate sk_is_nonip)
{
  struct MHD_Connection *connection;
  enum MHD_StatusCode res;

  /* Direct add to master daemon could never happen. */
  mhd_assert (! mhd_D_HAS_WORKERS (daemon));
  mhd_assert (mhd_FD_FITS_DAEMON (daemon, client_socket));

  if ((! non_blck) &&
      ((mhd_POLL_TYPE_EPOLL == daemon->events.poll_type) ||
       (mhd_WM_INT_EXTERNAL_EVENTS_EDGE == daemon->wmode_int)))
  {
    mhd_LOG_MSG (daemon, MHD_SC_NONBLOCKING_REQUIRED, \
                 "The daemon configuration requires non-blocking sockets, "
                 "the new socket has not been added.");
    (void) mhd_socket_close (client_socket);
    return MHD_SC_NONBLOCKING_REQUIRED;
  }
  res = new_connection_prepare_ (daemon,
                                 client_socket,
                                 addr, addrlen,
                                 external_add,
                                 non_blck,
                                 sk_spipe_supprs,
                                 sk_is_nonip,
                                 &connection);
  if (MHD_SC_OK != res)
    return res;

  if (external_add) // TODO: support thread-unsafe
  {
    mhd_assert (0 && "Not implemented yet");
#if 0 // TODO: support externally added
    /* Connection is added externally and MHD is thread safe mode. */
    MHD_mutex_lock_chk_ (&daemon->new_connections_mutex);
    DLL_insert (daemon->new_connections_head,
                daemon->new_connections_tail,
                connection);
    daemon->have_new = true;
    MHD_mutex_unlock_chk_ (&daemon->new_connections_mutex);

    /* The rest of connection processing must be handled in
     * the daemon thread. */
    if ((mhd_ITC_IS_VALID (daemon->itc)) &&
        (! mhd_itc_activate (daemon->itc, "n")))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _ ("Failed to signal new connection via inter-thread " \
                   "communication channel.\n"));
#endif
    }
    return MHD_YES;
#endif
  }

  return new_connection_process_ (daemon, connection);
}


#if 0 // TODO: implement
static void
new_connections_list_process_ (struct MHD_Daemon *daemon)
{
  struct MHD_Connection *local_head;
  struct MHD_Connection *local_tail;
  mhd_assert (daemon->events.act_req);
  // mhd_assert (MHD_D_IS_THREAD_SAFE_ (daemon));

  /* Detach DL-list of new connections from the daemon for
   * following local processing. */
  MHD_mutex_lock_chk_ (&daemon->new_connections_mutex);
  mhd_assert (NULL != daemon->new_connections_head);
  local_head = daemon->new_connections_head;
  local_tail = daemon->new_connections_tail;
  daemon->new_connections_head = NULL;
  daemon->new_connections_tail = NULL;
  daemon->have_new = false;
  MHD_mutex_unlock_chk_ (&daemon->new_connections_mutex);
  (void) local_head; /* Mute compiler warning */

  /* Process new connections in FIFO order. */
  do
  {
    struct MHD_Connection *c;   /**< Currently processed connection */

    c = local_tail;
    DLL_remove (local_head,
                local_tail,
                c);
    mhd_assert (daemon == c->daemon);
    if (MHD_NO == new_connection_process_ (daemon, c))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _ ("Failed to start serving new connection.\n"));
#endif
      (void) 0;
    }
  } while (NULL != local_tail);

}


#endif


MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_IN_ (4) MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_add_connection (struct MHD_Daemon *daemon,
                           MHD_Socket client_socket,
                           size_t addrlen,
                           const struct sockaddr *addr,
                           void *connection_cntx)
{
  bool sk_nonbl;
  bool sk_spipe_supprs;
  struct sockaddr_storage addrstorage;
  // TODO: global daemon lock for external events
  (void) connection_cntx; // FIXME: is it really needed? Where it is used?

  if ((! mhd_D_HAS_THREADS (daemon)) &&
      (daemon->conns.block_new))
    (void) 0; // FIXME: remove already pending connections?

  if (! mhd_D_TYPE_HAS_WORKERS (daemon->threading.d_type)
      && daemon->conns.block_new)
  {
    (void) mhd_socket_close (client_socket);
    return MHD_SC_LIMIT_CONNECTIONS_REACHED;
  }

  if (0 != addrlen)
  {
    if (AF_INET == addr->sa_family)
    {
      if (sizeof(struct sockaddr_in) > addrlen)
      {
        mhd_LOG_MSG (daemon, MHD_SC_CONFIGURATION_WRONG_SA_SIZE, \
                     "MHD_add_connection() has been called with " \
                     "incorrect 'addrlen' value.");
        (void) mhd_socket_close (client_socket);
        return MHD_SC_CONFIGURATION_WRONG_SA_SIZE;
      }
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
      if ((0 != addr->sa_len) &&
          (sizeof(struct sockaddr_in) > (size_t) addr->sa_len) )
      {
        mhd_LOG_MSG (daemon, MHD_SC_CONFIGURATION_WRONG_SA_SIZE, \
                     "MHD_add_connection() has been called with " \
                     "non-zero value of 'sa_len' member of " \
                     "'struct sockaddr' which does not match 'sa_family'.");
        (void) mhd_socket_close (client_socket);
        return MHD_SC_CONFIGURATION_WRONG_SA_SIZE;
      }
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
    }
#ifdef HAVE_INET6
    if (AF_INET6 == addr->sa_family)
    {
      if (sizeof(struct sockaddr_in6) > addrlen)
      {
        mhd_LOG_MSG (daemon, MHD_SC_CONFIGURATION_WRONG_SA_SIZE, \
                     "MHD_add_connection() has been called with " \
                     "incorrect 'addrlen' value.");
        (void) mhd_socket_close (client_socket);
        return MHD_SC_CONFIGURATION_WRONG_SA_SIZE;
      }
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
      if ((0 != addr->sa_len) &&
          (sizeof(struct sockaddr_in6) > (size_t) addr->sa_len) )
      {
        mhd_LOG_MSG (daemon, MHD_SC_CONFIGURATION_WRONG_SA_SIZE, \
                     "MHD_add_connection() has been called with " \
                     "non-zero value of 'sa_len' member of " \
                     "'struct sockaddr' which does not match 'sa_family'.");
        (void) mhd_socket_close (client_socket);
        return MHD_SC_CONFIGURATION_WRONG_SA_SIZE;
      }
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
    }
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
    if ((0 != addr->sa_len) &&
        (addrlen > (size_t) addr->sa_len))
      addrlen = (size_t) addr->sa_len;   /* Use safest value */
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
#endif /* HAVE_INET6 */
  }

  if (! mhd_FD_FITS_DAEMON (daemon, client_socket))
  {
    mhd_LOG_MSG (daemon, MHD_SC_NEW_CONN_FD_OUTSIDE_OF_SET_RANGE, \
                 "The new connection FD value is higher than allowed");
    (void) mhd_socket_close (client_socket);
    return MHD_SC_NEW_CONN_FD_OUTSIDE_OF_SET_RANGE;
  }

  if (! mhd_socket_nonblocking (client_socket))
  {
    mhd_LOG_MSG (daemon, MHD_SC_ACCEPT_CONFIGURE_NONBLOCKING_FAILED, \
                 "Failed to set nonblocking mode on the new client socket.");
    sk_nonbl = false;
  }
  else
    sk_nonbl = true;

#ifndef MHD_WINSOCK_SOCKETS
  sk_spipe_supprs = false;
#else  /* MHD_WINSOCK_SOCKETS */
  sk_spipe_supprs = true; /* Nothing to suppress on W32 */
#endif /* MHD_WINSOCK_SOCKETS */
#if defined(MHD_socket_nosignal_)
  if (! sk_spipe_supprs)
    sk_spipe_supprs = MHD_socket_nosignal_ (client_socket);
  if (! sk_spipe_supprs)
  {
    mhd_LOG_MSG (daemon, MHD_SC_ACCEPT_CONFIGURE_NOSIGPIPE_FAILED, \
                 "Failed to suppress SIGPIPE on the new client socket.");
#ifndef MSG_NOSIGNAL
    /* Application expects that SIGPIPE will be suppressed,
     * but suppression failed and SIGPIPE cannot be suppressed with send(). */
    if (! daemon->sigpipe_blocked)
    {
      int err = MHD_socket_get_error_ ();
      MHD_socket_close_ (client_socket);
      MHD_socket_fset_error_ (err);
      return MHD_SC_ACCEPT_CONFIGURE_NOSIGPIPE_FAILED;
    }
#endif /* MSG_NOSIGNAL */
  }
#endif /* MHD_socket_nosignal_ */

  if (1) // TODO: implement turbo
  {
    if (! mhd_socket_noninheritable (client_socket))
      mhd_LOG_MSG (daemon, MHD_SC_ACCEPT_CONFIGURE_NOINHERIT_FAILED, \
                   "Failed to set noninheritable mode on new client socket.");
  }

  /* Copy to sockaddr_storage structure to avoid alignment problems */
  if (0 < addrlen)
    memcpy (&addrstorage, addr, addrlen);
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
  addrstorage.ss_len = addrlen; /* Force set the right length */
#endif /* HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN */

#if defined(MHD_USE_THREADS)
  if (mhd_D_TYPE_HAS_WORKERS (daemon->threading.d_type))
  {
    unsigned int i;
    /* have a pool, try to find a pool with capacity; we use the
       socket as the initial offset into the pool for load
       balancing */
    unsigned int offset;
#ifdef MHD_WINSOCK_SOCKETS
    uint_fast64_t osb = (uint_fast64_t) client_socket;
    osb ^= (((uint_fast64_t) client_socket) >> 9);
    osb ^= (((uint_fast64_t) client_socket) >> 18);
    osb ^= (((uint_fast64_t) client_socket) >> 27);
    osb ^= (((uint_fast64_t) client_socket) >> 36);
    osb ^= (((uint_fast64_t) client_socket) >> 45);
    osb ^= (((uint_fast64_t) client_socket) >> 54);
    osb ^= (((uint_fast64_t) client_socket) >> 63);
    offset = (unsigned int) osb;
#else
    offset = (unsigned int) client_socket;
#endif

    for (i = 0; i < daemon->threading.hier.pool.num; ++i)
    {
      struct MHD_Daemon *const restrict worker =
        daemon->threading.hier.pool.workers
        + (i + offset) % daemon->threading.hier.pool.num;
      if (worker->conns.block_new)
        continue;
      return internal_add_connection (worker,
                                      client_socket,
                                      &addrstorage,
                                      addrlen,
                                      true,
                                      sk_nonbl,
                                      sk_spipe_supprs,
                                      mhd_T_MAYBE);
    }

    /* all pools are at their connection limit, must refuse */
    (void) mhd_socket_close (client_socket);
    return MHD_SC_LIMIT_CONNECTIONS_REACHED;
  }
#endif /* MHD_USE_THREADS */

  return internal_add_connection (daemon,
                                  client_socket,
                                  &addrstorage,
                                  addrlen,
                                  true,
                                  sk_nonbl,
                                  sk_spipe_supprs,
                                  mhd_T_MAYBE);
}


MHD_INTERNAL enum mhd_DaemonAcceptResult
mhd_daemon_accept_connection (struct MHD_Daemon *restrict daemon)
{
  struct sockaddr_storage addrstorage;
  socklen_t addrlen;
  MHD_Socket s;
  MHD_Socket fd;
  bool sk_nonbl;
  bool sk_spipe_supprs;
  bool sk_cloexec;
  enum mhd_Tristate sk_non_ip;
#if defined(_DEBUG) && defined (USE_ACCEPT4)
  const bool use_accept4 = ! daemon->dbg.avoid_accept4;
#elif defined (USE_ACCEPT4)
  static const bool use_accept4 = true;
#else  /* ! USE_ACCEPT4 && ! _DEBUG */
  static const bool use_accept4 = false;
#endif /* ! USE_ACCEPT4 && ! _DEBUG */

#ifdef MHD_USE_THREADS
  mhd_assert ((! mhd_D_HAS_THREADS (daemon)) || \
              mhd_thread_handle_ID_is_current_thread (daemon->threading.tid));
  mhd_assert (! mhd_D_TYPE_HAS_WORKERS (daemon->threading.d_type));
#endif /* MHD_USE_THREADS */

  fd = daemon->net.listen.fd;
  mhd_assert (MHD_INVALID_SOCKET != fd);

  addrlen = (socklen_t) sizeof (addrstorage);
  memset (&addrstorage,
          0,
          (size_t) addrlen);
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
  addrstorage.ss_len = addrlen;
#endif /* HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN */

  /* Initialise with default values to avoid compiler warnings */
  sk_nonbl = false;
  sk_spipe_supprs = false;
  sk_cloexec = false;
  s = MHD_INVALID_SOCKET;

#ifdef USE_ACCEPT4
  if (use_accept4 &&
      (MHD_INVALID_SOCKET !=
       (s = accept4 (fd,
                     (struct sockaddr *) &addrstorage,
                     &addrlen,
                     SOCK_CLOEXEC_OR_ZERO | SOCK_NONBLOCK_OR_ZERO
                     | SOCK_NOSIGPIPE_OR_ZERO))))
  {
    sk_nonbl = (SOCK_NONBLOCK_OR_ZERO != 0);
#ifndef MHD_WINSOCK_SOCKETS
    sk_spipe_supprs = (SOCK_NOSIGPIPE_OR_ZERO != 0);
#else  /* MHD_WINSOCK_SOCKETS */
    sk_spipe_supprs = true; /* Nothing to suppress on W32 */
#endif /* MHD_WINSOCK_SOCKETS */
    sk_cloexec = (SOCK_CLOEXEC_OR_ZERO != 0);
  }
#endif /* USE_ACCEPT4 */
#if defined(_DEBUG) || ! defined(USE_ACCEPT4)
  if (! use_accept4 &&
      (MHD_INVALID_SOCKET !=
       (s = accept (fd,
                    (struct sockaddr *) &addrstorage,
                    &addrlen))))
  {
#ifdef MHD_ACCEPT_INHERIT_NONBLOCK
    sk_nonbl = daemon->listen_nonblk;
#else  /* ! MHD_ACCEPT_INHERIT_NONBLOCK */
    sk_nonbl = false;
#endif /* ! MHD_ACCEPT_INHERIT_NONBLOCK */
#ifndef MHD_WINSOCK_SOCKETS
    sk_spipe_supprs = false;
#else  /* MHD_WINSOCK_SOCKETS */
    sk_spipe_supprs = true; /* Nothing to suppress on W32 */
#endif /* MHD_WINSOCK_SOCKETS */
    sk_cloexec = false;
  }
#endif /* _DEBUG || !USE_ACCEPT4 */

  if (MHD_INVALID_SOCKET == s)
  { /* This could be a common occurrence with multiple worker threads */
    const int err = mhd_SCKT_GET_LERR ();

    if (mhd_SCKT_ERR_IS_EINVAL (err))
      return mhd_DAEMON_ACCEPT_NO_MORE_PENDING; /* can happen during shutdown */   // FIXME: remove?
    if (mhd_SCKT_ERR_IS_DISCNN_BEFORE_ACCEPT (err))
      return mhd_DAEMON_ACCEPT_NO_MORE_PENDING;   /* do not print error if client just disconnects early */
    if (mhd_SCKT_ERR_IS_EINTR (err))
      return mhd_DAEMON_ACCEPT_SKIPPED;
    if (mhd_SCKT_ERR_IS_EAGAIN (err))
      return mhd_DAEMON_ACCEPT_NO_MORE_PENDING;
    if (mhd_SCKT_ERR_IS_LOW_RESOURCES (err) )
    {
      /* system/process out of resources */
      if (0 == daemon->conns.count)
      {
        /* Not setting 'block_new' flag, as there is no way it
           would ever be cleared.  Instead trying to produce
           bit fat ugly warning. */
        mhd_LOG_MSG (daemon, MHD_SC_ACCEPT_SYSTEM_LIMIT_REACHED_INSTANTLY, \
                     "Hit process or system resource limit at FIRST " \
                     "connection. This is really bad as there is no sane " \
                     "way to proceed. Will try busy waiting for system " \
                     "resources to become magically available.");
      }
      else
      {
        daemon->conns.block_new = true;
        mhd_LOG_PRINT (daemon, MHD_SC_ACCEPT_SYSTEM_LIMIT_REACHED, \
                       mhd_LOG_FMT ("Hit process or system resource limit " \
                                    "at %u connections, temporarily " \
                                    "suspending accept(). Consider setting " \
                                    "a lower MHD_OPTION_CONNECTION_LIMIT."), \
                       daemon->conns.count);
      }
      return mhd_DAEMON_ACCEPT_FAILED;
    }
    mhd_LOG_MSG (daemon, MHD_SC_ACCEPT_FAILED_UNEXPECTEDLY,
                 "Error accepting connection.");
    return mhd_DAEMON_ACCEPT_FAILED;
  }

  if (! mhd_FD_FITS_DAEMON (daemon, s))
  {
    mhd_LOG_MSG (daemon, MHD_SC_ACCEPT_OUTSIDE_OF_SET_RANGE, \
                 "The accepted socket has value outside of allowed range.");
    (void) mhd_socket_close (s);
    return mhd_DAEMON_ACCEPT_FAILED;
  }
  if (mhd_SOCKET_TYPE_IP == daemon->net.listen.type)
    sk_non_ip = mhd_T_NO;
  else if (mhd_SOCKET_TYPE_UNKNOWN == daemon->net.listen.type)
    sk_non_ip = mhd_T_MAYBE;
  else
    sk_non_ip = mhd_T_YES;
  if (0 >= addrlen)
  {
    if (mhd_SOCKET_TYPE_IP == daemon->net.listen.type)
      mhd_LOG_MSG (daemon, MHD_SC_ACCEPTED_UNKNOWN_TYPE, \
                   "Accepted socket has non-positive length of the address. " \
                   "Processing the new socket as a socket with " \
                   "unknown type.");
    addrlen = 0;
    sk_non_ip = mhd_T_MAYBE;
  }
  else if (((socklen_t) sizeof (addrstorage)) < addrlen)
  {
    /* Should not happen as 'sockaddr_storage' must be large enough to
     * store any address supported by the system. */
    mhd_LOG_MSG (daemon, MHD_SC_ACCEPTED_SOCKADDR_TOO_LARGE, \
                 "Accepted socket address is larger than expected by " \
                 "system headers. Processing the new socket as a socket with " \
                 "unknown type.");
    addrlen = 0;
    sk_non_ip = mhd_T_MAYBE; /* IP-type addresses must fit */
  }
  else if (mhd_T_MAYBE == sk_non_ip)
  {
    if (AF_INET == ((struct sockaddr *) &addrstorage)->sa_family)
      sk_non_ip = mhd_T_NO;
#ifdef HAVE_INET6
    else if (AF_INET6 == ((struct sockaddr *) &addrstorage)->sa_family)
      sk_non_ip = mhd_T_NO;
#endif /* HAVE_INET6 */
  }

  if (! sk_nonbl && ! mhd_socket_nonblocking (s))
  {
    mhd_LOG_MSG (daemon, MHD_SC_ACCEPT_CONFIGURE_NONBLOCKING_FAILED, \
                 "Failed to set nonblocking mode on incoming connection " \
                 "socket.");
  }
  else
    sk_nonbl = true;

  if (! sk_cloexec && ! mhd_socket_noninheritable (s))
  {
    mhd_LOG_MSG (daemon, MHD_SC_ACCEPT_CONFIGURE_NOINHERIT_FAILED, \
                 "Failed to set non-inheritable mode on incoming connection " \
                 "socket.");
  }

#if defined(MHD_socket_nosignal_)
  if (! sk_spipe_supprs && ! MHD_socket_nosignal_ (s))
  {
    mhd_LOG_MSG (daemon, MHD_SC_ACCEPT_CONFIGURE_NOSIGPIPE_FAILED,
                 "Failed to suppress SIGPIPE on incoming connection " \
                 "socket.");
#ifndef MSG_NOSIGNAL
    /* Application expects that SIGPIPE will be suppressed,
     * but suppression failed and SIGPIPE cannot be suppressed with send(). */
    if (! daemon->sigpipe_blocked)
    {
      (void) MHD_socket_close_ (s);
      return MHD_NO;
    }
#endif /* MSG_NOSIGNAL */
  }
  else
    sk_spipe_supprs = true;
#endif /* MHD_socket_nosignal_ */
  return (MHD_SC_OK == internal_add_connection (daemon,
                                                s,
                                                &addrstorage,
                                                (size_t) addrlen,
                                                false,
                                                sk_nonbl,
                                                sk_spipe_supprs,
                                                sk_non_ip)) ?
         mhd_DAEMON_ACCEPT_SUCCESS : mhd_DAEMON_ACCEPT_FAILED;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_conn_close_final (struct MHD_Connection *restrict c)
{
  mhd_assert (c->dbg.pre_closed);
  mhd_assert (c->dbg.pre_cleaned);
  mhd_assert (NULL == c->rp.response);
  mhd_assert (! c->rq.app_aware);
  mhd_assert (! c->in_proc_ready);
  mhd_assert (NULL == mhd_DLINKEDL_GET_NEXT (c, proc_ready));
  mhd_assert (NULL == mhd_DLINKEDL_GET_PREV (c, proc_ready));
  mhd_assert (c != mhd_DLINKEDL_GET_FIRST (&(c->daemon->events), proc_ready));
  mhd_assert (c != mhd_DLINKEDL_GET_LAST (&(c->daemon->events), proc_ready));

  if (mhd_D_HAS_THR_PER_CONN (c->daemon))
  {
    mhd_assert (0 && "Not implemented yet");
    // TODO: Support "thread per connection"
  }
  mhd_assert (NULL == mhd_DLINKEDL_GET_NEXT (c, by_timeout));
  mhd_assert (NULL == mhd_DLINKEDL_GET_PREV (c, by_timeout));
  mhd_assert (NULL == c->pool);

  mhd_DLINKEDL_DEL (&(c->daemon->conns), c, all_conn);

  // TODO: update per-IP limits
  if (NULL != c->addr)
    free (c->addr);
  mhd_socket_close (c->socket_fd);

  c->daemon->conns.count--;
  c->daemon->conns.block_new = false;

  free (c);
}
