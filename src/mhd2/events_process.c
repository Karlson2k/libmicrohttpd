/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/events_process.c
 * @brief  The implementation of events processing functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"
#include "events_process.h"

#include "mhd_socket_type.h"
#include "sys_poll.h"
#include "sys_select.h"
#ifdef MHD_USE_EPOLL
#  include <sys/epoll.h>
#endif
#ifdef MHD_POSIX_SOCKETS
#  include "sys_errno.h"
#endif

#include "mhd_itc.h"

#include "mhd_panic.h"

#include "mhd_sockets_macros.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"

#include "conn_mark_ready.h"
#include "daemon_logger.h"
#include "daemon_add_conn.h"
#include "daemon_funcs.h"
#include "conn_data_process.h"
#include "stream_funcs.h"

#include "mhd_public_api.h"

static int
get_max_wait (struct MHD_Daemon *restrict d)
{
  bool zero_wait = d->events.zero_wait;
  if (d->events.act_req.accept && d->conns.block_new)
    d->events.act_req.accept = false;

  d->events.zero_wait = false; /* Reset as this pending data will be processed */
  if (d->events.act_req.accept)
    return 0;
  if (zero_wait)
    return 0;
  if (NULL != mhd_DLINKEDL_GET_FIRST (&(d->events), proc_ready))
    return 0;

  return INT_MAX; // TODO: calculate correct timeout value
}


MHD_FN_PAR_NONNULL_ (1) static void
update_conn_net_status (struct MHD_Daemon *restrict d,
                        struct MHD_Connection *restrict c,
                        bool recv_ready,
                        bool send_ready,
                        bool err_state)
{
  enum mhd_SocketNetState sk_state;

  mhd_assert (d == c->daemon);

  sk_state = mhd_SOCKET_NET_STATE_NOTHING;
  if (recv_ready)
    sk_state = (enum mhd_SocketNetState)
               (sk_state | (unsigned int) mhd_SOCKET_NET_STATE_RECV_READY);
  if (send_ready)
    sk_state = (enum mhd_SocketNetState)
               (sk_state | (unsigned int) mhd_SOCKET_NET_STATE_SEND_READY);
  if (err_state)
    sk_state = (enum mhd_SocketNetState)
               (sk_state | (unsigned int) mhd_SOCKET_NET_STATE_ERROR_READY);
  c->sk_ready = sk_state;

  if ((0 !=
       (((unsigned int) c->sk_ready) & ((unsigned int) c->event_loop_info)
        & (MHD_EVENT_LOOP_INFO_READ | MHD_EVENT_LOOP_INFO_WRITE)))
      || err_state)
    mhd_conn_mark_ready (c, d);
  else
    mhd_conn_mark_unready (c, d);
}


/**
 * Accept new connections on the daemon
 * @param d the daemon to use
 * @return true if all incoming connections has been accepted,
 *         false if some connection may still wait to be accepted
 */
MHD_FN_PAR_NONNULL_ (1) static bool
daemon_accept_new_conns (struct MHD_Daemon *restrict d)
{
  unsigned int num_to_accept;
  mhd_assert (MHD_INVALID_SOCKET != d->net.listen.fd);
  mhd_assert (! d->conns.block_new);
  mhd_assert (d->conns.count < d->conns.cfg.count_limit);
  mhd_assert (! mhd_D_HAS_WORKERS (d));

  if (! d->net.listen.non_block)
    num_to_accept = 1; /* listen socket is blocking, only one connection can be processed */
  else
  {
    const unsigned int slots_left = d->conns.cfg.count_limit - d->conns.count;
    if (! mhd_D_HAS_MASTER (d))
    {
      /* Fill up to one quarter of allowed limit in one turn */
      num_to_accept = d->conns.cfg.count_limit / 4;
      /* Limit to a reasonable number */
      if (((sizeof(void *) > 4) ? 4096 : 1024) < num_to_accept)
        num_to_accept = ((sizeof(void *) > 4) ? 4096 : 1024);
      if (slots_left < num_to_accept)
        num_to_accept = slots_left;
    }
#ifdef MHD_USE_THREADS
    else
    {
      /* Has workers thread pool. Care must be taken to evenly distribute
         new connections in the workers pool.
         At the same time, the burst of new connections should be handled as
         quick as possible. */
      const unsigned int num_conn = d->conns.count;
      const unsigned int limit = d->conns.cfg.count_limit;
      const unsigned int num_workers =
        d->threading.hier.master->threading.hier.pool.num;
      if (num_conn < limit / 16)
      {
        num_to_accept = num_conn / num_workers;
        if (8 > num_to_accept)
        {
          if (8 > slots_left / 16)
            num_to_accept = slots_left / 16;
          else
            num_to_accept = 8;
        }
        if (64 < num_to_accept)
          num_to_accept = 64;
      }
      else if (num_conn < limit / 8)
      {
        num_to_accept = num_conn * 2 / num_workers;
        if (8 > num_to_accept)
        {
          if (8 > slots_left / 8)
            num_to_accept = slots_left / 8;
          else
            num_to_accept = 8;
        }
        if (128 < num_to_accept)
          num_to_accept = 128;
      }
      else if (num_conn < limit / 4)
      {
        num_to_accept = num_conn * 4 / num_workers;
        if (8 > num_to_accept)
          num_to_accept = 8;
        if (slots_left / 4 < num_to_accept)
          num_to_accept = slots_left / 4;
        if (256 < num_to_accept)
          num_to_accept = 256;
      }
      else if (num_conn < limit / 2)
      {
        num_to_accept = num_conn * 8 / num_workers;
        if (16 > num_to_accept)
          num_to_accept = 16;
        if (slots_left / 4 < num_to_accept)
          num_to_accept = slots_left / 4;
        if (256 < num_to_accept)
          num_to_accept = 256;
      }
      else if (slots_left > limit / 4)
      {
        num_to_accept = slots_left * 4 / num_workers;
        if (slots_left / 8 < num_to_accept)
          num_to_accept = slots_left / 8;
        if (128 < num_to_accept)
          num_to_accept = 128;
      }
      else if (slots_left > limit / 8)
      {
        num_to_accept = slots_left * 2 / num_workers;
        if (slots_left / 16 < num_to_accept)
          num_to_accept = slots_left / 16;
        if (64 < num_to_accept)
          num_to_accept = 64;
      }
      else /* (slots_left <= limit / 8) */
        num_to_accept = slots_left / 16;

      if (0 == num_to_accept)
        num_to_accept = 1;
      else if (slots_left > num_to_accept)
        num_to_accept = slots_left;
    }
#endif /* MHD_USE_THREADS */
  }

  while (0 != --num_to_accept)
  {
    enum mhd_DaemonAcceptResult res;
    res = mhd_daemon_accept_connection (d);
    if (mhd_DAEMON_ACCEPT_NO_MORE_PENDING == res)
      return true;
    if (mhd_DAEMON_ACCEPT_FAILED == res)
      break;
  }
  return false;
}


static bool
daemon_process_all_active_conns (struct MHD_Daemon *restrict d)
{
  struct MHD_Connection *c;
  mhd_assert (! mhd_D_HAS_WORKERS (d));

  c = mhd_DLINKEDL_GET_FIRST (&(d->events),proc_ready);
  while (NULL != c)
  {
    struct MHD_Connection *next;
    next = mhd_DLINKEDL_GET_NEXT (c, proc_ready); /* The current connection can be closed */
    if (! mhd_conn_process_recv_send_data (c))
      mhd_conn_close_final (c);

    c = next;
  }
  return true;
}


static void
close_all_daemon_conns (struct MHD_Daemon *d)
{
  struct MHD_Connection *c;

  for (c = mhd_DLINKEDL_GET_LAST (&(d->conns),all_conn);
       NULL != c;
       c = mhd_DLINKEDL_GET_LAST (&(d->conns),all_conn))
  {
    mhd_conn_pre_close_d_shutdown (c);
    mhd_conn_close_final (c);
  }
}


#ifdef MHD_USE_SELECT

/**
 * Add socket to the fd_set
 * @param fd the socket to add
 * @param fs the pointer to fd_set
 * @param max the pointer to variable to be updated with maximum FD value (or
 *            set to non-zero in case of WinSock)
 * @param d the daemon object
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (2)
MHD_FN_PAR_INOUT_ (3) void
fd_set_wrap (MHD_Socket fd,
             fd_set *restrict fs,
             int *restrict max,
             struct MHD_Daemon *restrict d)
{
  mhd_assert (mhd_FD_FITS_DAEMON (d, fd)); /* Must be checked for every FD before
                                              it is added */
  mhd_assert (mhd_POLL_TYPE_SELECT == d->events.poll_type);
  (void) d; /* Unused with non-debug builds */
#if defined(MHD_POSIX_SOCKETS)
  FD_SET (fd, fs);
  if (*max < fd)
    *max = fd;
#elif defined(MHD_WINSOCK_SOCKETS)
  /* Use custom set function to take advantage of know uniqueness of
   * used sockets (to skip useless (for this function) check for duplicated
   * sockets implemented in system's macro). */
  mhd_assert (fs->fd_count < FD_SETSIZE - 1); /* Daemon limits set to always fit FD_SETSIZE */
  mhd_assert (! FD_ISSET (fd, fs)); /* All sockets must be unique */
  fs->fd_array[fs->fd_count++] = fd;
  *max = 1;
#else
#error Unknown sockets type
#endif
}


/**
 * Set daemon's FD_SETs to monitor all daemon's sockets
 * @param d the daemon to use
 * @param listen_only set to 'true' if connections's sockets should NOT
 *                    be monitored
 * @return with POSIX sockets: the maximum number of the socket used in
 *                             the FD_SETs;
 *         with winsock: non-zero if at least one socket has been added to
 *                       the FD_SETs,
 *                       zero if no sockets in the FD_SETs
 */
static MHD_FN_PAR_NONNULL_ (1) int
select_update_fdsets (struct MHD_Daemon *restrict d,
                      bool listen_only)
{
  struct MHD_Connection *c;
  fd_set *const restrict rfds = d->events.data.select.rfds;
  fd_set *const restrict wfds = d->events.data.select.wfds;
  fd_set *const restrict efds = d->events.data.select.efds;
  int ret;

  mhd_assert (mhd_POLL_TYPE_SELECT == d->events.poll_type);
  mhd_assert (NULL != rfds);
  mhd_assert (NULL != wfds);
  mhd_assert (NULL != efds);
  FD_ZERO (rfds);
  FD_ZERO (wfds);
  FD_ZERO (efds);

  ret = 0;
#ifdef MHD_USE_THREADS
  mhd_assert (mhd_ITC_IS_VALID (d->threading.itc));
  fd_set_wrap (mhd_itc_r_fd (d->threading.itc),
               rfds,
               &ret,
               d);
  fd_set_wrap (mhd_itc_r_fd (d->threading.itc),
               efds,
               &ret,
               d);
#endif
  if (MHD_INVALID_SOCKET != d->net.listen.fd)
  {
    fd_set_wrap (d->net.listen.fd,
                 rfds,
                 &ret,
                 d);
    fd_set_wrap (d->net.listen.fd,
                 efds,
                 &ret,
                 d);
  }
  if (listen_only)
    return ret;

  for (c = mhd_DLINKEDL_GET_FIRST (&(d->conns),all_conn); NULL != c;
       c = mhd_DLINKEDL_GET_NEXT (c,all_conn))
  {
    mhd_assert (MHD_CONNECTION_CLOSED != c->state);

    if (0 != (c->event_loop_info & MHD_EVENT_LOOP_INFO_READ))
      fd_set_wrap (c->socket_fd,
                   rfds,
                   &ret,
                   d);
    if (0 != (c->event_loop_info & MHD_EVENT_LOOP_INFO_WRITE))
      fd_set_wrap (c->socket_fd,
                   wfds,
                   &ret,
                   d);
    fd_set_wrap (c->socket_fd,
                 efds,
                 &ret,
                 d);
  }

  return ret;
}


static MHD_FN_PAR_NONNULL_ (1) bool
select_update_statuses_from_fdsets (struct MHD_Daemon *d,
                                    int num_events)
{
  struct MHD_Connection *c;
  fd_set *const restrict rfds = d->events.data.select.rfds;
  fd_set *const restrict wfds = d->events.data.select.wfds;
  fd_set *const restrict efds = d->events.data.select.efds;

  mhd_assert (mhd_POLL_TYPE_SELECT == d->events.poll_type);
  mhd_assert (0 <= num_events);
  mhd_assert (((unsigned int) num_events) <= d->dbg.num_events_elements);

#ifndef MHD_FAVOR_SMALL_CODE
  if (0 == num_events)
    return true;
#endif /* MHD_FAVOR_SMALL_CODE */

#ifdef MHD_USE_THREADS
  mhd_assert (mhd_ITC_IS_VALID (d->threading.itc));
  if (FD_ISSET (mhd_itc_r_fd (d->threading.itc), efds))
  {
    mhd_LOG_MSG (d, MHD_SC_ITC_STATUS_ERROR, \
                 "System reported that ITC has an error status.");
    /* ITC is broken, need to stop the daemon thread now as otherwise
       application will not be able to stop the thread. */
    return false;
  }
  if (FD_ISSET (mhd_itc_r_fd (d->threading.itc), rfds))
  {
    --num_events;
    /* Clear ITC here, as before any other data processing.
     * Any external events may activate ITC again if any data to process is
     * added externally. Cleaning ITC early ensures guaranteed that new data
     * will not be missed. */
    mhd_itc_clear (d->threading.itc);
  }

#ifndef MHD_FAVOR_SMALL_CODE
  if (0 == num_events)
    return true;
#endif /* MHD_FAVOR_SMALL_CODE */
#endif /* MHD_USE_THREADS */

  if (MHD_INVALID_SOCKET != d->net.listen.fd)
  {
    if (FD_ISSET (d->net.listen.fd, efds))
    {
      --num_events;
      mhd_LOG_MSG (d, MHD_SC_ITC_STATUS_ERROR, \
                   "System reported that the listening socket has an error " \
                   "status. The daemon will not listen any more.");
      /* Close the listening socket unless the master daemon should close it */
      if (! mhd_D_HAS_MASTER (d))
        mhd_socket_close (d->net.listen.fd);

      /* Stop monitoring socket to avoid spinning with busy-waiting */
      d->net.listen.fd = MHD_INVALID_SOCKET;
    }
    else if (FD_ISSET (d->net.listen.fd, rfds))
    {
      --num_events;
      d->events.act_req.accept = true;
    }
  }

  mhd_assert ((0 == num_events) || \
              (mhd_DAEMON_TYPE_LISTEN_ONLY != d->threading.d_type));

#ifdef MHD_FAVOR_SMALL_CODE
  (void) num_events;
  num_events = 1; /* Use static value to optimise out the next look */
#endif /* ! MHD_FAVOR_SMALL_CODE */

  for (c = mhd_DLINKEDL_GET_FIRST (&(d->conns), all_conn);
       (NULL != c) && (0 != num_events);
       c = mhd_DLINKEDL_GET_NEXT (c, all_conn))
  {
    const MHD_Socket sk = c->socket_fd;
    bool recv_ready = FD_ISSET (sk, rfds);
    bool send_ready = FD_ISSET (sk, wfds);
    bool err_state = FD_ISSET (sk, efds);

    update_conn_net_status (d,
                            c,
                            recv_ready,
                            send_ready,
                            err_state);
#ifndef MHD_FAVOR_SMALL_CODE
    if (recv_ready || send_ready || err_state)
      --num_events;
#endif /* MHD_FAVOR_SMALL_CODE */
  }

  #ifndef MHD_FAVOR_SMALL_CODE
  mhd_assert (0 == num_events);
#endif /* MHD_FAVOR_SMALL_CODE */
  return true;
}


/**
 * Update states of all connections, check for connection pending
 * to be accept()'ed, check for the events on ITC.
 * @param listen_only set to 'true' if connections's sockets should NOT
 *                    be monitored
 * @return 'true' if processed successfully,
 *         'false' is unrecoverable error occurs and the daemon must be
 *         closed
 */
static MHD_FN_PAR_NONNULL_ (1) bool
get_all_net_updates_by_select (struct MHD_Daemon *restrict d,
                               bool listen_only)
{
  int max_socket;
  int max_wait;
  struct timeval tmvl;
  int num_events;
  mhd_assert (mhd_POLL_TYPE_SELECT == d->events.poll_type);

  max_socket = select_update_fdsets (d,
                                     listen_only);

  max_wait = get_max_wait (d); // TODO: use correct timeout value

#ifdef MHD_WINSOCK_SOCKETS
  if (0 == max_socket)
  {
    Sleep ((unsigned int) max_wait);
    return true;
  }
#endif /* MHD_WINSOCK_SOCKETS */

  tmvl.tv_sec = max_wait / 1000;
#ifndef MHD_WINSOCK_SOCKETS
  tmvl.tv_usec = (uint_least16_t) ((max_wait % 1000) * 1000);
#else
  tmvl.tv_usec = (int) ((max_wait % 1000) * 1000);
#endif

  num_events = select (max_socket + 1,
                       d->events.data.select.rfds,
                       d->events.data.select.wfds,
                       d->events.data.select.efds,
                       &tmvl);

  if (0 > num_events)
  {
    int err;
    bool is_hard_error;
    bool is_ignored_error;
    is_hard_error = false;
    is_ignored_error = false;
#if defined(MHD_POSIX_SOCKETS)
    err = errno;
    if (0 != err)
    {
      is_hard_error =
        ((mhd_EBADF_OR_ZERO == err) || (mhd_EINVAL_OR_ZERO == err));
      is_ignored_error = (mhd_EINTR_OR_ZERO == err);
    }
#elif defined(MHD_WINSOCK_SOCKETS)
    err = WSAGetLastError ();
    is_hard_error =
      ((WSAENETDOWN == err) || (WSAEFAULT == err) || (WSAEINVAL == err) ||
       (WSANOTINITIALISED == err));
#endif
    if (! is_ignored_error)
    {
      if (is_hard_error)
      {
        mhd_LOG_MSG (d, MHD_SC_SELECT_HARD_ERROR, \
                     "The select() encountered unrecoverable error.");
        return false;
      }
      mhd_LOG_MSG (d, MHD_SC_SELECT_SOFT_ERROR, \
                   "The select() encountered error.");
      return true;
    }
  }

  return select_update_statuses_from_fdsets (d, num_events);
}


#endif /* MHD_USE_SELECT */


#ifdef MHD_USE_POLL

static MHD_FN_PAR_NONNULL_ (1) unsigned int
poll_update_fds (struct MHD_Daemon *restrict d,
                 bool listen_only)
{
  unsigned int i_s;
  unsigned int i_c;
  struct MHD_Connection *restrict c;
  mhd_assert (mhd_POLL_TYPE_POLL == d->events.poll_type);

  i_s = 0;
#ifdef MHD_USE_THREADS
  mhd_assert (mhd_ITC_IS_VALID (d->threading.itc));
  mhd_assert (d->events.data.poll.fds[i_s].fd == \
              mhd_itc_r_fd (d->threading.itc));
  mhd_assert (mhd_SOCKET_REL_MARKER_ITC == \
              d->events.data.poll.rel[i_s].fd_id);
  ++i_s;
#endif
  if (MHD_INVALID_SOCKET != d->net.listen.fd)
  {
    mhd_assert (d->events.data.poll.fds[i_s].fd == d->net.listen.fd);
    mhd_assert (mhd_SOCKET_REL_MARKER_LISTEN == \
                d->events.data.poll.rel[i_s].fd_id);
    ++i_s;
  }
  if (listen_only)
    return i_s;

  i_c = i_s;
  for (c = mhd_DLINKEDL_GET_FIRST (&(d->conns),all_conn); NULL != c;
       c = mhd_DLINKEDL_GET_NEXT (c,all_conn))
  {
    unsigned short events; /* 'unsigned' for correct bits manipulations */
    mhd_assert ((i_c - i_s) < d->conns.cfg.count_limit);
    mhd_assert (i_c < d->dbg.num_events_elements);
    mhd_assert (MHD_CONNECTION_CLOSED != c->state);

    d->events.data.poll.fds[i_c].fd = c->socket_fd;
    d->events.data.poll.rel[i_c].connection = c;
    events = 0;
    if (0 != (c->event_loop_info & MHD_EVENT_LOOP_INFO_READ))
      events |= MHD_POLL_IN;
    if (0 != (c->event_loop_info & MHD_EVENT_LOOP_INFO_WRITE))
      events |= MHD_POLL_OUT;

    d->events.data.poll.fds[i_c].events = (short) events;
    ++i_c;
  }
  mhd_assert (d->conns.count == (i_c - i_s));
  mhd_assert (i_c <= d->dbg.num_events_elements);
  return i_c;
}


static MHD_FN_PAR_NONNULL_ (1) bool
poll_update_statuses_from_fds (struct MHD_Daemon *restrict d,
                               int num_events)
{
  unsigned int i_s;
  unsigned int i_c;
  mhd_assert (mhd_POLL_TYPE_POLL == d->events.poll_type);
  mhd_assert (0 <= num_events);
  mhd_assert (((unsigned int) num_events) <= d->dbg.num_events_elements);

  if (0 == num_events)
    return true;

  i_s = 0;
#ifdef MHD_USE_THREADS
  mhd_assert (mhd_ITC_IS_VALID (d->threading.itc));
  mhd_assert (d->events.data.poll.fds[i_s].fd == \
              mhd_itc_r_fd (d->threading.itc));
  mhd_assert (mhd_SOCKET_REL_MARKER_ITC == \
              d->events.data.poll.rel[i_s].fd_id);
  if (0 != (d->events.data.poll.fds[i_s].revents & (POLLERR | POLLNVAL)))
  {
    mhd_LOG_MSG (d, MHD_SC_ITC_STATUS_ERROR, \
                 "System reported that ITC has an error status.");
    /* ITC is broken, need to stop the daemon thread now as otherwise
       application will not be able to stop the thread. */
    return false;
  }
  if (0 != (d->events.data.poll.fds[i_s].revents & (MHD_POLL_IN | POLLIN)))
  {
    --num_events;
    /* Clear ITC here, as before any other data processing.
     * Any external events may activate ITC again if any data to process is
     * added externally. Cleaning ITC early ensures guaranteed that new data
     * will not be missed. */
    mhd_itc_clear (d->threading.itc);
  }
  ++i_s;

  if (0 == num_events)
    return true;
#endif /* MHD_USE_THREADS */

  if (MHD_INVALID_SOCKET != d->net.listen.fd)
  {
    const short revents = d->events.data.poll.fds[i_s].revents;

    mhd_assert (d->events.data.poll.fds[i_s].fd == d->net.listen.fd);
    mhd_assert (mhd_SOCKET_REL_MARKER_LISTEN == \
                d->events.data.poll.rel[i_s].fd_id);
    if (0 != (revents & (POLLERR | POLLNVAL | POLLHUP)))
    {
      --num_events;
      mhd_LOG_MSG (d, MHD_SC_ITC_STATUS_ERROR, \
                   "System reported that the listening socket has an error " \
                   "status. The daemon will not listen any more.");
      /* Close the listening socket unless the master daemon should close it */
      if (! mhd_D_HAS_MASTER (d))
        mhd_socket_close (d->net.listen.fd);

      /* Stop monitoring socket to avoid spinning with busy-waiting */
      d->net.listen.fd = MHD_INVALID_SOCKET;
    }
    else if (0 !=
             (d->events.data.poll.fds[i_s].revents & (MHD_POLL_IN | POLLIN)))
    {
      --num_events;
      d->events.act_req.accept = true;
    }
    ++i_s;
  }

  mhd_assert ((0 == num_events) || \
              (mhd_DAEMON_TYPE_LISTEN_ONLY != d->threading.d_type));

  for (i_c = i_s; (i_c < i_s + d->conns.count) && (0 < num_events); ++i_c)
  {
    struct MHD_Connection *restrict c;
    bool recv_ready;
    bool send_ready;
    bool err_state;
    short revents;
    mhd_assert (i_c < d->dbg.num_events_elements);
    mhd_assert (mhd_SOCKET_REL_MARKER_EMPTY != \
                d->events.data.poll.rel[i_c].fd_id);
    mhd_assert (mhd_SOCKET_REL_MARKER_ITC != \
                d->events.data.poll.rel[i_c].fd_id);
    mhd_assert (mhd_SOCKET_REL_MARKER_LISTEN != \
                d->events.data.poll.rel[i_c].fd_id);

    c = d->events.data.poll.rel[i_c].connection;
    mhd_assert (c->socket_fd == d->events.data.poll.fds[i_c].fd);
    revents = d->events.data.poll.fds[i_c].revents;
    recv_ready = (0 != (revents & (MHD_POLL_IN | POLLIN)));
    send_ready = (0 != (revents & (MHD_POLL_OUT | POLLOUT)));
#ifndef MHD_POLLHUP_ON_REM_SHUT_WR
    err_state = (0 != (revents & (POLLHUP | POLLERR | POLLNVAL)));
#else
    err_state = (0 != (revents & (POLLERR | POLLNVAL)));
    if (0 != (revents & POLLHUP))
    { /* This can be a disconnect OR remote side set SHUT_WR */
      recv_ready = true; /* Check the socket by reading */
      if (0 == (c->event_loop_info & MHD_EVENT_LOOP_INFO_READ))
        err_state = true; /* The socket will not be checked by reading, the only way to avoid spinning */
    }
#endif
    if (0 != (revents & (MHD_POLLPRI | MHD_POLLRDBAND)))
    { /* Statuses were not requested, but returned */
      if (! recv_ready ||
          (0 == (c->event_loop_info & MHD_EVENT_LOOP_INFO_READ)))
        err_state = true; /* The socket will not be read, the only way to avoid spinning */
    }
    if (0 != (revents & MHD_POLLWRBAND))
    { /* Status was not requested, but returned */
      if (! send_ready ||
          (0 == (c->event_loop_info & MHD_EVENT_LOOP_INFO_WRITE)))
        err_state = true; /* The socket will not be written, the only way to avoid spinning */
    }

    update_conn_net_status (d, c, recv_ready, send_ready, err_state);
  }
  mhd_assert (d->conns.count >= (i_c - i_s));
  mhd_assert (i_c <= d->dbg.num_events_elements);
  return true;
}


static MHD_FN_PAR_NONNULL_ (1) bool
get_all_net_updates_by_poll (struct MHD_Daemon *restrict d,
                             bool listen_only)
{
  unsigned int num_fds;
  int num_events;
  mhd_assert (mhd_POLL_TYPE_POLL == d->events.poll_type);

  num_fds = poll_update_fds (d, listen_only);

  // TODO: handle empty list situation

  num_events = mhd_poll (d->events.data.poll.fds,
                         num_fds,
                         get_max_wait (d)); // TODO: use correct timeout value
  if (0 > num_events)
  {
    int err;
    bool is_hard_error;
    bool is_ignored_error;
    is_hard_error = false;
    is_ignored_error = false;
#if defined(MHD_POSIX_SOCKETS)
    err = errno;
    if (0 != err)
    {
      is_hard_error =
        ((mhd_EFAULT_OR_ZERO == err) || (mhd_EINVAL_OR_ZERO == err));
      is_ignored_error = (mhd_EINTR_OR_ZERO == err);
    }
#elif defined(MHD_WINSOCK_SOCKETS)
    err = WSAGetLastError ();
    is_hard_error =
      ((WSAENETDOWN == err) || (WSAEFAULT == err) || (WSAEINVAL == err));
#endif
    if (! is_ignored_error)
    {
      if (is_hard_error)
      {
        mhd_LOG_MSG (d, MHD_SC_POLL_HARD_ERROR, \
                     "The poll() encountered unrecoverable error.");
        return false;
      }
      mhd_LOG_MSG (d, MHD_SC_POLL_SOFT_ERROR, \
                   "The poll() encountered error.");
    }
    return true;
  }

  return poll_update_statuses_from_fds (d, num_events);
}


#endif /* MHD_USE_POLL */

#ifdef MHD_USE_EPOLL

/**
 * Map events provided by epoll to connection states, ITC and
 * listen socket states
 */
static MHD_FN_PAR_NONNULL_ (1) bool
poll_update_statuses_from_eevents (struct MHD_Daemon *restrict d,
                                   unsigned int num_events)
{
  unsigned int i;
  struct epoll_event *const restrict events =
    d->events.data.epoll.events;
  for (i = 0; num_events > i; ++i)
  {
    struct epoll_event *const e = events + i;
    if (((uint64_t) mhd_SOCKET_REL_MARKER_ITC) == e->data.u64) /* uint64_t is in the system header */
    {
      if (0 != (e->events & (EPOLLPRI | EPOLLERR | EPOLLHUP)))
      {
        mhd_LOG_MSG (d, MHD_SC_ITC_STATUS_ERROR, \
                     "System reported that ITC has an error status.");
        /* ITC is broken, need to stop the daemon thread now as otherwise
           application will not be able to stop the thread. */
        return false;
      }
      if (0 != (e->events & EPOLLIN))
      {
        /* Clear ITC here, as before any other data processing.
         * Any external events may activate ITC again if any data to process is
         * added externally. Cleaning ITC early ensures guaranteed that new data
         * will not be missed. */
        mhd_itc_clear (d->threading.itc);
      }
    }
    else if (((uint64_t) mhd_SOCKET_REL_MARKER_LISTEN) == e->data.u64) /* uint64_t is in the system header */
    {
      if (0 != (e->events & (EPOLLPRI | EPOLLERR | EPOLLHUP)))
      {
        mhd_LOG_MSG (d, MHD_SC_ITC_STATUS_ERROR, \
                     "System reported that the listening socket has an error " \
                     "status. The daemon will not listen any more.");

        // TODO: remove listen from epoll monitoring

        /* Close the listening socket unless the master daemon should close it */
        if (! mhd_D_HAS_MASTER (d))
          mhd_socket_close (d->net.listen.fd);

        /* Stop monitoring socket to avoid spinning with busy-waiting */
        d->net.listen.fd = MHD_INVALID_SOCKET;
      }
      if (0 != (e->events & EPOLLIN))
        d->events.act_req.accept = true;
    }
    else
    {
      bool recv_ready;
      bool send_ready;
      bool err_state;
      struct MHD_Connection *const restrict c =
        (struct MHD_Connection *) e->data.ptr;
      recv_ready = (0 != (e->events & (EPOLLIN | EPOLLERR | EPOLLHUP)));
      send_ready = (0 != (e->events & (EPOLLOUT | EPOLLERR | EPOLLHUP)));
      err_state = (0 != (e->events & (EPOLLERR | EPOLLHUP)));

      update_conn_net_status (d, c, recv_ready, send_ready, err_state);
    }
  }
  return true;
}


/**
 * Update states of all connections, check for connection pending
 * to be accept()'ed, check for the events on ITC.
 */
static MHD_FN_PAR_NONNULL_ (1) bool
get_all_net_updates_by_epoll (struct MHD_Daemon *restrict d)
{
  int num_events;
  unsigned int events_processed;
  int max_wait;
  mhd_assert (mhd_POLL_TYPE_EPOLL == d->events.poll_type);
  mhd_assert (0 < ((int) d->events.data.epoll.num_elements));
  mhd_assert (d->events.data.epoll.num_elements == \
              (size_t) ((int) d->events.data.epoll.num_elements));
  mhd_assert (0 != d->events.data.epoll.num_elements);
  mhd_assert (0 != d->conns.cfg.count_limit);
  mhd_assert (d->events.data.epoll.num_elements == d->dbg.num_events_elements);

  // TODO: add listen socket enable/disable

  events_processed = 0;
  max_wait = get_max_wait (d); // TODO: use correct timeout value
  do
  {
    num_events = epoll_wait (d->events.data.epoll.e_fd,
                             d->events.data.epoll.events,
                             (int) d->events.data.epoll.num_elements,
                             max_wait);
    max_wait = 0;
    if (0 > num_events)
    {
      const int err = errno;
      if (EINTR != err)
      {
        mhd_LOG_MSG (d, MHD_SC_EPOLL_HARD_ERROR, \
                     "The epoll_wait() encountered unrecoverable error.");
        return false;
      }
      return true; /* EINTR, try next time */
    }
    if (! poll_update_statuses_from_eevents (d, (unsigned int) num_events))
      return false;

    events_processed += (unsigned int) num_events; /* Avoid reading too many events */
  } while ((((unsigned int) num_events) == d->events.data.epoll.num_elements) &&
           (events_processed < d->conns.cfg.count_limit + 2));

  return true;
}


#endif /* MHD_USE_EPOLL */


static MHD_FN_PAR_NONNULL_ (1) bool
process_all_events_and_data (struct MHD_Daemon *restrict d)
{
  switch (d->events.poll_type)
  {
  case mhd_POLL_TYPE_EXT:
    return false; // TODO: implement
    break;
#ifdef MHD_USE_SELECT
  case mhd_POLL_TYPE_SELECT:
    if (! get_all_net_updates_by_select (d, false))
      return false;
    break;
#endif /* MHD_USE_SELECT */
#ifdef MHD_USE_POLL
  case mhd_POLL_TYPE_POLL:
    if (! get_all_net_updates_by_poll (d, false))
      return false;
    break;
#endif /* MHD_USE_POLL */
#ifdef MHD_USE_EPOLL
  case mhd_POLL_TYPE_EPOLL:
    if (! get_all_net_updates_by_epoll (d))
      return false;
    break;
#endif /* MHD_USE_EPOLL */
#ifndef MHD_USE_SELECT
  case mhd_POLL_TYPE_SELECT:
#endif /* ! MHD_USE_SELECT */
#ifndef MHD_USE_POLL
  case mhd_POLL_TYPE_POLL:
#endif /* ! MHD_USE_POLL */
#ifndef MHD_USE_EPOLL
  case mhd_POLL_TYPE_EPOLL:
#endif /* ! MHD_USE_EPOLL */
  case mhd_POLL_TYPE_NOT_SET_YET:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    MHD_PANIC ("Daemon data integrity broken");
  }
  if (d->events.act_req.accept)
  {
    if (daemon_accept_new_conns (d))
      d->events.act_req.accept = false;
    else if (! d->net.listen.non_block)
      d->events.act_req.accept = false;
  }
  daemon_process_all_active_conns (d);
  return ! d->threading.stop_requested;
}


/**
 * The entry point for the daemon worker thread
 * @param cls the closure
 */
mhd_THRD_RTRN_TYPE mhd_THRD_CALL_SPEC
mhd_worker_all_events (void *cls)
{
  struct MHD_Daemon *const restrict d = (struct MHD_Daemon *) cls;
  mhd_thread_handle_ID_set_current_thread_ID (&(d->threading.tid));
  mhd_assert (d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
  mhd_assert (mhd_D_TYPE_IS_VALID (d->threading.d_type));
  mhd_assert (mhd_D_TYPE_HAS_EVENTS_PROCESSING (d->threading.d_type));
  mhd_assert (mhd_DAEMON_TYPE_LISTEN_ONLY != d->threading.d_type);
  mhd_assert (! mhd_D_TYPE_HAS_WORKERS (d->threading.d_type));
  mhd_assert (mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION != d->wmode_int);
  mhd_assert (d->dbg.events_fully_inited);
  mhd_assert (d->dbg.connections_inited);

  while (! d->threading.stop_requested)
  {
    if (d->threading.resume_requested)
      mhd_daemon_resume_conns (d);

    if (! process_all_events_and_data (d))
      break;
  }
  if (! d->threading.stop_requested)
  {
    mhd_LOG_MSG (d, MHD_SC_DAEMON_THREAD_STOP_UNEXPECTED, \
                 "The daemon thread is stopping, but termination has not " \
                 "been requested for the daemon.");
  }
  close_all_daemon_conns (d);

  return (mhd_THRD_RTRN_TYPE) 0;
}


static MHD_FN_PAR_NONNULL_ (1) bool
process_listening_and_itc_only (struct MHD_Daemon *restrict d)
{
  if (false)
    (void) 0;
#ifdef MHD_USE_SELECT
  else if (mhd_POLL_TYPE_SELECT == d->events.poll_type)
  {
    return false; // TODO: implement
  }
#endif /* MHD_USE_SELECT */
#ifdef MHD_USE_POLL
  else if (mhd_POLL_TYPE_POLL == d->events.poll_type)
  {
    if (! get_all_net_updates_by_poll (d, true))
      return false;
  }
#endif /* MHD_USE_POLL */
  else
  {
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    MHD_PANIC ("Daemon data integrity broken");
  }
  // TODO: Accept connections
  return false;
}


/**
 * The entry point for the daemon listening thread
 * @param cls the closure
 */
mhd_THRD_RTRN_TYPE mhd_THRD_CALL_SPEC
mhd_worker_listening_only (void *cls)
{
  struct MHD_Daemon *const restrict d = (struct MHD_Daemon *) cls;
  mhd_thread_handle_ID_set_current_thread_ID (&(d->threading.tid));

  mhd_assert (d->dbg.net_inited);
  mhd_assert (! d->dbg.net_deinited);
  mhd_assert (mhd_DAEMON_TYPE_LISTEN_ONLY == d->threading.d_type);
  mhd_assert (mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION == d->wmode_int);
  mhd_assert (d->dbg.events_fully_inited);
  mhd_assert (d->dbg.connections_inited);

  while (! d->threading.stop_requested)
  {
    if (! process_listening_and_itc_only (d))
      break;
  }
  if (! d->threading.stop_requested)
  {
    mhd_LOG_MSG (d, MHD_SC_DAEMON_THREAD_STOP_UNEXPECTED, \
                 "The daemon thread is stopping, but termination has " \
                 "not been requested by the daemon.");
  }
  return (mhd_THRD_RTRN_TYPE) 0;
}


mhd_THRD_RTRN_TYPE mhd_THRD_CALL_SPEC
mhd_worker_connection (void *cls)
{
  (void) cls;
  mhd_assert (0 && "Not yet implemented");
  return (mhd_THRD_RTRN_TYPE) 0;
}
