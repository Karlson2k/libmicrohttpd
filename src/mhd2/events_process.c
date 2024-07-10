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

#include "events_process.h"

#include "sys_poll.h"

#include "mhd_public_api.h"

#include "mhd_itc.h"

#include "mhd_panic.h"

#include "mhd_sockets_macros.h"

#include "mhd_daemon.h"
#include "daemon_logger.h"
#include "mhd_connection.h"
#include "daemon_add_conn.h"
#include "daemon_funcs.h"
#include "conn_data_process.h"



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

  if (NULL != mhd_DLINKEDL_GET_PREV (c,proc_ready))
    return; /* In the 'proc_ready' list already */

  mhd_assert (0 != (((unsigned int) c->event_loop_info) \
                    & MHD_EVENT_LOOP_INFO_PROCESS));

  if ((0 !=
       (((unsigned int) c->sk_ready) & ((unsigned int) c->event_loop_info)
        & (MHD_EVENT_LOOP_INFO_READ | MHD_EVENT_LOOP_INFO_WRITE))) ||
      err_state)
  {
    mhd_DLINKEDL_INS_LAST (&(d->events),c,proc_ready);
  }
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
daemon_process_all_act_coons (struct MHD_Daemon *restrict d)
{
  struct MHD_Connection *c;
  mhd_assert (! mhd_D_HAS_WORKERS (d));

  c = mhd_DLINKEDL_GET_FIRST (&(d->events),proc_ready);
  while (NULL != c)
  {
    struct MHD_Connection *next;
    next = mhd_DLINKEDL_GET_NEXT (c, proc_ready); /* The current connection can be closed */
    if (! mhd_conn_process_recv_send_data(c))
      mhd_conn_close_final(c);

    c = next;
  }
  return true;
}


#ifdef MHD_USE_POLL

MHD_FN_PAR_NONNULL_ (1) static unsigned int
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

    d->events.data.poll.fds[i_c].fd = c->socket_fd;
    d->events.data.poll.rel[i_c].connection = c;
    events = POLLHUP; /* Actually, not needed and should be ignored in 'events' */
    if (0 != (c->event_loop_info & MHD_EVENT_LOOP_INFO_READ))
      events |= MHD_POLL_IN;
    if (0 != (c->event_loop_info & MHD_EVENT_LOOP_INFO_WRITE))
      events |= MHD_POLL_OUT;

    d->events.data.poll.fds[i_c].events = (short) events;
    ++i_c;
  }
  mhd_assert (d->conns.count == (i_c - i_s));
  return i_c;
}


MHD_FN_PAR_NONNULL_ (1) static bool
poll_update_statuses_from_fds (struct MHD_Daemon *restrict d,
                               int num_events)
{
  unsigned int i_s;
  unsigned int i_c;
  mhd_assert (mhd_POLL_TYPE_POLL == d->events.poll_type);
  mhd_assert (0 <= num_events);

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
    MHD_LOG_MSG (d, MHD_SC_ITC_STATUS_ERROR, \
                 "System reported that ITC has an error status.");
    /* ITC is broken, need to stop the daemon thread now as otherwise
       application will not be able to stop the thread. */
    return false;
  }
  if (0 != (d->events.data.poll.fds[i_s].revents & MHD_POLL_IN))
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
      MHD_LOG_MSG (d, MHD_SC_ITC_STATUS_ERROR, \
                   "System reported that the listening socket has an error " \
                   "status. The daemon will not listen any more.");
      /* Close the listening socket unless the master daemon should close it */
      if (! mhd_D_TYPE_HAS_MASTER_DAEMON (d->threading.d_type))
        mhd_socket_close (d->net.listen.fd);

      /* Stop monitoring socket to avoid spinning with busy-waiting */
      d->net.listen.fd = MHD_INVALID_SOCKET;
    }
    else if (0 != (d->events.data.poll.fds[i_s].revents & MHD_POLL_IN))
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
    mhd_assert (mhd_SOCKET_REL_MARKER_EMPTY != \
                d->events.data.poll.rel[i_c].fd_id);
    mhd_assert (mhd_SOCKET_REL_MARKER_ITC != \
                d->events.data.poll.rel[i_c].fd_id);
    mhd_assert (mhd_SOCKET_REL_MARKER_LISTEN != \
                d->events.data.poll.rel[i_c].fd_id);

    c = d->events.data.poll.rel[i_c].connection;
    mhd_assert (c->socket_fd == d->events.data.poll.fds[i_c].fd);
    revents = d->events.data.poll.fds[i_c].revents;
    recv_ready = (0 != (revents & MHD_POLL_IN));
    send_ready = (0 != (revents & MHD_POLL_OUT));
#ifndef MHD_POLLHUP_ON_REM_SHUT_WR
    err_state = (0 != (revents & (POLLHUP | POLLERR | POLLNVAL)));
#else
    err_state = (0 != (revents & (POLLERR | POLLNVAL)));
    if (0 != (revents & POLLHUP))
    { /* This can be a disconnect OR remote side set SHUT_WR */
      recv_ready = true; /* Check the socket by reading */
      if (0 != (d->events.data.poll.fds[i_c].events | MHD_POLL_IN))
        err_state = true; /* The socket will not be checked by reading, the only way to avoid spinning */
    }
#endif
    if (0 != (revents & (MHD_POLLPRI | MHD_POLLRDBAND)))
    { /* Statuses were not requested, but returned */
      if (! recv_ready ||
          (0 != (d->events.data.poll.fds[i_c].events | MHD_POLL_IN)))
        err_state = true; /* The socket will not be read, the only way to avoid spinning */
    }
    if (0 != (revents & MHD_POLLWRBAND))
    { /* Status was not requested, but returned */
      if (! send_ready ||
          (0 != (d->events.data.poll.fds[i_c].events | MHD_POLL_OUT)))
        err_state = true; /* The socket will not be written, the only way to avoid spinning */
    }

    update_conn_net_status (d, c, recv_ready, send_ready, err_state);
  }
  mhd_assert (d->conns.count >= (i_c - i_s));
  return true;
}


MHD_FN_PAR_NONNULL_ (1) static bool
get_all_net_updates_by_poll (struct MHD_Daemon *restrict d,
                             bool listen_only)
{
  unsigned int num_fds;
  int num_events;
  mhd_assert (mhd_POLL_TYPE_POLL == d->events.poll_type);

  num_fds = poll_update_fds (d, listen_only);

  // TODO: handle empty list situation

  num_events = mhd_poll (d->events.data.poll.fds, num_fds, -1);
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
        ((MHD_EFAULT_OR_ZERO == err) || (MHD_EINVAL_OR_ZERO == err));
      is_ignored_error = (MHD_EINTR_OR_ZERO == err);
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
        MHD_LOG_MSG (d, MHD_SC_POLL_HARD_ERROR, \
                     "The poll() encountered unrecoverable error.");
        return false;
      }
      MHD_LOG_MSG (d, MHD_SC_POLL_SOFT_ERROR, \
                   "The poll() encountered error.");
    }
  }

  if (! poll_update_statuses_from_fds (d, num_events))
    return false;

  return true;
}


#endif /* MHD_USE_POLL */


MHD_FN_PAR_NONNULL_ (1) static bool
process_all_events_and_data (struct MHD_Daemon *restrict d)
{
  switch (d->events.poll_type)
  {
  case mhd_POLL_TYPE_EXT:
    return false; // TODO: implement
    break;
#ifdef MHD_USE_SELECT
  case mhd_POLL_TYPE_SELECT:
    return false; // TODO: implement
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
    return false; // TODO: implement
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
  daemon_process_all_act_coons (d);
  return false;
}


/**
 * The entry point for the daemon worker thread
 * @param cls the closure
 */
mhd_THRD_RTRN_TYPE mhd_THRD_CALL_SPEC
mhd_worker_all_events (void *cls)
{
  struct MHD_Daemon *const restrict d = (struct MHD_Daemon *) cls;
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
    MHD_LOG_MSG (d, MHD_SC_DAEMON_THREAD_STOP_UNEXPECTED, \
                 "The daemon thread is stopping, but termination has not " \
                 "been requested by the daemon.");
  }
  return (mhd_THRD_RTRN_TYPE) 0;
}


MHD_FN_PAR_NONNULL_ (1) static bool
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
    MHD_LOG_MSG (d, MHD_SC_DAEMON_THREAD_STOP_UNEXPECTED, \
                 "The daemon thread is stopping, but termination has not been " \
                 "requested by the daemon.");
  }
  return (mhd_THRD_RTRN_TYPE) 0;
}


mhd_THRD_RTRN_TYPE mhd_THRD_CALL_SPEC
mhd_worker_connection (void *cls)
{
  mhd_assert (! cls && "Not yet implemented");
  return (mhd_THRD_RTRN_TYPE) 0;
}
