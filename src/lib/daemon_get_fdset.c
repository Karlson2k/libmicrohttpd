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
 * @file lib/daemon_get_fdset.c
 * @brief function to get select() fdset of a daemon
 * @author Christian Grothoff
 */
#include "internal.h"

/**
 * We defined a macro with the same name as a function we
 * are implementing here. Need to undef the macro to avoid
 * causing a conflict.
 */
#undef MHD_daemon_get_fdset

/**
 * Obtain the `select()` sets for this daemon.  Daemon's FDs will be
 * added to fd_sets. To get only daemon FDs in fd_sets, call FD_ZERO
 * for each fd_set before calling this function. FD_SETSIZE is assumed
 * to be platform's default.
 *
 * This function should only be called in when MHD is configured to
 * use external select with 'select()' or with 'epoll'.  In the latter
 * case, it will only add the single 'epoll()' file descriptor used by
 * MHD to the sets.  It's necessary to use #MHD_get_timeout() in
 * combination with this function.
 *
 * This function must be called only for daemon started without
 * #MHD_USE_INTERNAL_POLLING_THREAD flag.
 *
 * @param daemon daemon to get sets from
 * @param read_fd_set read set
 * @param write_fd_set write set
 * @param except_fd_set except set
 * @param max_fd increased to largest FD added (if larger
 *               than existing value); can be NULL
 * @return #MHD_SC_OK on success, otherwise error code
 * @ingroup event
 */
enum MHD_StatusCode
MHD_daemon_get_fdset (struct MHD_Daemon *daemon,
		      fd_set *read_fd_set,
		      fd_set *write_fd_set,
		      fd_set *except_fd_set,
		      MHD_socket *max_fd)
{
  return MHD_daemon_get_fdset2 (daemon,
				read_fd_set,
				write_fd_set,
				except_fd_set,
				max_fd,
				_MHD_SYS_DEFAULT_FD_SETSIZE);
}


/**
 * Internal version of #MHD_daemon_get_fdset2().
 *
 * @param daemon daemon to get sets from
 * @param read_fd_set read set
 * @param write_fd_set write set
 * @param except_fd_set except set
 * @param max_fd increased to largest FD added (if larger
 *               than existing value); can be NULL
 * @param fd_setsize value of FD_SETSIZE
 * @return #MHD_SC_OK on success
 * @ingroup event
 */
static enum MHD_StatusCode
internal_get_fdset2 (struct MHD_Daemon *daemon,
                     fd_set *read_fd_set,
                     fd_set *write_fd_set,
                     fd_set *except_fd_set,
                     MHD_socket *max_fd,
                     unsigned int fd_setsize)

{
  struct MHD_Connection *pos;
  struct MHD_Connection *posn;
  int result = MHD_YES;
  MHD_socket ls;

  if (daemon->shutdown)
    return MHD_NO;

  ls = daemon->listen_socket;
  if ( (MHD_INVALID_SOCKET != ls) &&
       (! daemon->was_quiesced) &&
       (! MHD_add_to_fd_set_ (ls,
                              read_fd_set,
                              max_fd,
                              fd_setsize)) )
    result = MHD_NO;

  /* Add all sockets to 'except_fd_set' as well to watch for
   * out-of-band data. However, ignore errors if INFO_READ
   * or INFO_WRITE sockets will not fit 'except_fd_set'. */
  /* Start from oldest connections. Make sense for W32 FDSETs. */
  for (pos = daemon->connections_tail; NULL != pos; pos = posn)
    {
      posn = pos->prev;

      switch (pos->request.event_loop_info)
	{
	case MHD_EVENT_LOOP_INFO_READ:
	  if (! MHD_add_to_fd_set_ (pos->socket_fd,
                                    read_fd_set,
                                    max_fd,
                                    fd_setsize))
	    result = MHD_NO;
#ifdef MHD_POSIX_SOCKETS
          MHD_add_to_fd_set_ (pos->socket_fd,
                              except_fd_set,
                              max_fd,
                              fd_setsize);
#endif /* MHD_POSIX_SOCKETS */
	  break;
	case MHD_EVENT_LOOP_INFO_WRITE:
	  if (! MHD_add_to_fd_set_ (pos->socket_fd,
                                    write_fd_set,
                                    max_fd,
                                    fd_setsize))
	    result = MHD_NO;
#ifdef MHD_POSIX_SOCKETS
          MHD_add_to_fd_set_ (pos->socket_fd,
                              except_fd_set,
                              max_fd,
                              fd_setsize);
#endif /* MHD_POSIX_SOCKETS */
	  break;
	case MHD_EVENT_LOOP_INFO_BLOCK:
	  if ( (NULL == except_fd_set) ||
	      ! MHD_add_to_fd_set_ (pos->socket_fd,
	                            except_fd_set,
                                    max_fd,
                                    fd_setsize))
            result = MHD_NO;
	  break;
	case MHD_EVENT_LOOP_INFO_CLEANUP:
	  /* this should never happen */
	  break;
	}
    }
#ifdef MHD_WINSOCK_SOCKETS
  /* W32 use limited array for fd_set so add INFO_READ/INFO_WRITE sockets
   * only after INFO_BLOCK sockets to ensure that INFO_BLOCK sockets will
   * not be pushed out. */
  for (pos = daemon->connections_tail; NULL != pos; pos = posn)
    {
      posn = pos->prev;
      MHD_add_to_fd_set_ (pos->socket_fd,
                          except_fd_set,
                          max_fd,
                          fd_setsize);
    }
#endif /* MHD_WINSOCK_SOCKETS */
#if defined(HTTPS_SUPPORT) && defined(UPGRADE_SUPPORT)
  {
    struct MHD_UpgradeResponseHandle *urh;

    for (urh = daemon->urh_tail; NULL != urh; urh = urh->prev)
      {
        if (MHD_NO ==
            urh_to_fdset (urh,
                          read_fd_set,
                          write_fd_set,
                          except_fd_set,
                          max_fd,
                          fd_setsize))
          result = MHD_NO;
      }
  }
#endif
#if DEBUG_CONNECT
#ifdef HAVE_MESSAGES
  if (NULL != max_fd)
    MHD_DLOG (daemon,
              _("Maximum socket in select set: %d\n"),
              *max_fd);
#endif
#endif /* HTTPS_SUPPORT && UPGRADE_SUPPORT */
  return result;
}


/**
 * Obtain the `select()` sets for this daemon.  Daemon's FDs will be
 * added to fd_sets. To get only daemon FDs in fd_sets, call FD_ZERO
 * for each fd_set before calling this function.
 *
 * Passing custom FD_SETSIZE as @a fd_setsize allow usage of
 * larger/smaller than platform's default fd_sets.
 *
 * This function should only be called in when MHD is configured to
 * use external select with 'select()' or with 'epoll'.  In the latter
 * case, it will only add the single 'epoll' file descriptor used by
 * MHD to the sets.  It's necessary to use #MHD_get_timeout() in
 * combination with this function.
 *
 * This function must be called only for daemon started
 * without #MHD_USE_INTERNAL_POLLING_THREAD flag.
 *
 * @param daemon daemon to get sets from
 * @param read_fd_set read set
 * @param write_fd_set write set
 * @param except_fd_set except set
 * @param max_fd increased to largest FD added (if larger
 *               than existing value); can be NULL
 * @param fd_setsize value of FD_SETSIZE
 * @return #MHD_SC_OK on success, otherwise error code
 * @ingroup event
 */
enum MHD_StatusCode
MHD_daemon_get_fdset2 (struct MHD_Daemon *daemon,
		       fd_set *read_fd_set,
		       fd_set *write_fd_set,
		       fd_set *except_fd_set,
		       MHD_socket *max_fd,
		       unsigned int fd_setsize)
{
  if ( (MHD_TM_EXTERNAL_EVENT_LOOP != daemon->threading_model) ||
       (MHD_ELS_POLL == daemon->event_loop_syscall) ) 
    return MHD_SC_CONFIGURATION_MISSMATCH_FOR_GET_FDSET;

#ifdef EPOLL_SUPPORT
  if (MHD_ELS_EPOLL == daemon->event_loop_syscall)
    {
      if (daemon->shutdown)
        return MHD_SC_DAEMON_ALREADY_SHUTDOWN;

      /* we're in epoll mode, use the epoll FD as a stand-in for
         the entire event set */

      return MHD_add_to_fd_set_ (daemon->epoll_fd,
                                 read_fd_set,
                                 max_fd,
                                 fd_setsize)
	? MHD_SC_OK
	: MHD_SC_SOCKET_OUTSIDE_OF_FDSET_RANGE;
    }
#endif

  return internal_get_fdset2 (daemon,
			      read_fd_set,
                              write_fd_set,
			      except_fd_set,
                              max_fd,
			      fd_setsize);
}

/* end of daemon_get_fdset.c */
