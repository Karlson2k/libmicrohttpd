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
  return -1;
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
  return -1;
}

/* end of daemon_get_fdset.c */
