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
 * @file lib/daemon_get_timeout.c
 * @brief function to obtain timeout for event loop
 * @author Christian Grothoff
 */
#include "internal.h"


/**
 * Obtain timeout value for polling function for this daemon.
 * This function set value to amount of milliseconds for which polling
 * function (`select()` or `poll()`) should at most block, not the
 * timeout value set for connections.
 * It is important to always use this function, even if connection
 * timeout is not set, as in some cases MHD may already have more
 * data to process on next turn (data pending in TLS buffers,
 * connections are already ready with epoll etc.) and returned timeout
 * will be zero.
 *
 * @param daemon daemon to query for timeout
 * @param timeout set to the timeout (in milliseconds)
 * @return #MHD_SC_OK on success, #MHD_SC_NO_TIMEOUT if timeouts are
 *        not used (or no connections exist that would
 *        necessitate the use of a timeout right now), otherwise
 *        an error code
 * @ingroup event
 */
enum MHD_StatusCode
MHD_daemon_get_timeout (struct MHD_Daemon *daemon,
			MHD_UNSIGNED_LONG_LONG *timeout)
{
  return -1;
}

/* end of daemon_get_timeout.c */
