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
 * @file lib/daemon_run_from_select.c
 * @brief functions to run select-based event loop
 * @author Christian Grothoff
 */
#include "internal.h"


/**
 * Run webserver operations. This method should be called by clients
 * in combination with #MHD_get_fdset and #MHD_get_timeout() if the
 * client-controlled select method is used.
 *
 * You can use this function instead of #MHD_run if you called
 * `select()` on the result from #MHD_get_fdset.  File descriptors in
 * the sets that are not controlled by MHD will be ignored.  Calling
 * this function instead of #MHD_run is more efficient as MHD will not
 * have to call `select()` again to determine which operations are
 * ready.
 *
 * This function cannot be used with daemon started with
 * #MHD_USE_INTERNAL_POLLING_THREAD flag.
 *
 * @param daemon daemon to run select loop for
 * @param read_fd_set read set
 * @param write_fd_set write set
 * @param except_fd_set except set
 * @return #MHD_SC_OK on success
 * @ingroup event
 */
enum MHD_StatusCode
MHD_daemon_run_from_select (struct MHD_Daemon *daemon,
			    const fd_set *read_fd_set,
			    const fd_set *write_fd_set,
			    const fd_set *except_fd_set)
{
  return -1;
}

/* end of daemon_run_from_select.c */
