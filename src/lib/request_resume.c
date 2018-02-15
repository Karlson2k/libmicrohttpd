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
 * @file lib/request_resume.c
 * @brief implementation of MHD_request_resume()
 * @author Christian Grothoff
 */
#include "internal.h"


/**
 * Resume handling of network data for suspended request.  It is
 * safe to resume a suspended request at any time.  Calling this
 * function on a request that was not previously suspended will
 * result in undefined behavior.
 *
 * If you are using this function in ``external'' select mode, you must
 * make sure to run #MHD_run() afterwards (before again calling
 * #MHD_get_fdset(), as otherwise the change may not be reflected in
 * the set returned by #MHD_get_fdset() and you may end up with a
 * request that is stuck until the next network activity.
 *
 * @param request the request to resume
 */
void
MHD_request_resume (struct MHD_Request *request)
{
  struct MHD_Daemon *daemon = request->daemon;
  
  if (daemon->disallow_suspend_resume)
    MHD_PANIC (_("Cannot resume connections without enabling MHD_ALLOW_SUSPEND_RESUME!\n"));
  MHD_mutex_lock_chk_ (&daemon->cleanup_connection_mutex);
  request->connection->resuming = true;
  daemon->resuming = true;
  MHD_mutex_unlock_chk_ (&daemon->cleanup_connection_mutex);
  if ( (MHD_ITC_IS_VALID_(daemon->itc)) &&
       (! MHD_itc_activate_ (daemon->itc,
			     "r")) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_ITC_USE_FAILED,
                _("Failed to signal resume via inter-thread communication channel."));
#endif
    }
}

/* end of request_resume.c */
