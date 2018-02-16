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
 * @file lib/connection_call_handlers.c
 * @brief call the connection's handlers based on the event trigger
 * @author Christian Grothoff
 */
#include "internal.h"
#include "connection_call_handlers.h"
#include "connection_close.h"


/**
 * Call the handlers for a connection in the appropriate order based
 * on the readiness as detected by the event loop.
 *
 * @param con connection to handle
 * @param read_ready set if the socket is ready for reading
 * @param write_ready set if the socket is ready for writing
 * @param force_close set if a hard error was detected on the socket;
 *        if this information is not available, simply pass #MHD_NO
 * @return #MHD_YES to continue normally,
 *         #MHD_NO if a serious error was encountered and the
 *         connection is to be closed.
 */
// FIXME: rename connection->request?
int
MHD_connection_call_handlers_ (struct MHD_Connection *con,
			       bool read_ready,
			       bool write_ready,
			       bool force_close)
{
  struct MHD_Daemon *daemon = con->daemon;
  int ret;
  bool states_info_processed = false;
  /* Fast track flag */
  bool on_fasttrack = (con->request.state == MHD_REQUEST_INIT);

#ifdef HTTPS_SUPPORT
  if (con->tls_read_ready)
    read_ready = true;
#endif /* HTTPS_SUPPORT */
  if (!force_close)
    {
      if ( (MHD_EVENT_LOOP_INFO_READ ==
	    con->request.event_loop_info) &&
	   read_ready)
        {
          MHD_connection_handle_read (con);
          ret = MHD_connection_handle_idle (con);
          states_info_processed = true;
        }
      /* No need to check value of 'ret' here as closed connection
       * cannot be in MHD_EVENT_LOOP_INFO_WRITE state. */
      if ( (MHD_EVENT_LOOP_INFO_WRITE ==
	    con->request.event_loop_info) &&
	   write_ready)
        {
          MHD_connection_handle_write (con);
          ret = MHD_connection_handle_idle (con);
          states_info_processed = true;
        }
    }
  else
    {
      MHD_connection_close_ (con,
                             MHD_REQUEST_TERMINATED_WITH_ERROR);
      return MHD_connection_handle_idle (con);
    }

  if (! states_info_processed)
    { /* Connection is not read or write ready, but external conditions
       * may be changed and need to be processed. */
      ret = MHD_connection_handle_idle (con);
    }
  /* Fast track for fast connections. */
  /* If full request was read by single read_handler() invocation
     and headers were completely prepared by single MHD_connection_handle_idle()
     then try not to wait for next sockets polling and send response
     immediately.
     As writeability of socket was not checked and it may have
     some data pending in system buffers, use this optimization
     only for non-blocking sockets. */
  /* No need to check 'ret' as connection is always in
   * MHD_CONNECTION_CLOSED state if 'ret' is equal 'MHD_NO'. */
  else if (on_fasttrack &&
	   con->sk_nonblck)
    {
      if (MHD_REQUEST_HEADERS_SENDING == con->request.state)
        {
          MHD_connection_handle_write (con);
          /* Always call 'MHD_connection_handle_idle()' after each read/write. */
          ret = MHD_connection_handle_idle (con);
        }
      /* If all headers were sent by single write_handler() and
       * response body is prepared by single MHD_connection_handle_idle()
       * call - continue. */
      if ((MHD_REQUEST_NORMAL_BODY_READY == con->request.state) ||
          (MHD_REQUEST_CHUNKED_BODY_READY == con->request.state))
        {
          MHD_connection_handle_write (con);
          ret = MHD_connection_handle_idle (con);
        }
    }

  /* All connection's data and states are processed for this turn.
   * If connection already has more data to be processed - use
   * zero timeout for next select()/poll(). */
  /* Thread-per-connection do not need global zero timeout as
   * connections are processed individually. */
  /* Note: no need to check for read buffer availability for
   * TLS read-ready connection in 'read info' state as connection
   * without space in read buffer will be market as 'info block'. */
  if ( (! daemon->data_already_pending) &&
       (MHD_TM_THREAD_PER_CONNECTION != daemon->threading_model) )
    {
      if (MHD_EVENT_LOOP_INFO_BLOCK ==
	  con->request.event_loop_info)
        daemon->data_already_pending = true;
#ifdef HTTPS_SUPPORT
      else if ( (con->tls_read_ready) &&
                (MHD_EVENT_LOOP_INFO_READ ==
		 con->request.event_loop_info) )
        daemon->data_already_pending = true;
#endif /* HTTPS_SUPPORT */
    }
  return ret;
}

/* end of connection_call_handlers.c */
