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
 * @file lib/connection_update_event_loop_info.c
 * @brief update the set of network events this connection is waiting for
 * @author Christian Grothoff
 */
#include "internal.h"
#include "connection_update_event_loop_info.h"


/**
 * Update the 'event_loop_info' field of this connection based on the
 * state that the connection is now in.  May also close the connection
 * or perform other updates to the connection if needed to prepare for
 * the next round of the event loop.
 *
 * @param connection connection to get poll set for
 */
void
MHD_connection_update_event_loop_info_ (struct MHD_Connection *connection)
{
  /* Do not update states of suspended connection */
  if (connection->suspended)
    return; /* States will be updated after resume. */
#ifdef HTTPS_SUPPORT
  if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
    { /* HTTPS connection. */
      switch (connection->tls_state)
        {
          case MHD_TLS_CONN_INIT:
            connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
            return;
          case MHD_TLS_CONN_HANDSHAKING:
            if (0 == gnutls_record_get_direction (connection->tls_session))
              connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
            else
              connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
            return;
          default:
            break;
        }
    }
#endif /* HTTPS_SUPPORT */
  while (1)
    {
#if DEBUG_STATES
      MHD_DLOG (connection->daemon,
                _("In function %s handling connection at state: %s\n"),
                __FUNCTION__,
                MHD_state_to_string (connection->state));
#endif
      switch (connection->state)
        {
        case MHD_CONNECTION_INIT:
        case MHD_CONNECTION_URL_RECEIVED:
        case MHD_CONNECTION_HEADER_PART_RECEIVED:
          /* while reading headers, we always grow the
             read buffer if needed, no size-check required */
          if ( (connection->read_buffer_offset == connection->read_buffer_size) &&
	       (MHD_NO == try_grow_read_buffer (connection)) )
            {
              transmit_error_response (connection,
                                       (connection->url != NULL)
                                       ? MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE
                                       : MHD_HTTP_URI_TOO_LONG,
                                       REQUEST_TOO_BIG);
              continue;
            }
	  if (! connection->read_closed)
	    connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
	  else
	    connection->event_loop_info = MHD_EVENT_LOOP_INFO_BLOCK;
          break;
        case MHD_CONNECTION_HEADERS_RECEIVED:
          mhd_assert (0);
          break;
        case MHD_CONNECTION_HEADERS_PROCESSED:
          mhd_assert (0);
          break;
        case MHD_CONNECTION_CONTINUE_SENDING:
          connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
          break;
        case MHD_CONNECTION_CONTINUE_SENT:
          if (connection->read_buffer_offset == connection->read_buffer_size)
            {
              if ((MHD_YES != try_grow_read_buffer (connection)) &&
                  (0 != (connection->daemon->options &
                         MHD_USE_INTERNAL_POLLING_THREAD)))
                {
                  /* failed to grow the read buffer, and the
                     client which is supposed to handle the
                     received data in a *blocking* fashion
                     (in this mode) did not handle the data as
                     it was supposed to!
                     => we would either have to do busy-waiting
                     (on the client, which would likely fail),
                     or if we do nothing, we would just timeout
                     on the connection (if a timeout is even
                     set!).
                     Solution: we kill the connection with an error */
                  transmit_error_response (connection,
                                           MHD_HTTP_INTERNAL_SERVER_ERROR,
                                           INTERNAL_ERROR);
                  continue;
                }
            }
          if ( (connection->read_buffer_offset < connection->read_buffer_size) &&
	       (! connection->read_closed) )
	    connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
	  else
	    connection->event_loop_info = MHD_EVENT_LOOP_INFO_BLOCK;
          break;
        case MHD_CONNECTION_BODY_RECEIVED:
        case MHD_CONNECTION_FOOTER_PART_RECEIVED:
          /* while reading footers, we always grow the
             read buffer if needed, no size-check required */
          if (connection->read_closed)
            {
	      CONNECTION_CLOSE_ERROR (connection,
				      NULL);
              continue;
            }
	  connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
          /* transition to FOOTERS_RECEIVED
             happens in read handler */
          break;
        case MHD_CONNECTION_FOOTERS_RECEIVED:
	  connection->event_loop_info = MHD_EVENT_LOOP_INFO_BLOCK;
          break;
        case MHD_CONNECTION_HEADERS_SENDING:
          /* headers in buffer, keep writing */
	  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
          break;
        case MHD_CONNECTION_HEADERS_SENT:
          mhd_assert (0);
          break;
        case MHD_CONNECTION_NORMAL_BODY_READY:
	  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
          break;
        case MHD_CONNECTION_NORMAL_BODY_UNREADY:
	  connection->event_loop_info = MHD_EVENT_LOOP_INFO_BLOCK;
          break;
        case MHD_CONNECTION_CHUNKED_BODY_READY:
	  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
          break;
        case MHD_CONNECTION_CHUNKED_BODY_UNREADY:
	  connection->event_loop_info = MHD_EVENT_LOOP_INFO_BLOCK;
          break;
        case MHD_CONNECTION_BODY_SENT:
          mhd_assert (0);
          break;
        case MHD_CONNECTION_FOOTERS_SENDING:
	  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
          break;
        case MHD_CONNECTION_FOOTERS_SENT:
          mhd_assert (0);
          break;
        case MHD_CONNECTION_CLOSED:
	  connection->event_loop_info = MHD_EVENT_LOOP_INFO_CLEANUP;
          return;       /* do nothing, not even reading */
        case MHD_CONNECTION_IN_CLEANUP:
          mhd_assert (0);
          break;
#ifdef UPGRADE_SUPPORT
        case MHD_CONNECTION_UPGRADE:
          mhd_assert (0);
          break;
#endif /* UPGRADE_SUPPORT */
        default:
          mhd_assert (0);
        }
      break;
    }
}


/* end of connection_update_event_loop_info.c */

