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
 * @file lib/connection_update_event_loop_info.h
 * @brief function to update last activity of a connection
 * @author Christian Grothoff
 */

#ifndef CONNECTION_UPDATE_EVENT_LOOP_INFO_H
#define CONNECTION_UPDATE_EVENT_LOOP_INFO_H


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
  MHD_NONNULL (1);


#endif
