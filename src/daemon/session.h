/*
     This file is part of libmicrohttpd
     (C) 2007 Daniel Pittman

     libmicrohttpd is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     libmicrohttpd is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with libmicrohttpd; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file session.h
 * @brief  Methods for managing sessions
 * @author Daniel Pittman
 * @author Christian Grothoff
 * @version 0.1.0
 */

#ifndef SESSION_H
#define SESSION_H


/**
 * Obtain the select sets for this session.
 *
 * @return MHD_YES on success
 */
int 
MHD_session_get_fdset(struct MHD_Session * session,
		      fd_set * read_fd_set,
		      fd_set * write_fd_set,
		      fd_set * except_fd_set,
		      int * max_fd);


/**
 * This function handles a particular connection when it has been
 * determined that there is data to be read off a socket. All implementations
 * (multithreaded, external select, internal select) call this function
 * to handle reads. 
 */
int
MHD_session_handle_read(struct MHD_Session * session);
  

/**
 * This function was created to handle writes to sockets when it has been
 * determined that the socket can be written to. If there is no data
 * to be written, however, the function call does nothing. All implementations
 * (multithreaded, external select, internal select) call this function
 */
int
MHD_session_handle_write(struct MHD_Session * session);


#endif
