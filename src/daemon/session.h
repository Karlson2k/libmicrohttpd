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


struct MHD_Session {
  struct MHD_Session * next;

  struct MHD_Daemon * daemon;

  struct MHD_HTTP_Header * headers_received;
  
  struct MHD_Response * response;

  char * method;

  char * url;

  /**
   * Buffer for reading requests.
   */
  void * read_buffer;

  /**
   * Buffer for writing response.
   */
  void * write_buffer;

  /**
   * Foreign address (of length addr_len).
   */
  struct sockaddr_in * addr;

  /**
   * Thread for this session (if we are using
   * one thread per connection).
   */
  pthread_t pid;

  size_t read_buffer_size;

  size_t readLoc;

  size_t write_buffer_size;

  size_t writeLoc;

  /**
   * Current write position in the actual response
   * (excluding headers, content only; should be 0
   * while sending headers).
   */
  size_t messagePos;

  /**
   * Remaining (!) number of bytes in the upload.
   * Set to -1 for unknown (connection will close
   * to indicate end of upload).
   */
  size_t uploadSize;

  /**
   * Length of the foreign address.
   */
  socklen_t addr_len;

  /**
   * Socket for this connection.  Set to -1 if
   * this connection has died (daemon should clean
   * up in that case).
   */
  int socket_fd;
  
  /**
   * Have we finished receiving all of the headers yet?
   * Set to 1 once we are done processing all of the
   * headers.  Note that due to pipelining, it is
   * possible that the NEXT request is already 
   * (partially) waiting in the read buffer.
   */
  int headersReceived;

  /**
   * Have we finished receiving the data from a
   * potential file-upload? 
   */
  int bodyReceived;

  /**
   * Have we finished sending all of the headers yet?
   */
  int headersSent;

  /**
   * HTTP response code.  Only valid if response object
   * is already set.
   */
  unsigned int responseCode;

};


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
