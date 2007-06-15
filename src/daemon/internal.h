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
 * @file internal.h
 * @brief  internal shared structures
 * @author Daniel Pittman
 * @author Christian Grothoff
 * @version 0.1.0
 */

#ifndef INTERNAL_H
#define INTERNAL_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "config.h"
#include "plibc.h"
#include "microhttpd.h"

#ifndef MINGW
#include <netdb.h>
#include <netinet/in.h>
#endif

#include <pthread.h>

#define MHD_MAX_BUF_SIZE 2048

#define MAX(a,b) ((a)<(b)) ? (b) : (a)


/**
 * fprintf-like helper function for logging debug
 * messages.
 */
void MHD_DLOG(const struct MHD_Daemon * daemon,
	      const char * format,
	      ...);


/**
 * Header or cookie in HTTP request or response.
 */
struct MHD_HTTP_Header {
  struct MHD_HTTP_Header * next;

  char * header;

  char * value;

  enum MHD_ValueKind kind;
};


struct MHD_Access_Handler {
  struct MHD_Access_Handler * next;

  char * uri_prefix;

  MHD_AccessHandlerCallback dh;

  void * dh_cls;
};


/**
 * Representation of a response.
 */ 
struct MHD_Response {

  /**
   * Headers to send for the response.  Initially
   * the linked list is created in inverse order;
   * the order should be inverted before sending!
   */
  struct MHD_HTTP_Header * first_header;

  /**
   * Buffer pointing to data that we are supposed
   * to send as a response.
   */
  char * data;

  /**
   * Closure to give to the content reader
   * free callback.
   */ 
  void * crc_cls;
 
  /**
   * How do we get more data?  NULL if we are
   * given all of the data up front.
   */
  MHD_ContentReaderCallback crc;

  /**
   * NULL if data must not be freed, otherwise
   * either user-specified callback or "&free".
   */
  MHD_ContentReaderFreeCallback crfc;

  /**
   * Mutex to synchronize access to data/size and
   * reference counts.
   */
  pthread_mutex_t mutex;

  /**
   * Reference count for this response.  Free
   * once the counter hits zero.
   */
  unsigned int reference_count;
  
  /**
   * Set to -1 if size is not known.
   */
  size_t total_size;

  /**
   * Size of data.
   */
  size_t data_size;

  /**
   * At what offset in the stream is the
   * beginning of data located?
   */
  size_t data_start;
  
};



struct MHD_Session {
  struct MHD_Session * next;

  struct MHD_Daemon * daemon;

  struct MHD_HTTP_Header * headers_received;
  
  struct MHD_Response * response;

  /**
   * Request method.  Should be GET/POST/etc.
   */
  char * method;

  /**
   * Requested URL (everything after "GET" only).
   */
  char * url;

  /**
   * Buffer for reading requests.
   */
  char * read_buffer;

  /**
   * Buffer for writing response.
   */
  char * write_buffer;
  
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



struct MHD_Daemon {

  struct MHD_Access_Handler * handlers;

  struct MHD_Access_Handler default_handler;

  struct MHD_Session * connections;
  
  MHD_AcceptPolicyCallback apc;

  void * apc_cls;

  /**
   * PID of the select thread (if we have internal select)
   */
  pthread_t pid;

  /**
   * Listen socket.
   */
  int socket_fd;

  /**
   * Are we shutting down?
   */
  int shutdown;

  /**
   * Daemon's options.
   */
  enum MHD_OPTION options;

  unsigned short port;

};


#endif
