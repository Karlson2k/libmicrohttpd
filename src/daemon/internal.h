/*
     This file is part of libmicrohttpd
     (C) 2007 Daniel Pittman and Christian Grothoff

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
 * @file internal.h
 * @brief  internal shared structures
 * @author Daniel Pittman
 * @author Christian Grothoff
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
#include <sys/mman.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

#include <pthread.h>

#define MAX(a,b) ((a)<(b)) ? (b) : (a)
#define MIN(a,b) ((a)<(b)) ? (a) : (b)

/**
 * Size by which MHD usually tries to increment read/write buffers.
 */
#define MHD_BUF_INC_SIZE 2048

/**
 * fprintf-like helper function for logging debug
 * messages.
 */
void MHD_DLOG (const struct MHD_Daemon *daemon, const char *format, ...);


/**
 * Header or cookie in HTTP request or response.
 */
struct MHD_HTTP_Header
{
  struct MHD_HTTP_Header *next;

  char *header;

  char *value;

  enum MHD_ValueKind kind;
};


struct MHD_Access_Handler
{
  struct MHD_Access_Handler *next;

  char *uri_prefix;

  MHD_AccessHandlerCallback dh;

  void *dh_cls;
};


/**
 * Representation of a response.
 */
struct MHD_Response
{

  /**
   * Headers to send for the response.  Initially
   * the linked list is created in inverse order;
   * the order should be inverted before sending!
   */
  struct MHD_HTTP_Header *first_header;

  /**
   * Buffer pointing to data that we are supposed
   * to send as a response.
   */
  char *data;

  /**
   * Closure to give to the content reader
   * free callback.
   */
  void *crc_cls;

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
   * Size of the data buffer.
   */
  size_t data_buffer_size;

  /**
   * At what offset in the stream is the
   * beginning of data located?
   */
  size_t data_start;

};



struct MHD_Connection
{

  /**
   * This is a linked list.
   */
  struct MHD_Connection *next;

  /**
   * Reference to the MHD_Daemon struct.
   */
  struct MHD_Daemon *daemon;

  /**
   * Linked list of parsed headers.
   */
  struct MHD_HTTP_Header *headers_received;

  /**
   * Response to transmit (initially NULL).
   */
  struct MHD_Response *response;

  /**
   * The memory pool is created whenever we first read
   * from the TCP stream and destroyed at the end of
   * each request (and re-created for the next request).
   * In the meantime, this pointer is NULL.  The
   * pool is used for all connection-related data
   * except for the response (which maybe shared between
   * connections) and the IP address (which persists
   * across individual requests).
   */
  struct MemoryPool *pool;

  /**
   * Request method.  Should be GET/POST/etc.  Allocated
   * in pool.
   */
  char *method;

  /**
   * Requested URL (everything after "GET" only).  Allocated
   * in pool.
   */
  char *url;

  /**
   * HTTP version string (i.e. http/1.1).  Allocated
   * in pool.
   */
  char *version;

  /**
   * Buffer for reading requests.   Allocated
   * in pool.
   */
  char *read_buffer;

  /**
   * Buffer for writing response (headers only).  Allocated
   * in pool.
   */
  char *write_buffer;

  /**
   * Foreign address (of length addr_len).  MALLOCED (not
   * in pool!).
   */
  struct sockaddr_in *addr;

  /**
   * Thread for this connection (if we are using
   * one thread per connection).
   */
  pthread_t pid;

  /**
   * Size of read_buffer (in bytes).
   */
  size_t read_buffer_size;

  /**
   * Position where we currently append data in
   * read_buffer (last valid position).
   */
  size_t readLoc;

  /**
   * Size of write_buffer (in bytes).
   */
  size_t write_buffer_size;

  /**
   * Offset where we are with sending from write_buffer.
   */
  size_t writePos;

  /**
   * Last valid location in write_buffer.
   */
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
   * Position in the 100 CONTINUE message that
   * we need to send when receiving http 1.1 requests.
   */
  size_t continuePos;

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
   * Has this socket been closed for reading (i.e.
   * other side closed the connection)?  If so,
   * we must completely close the connection once
   * we are done sending our response.
   */
  int read_close;

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
   * Are we processing the POST data?
   */
  int post_processed;

  /**
   * HTTP response code.  Only valid if response object
   * is already set.
   */
  unsigned int responseCode;

};



struct MHD_Daemon
{

  struct MHD_Access_Handler *handlers;

  struct MHD_Access_Handler default_handler;

  /**
   * Linked list of our current connections.
   */
  struct MHD_Connection *connections;

  MHD_AcceptPolicyCallback apc;

  void *apc_cls;

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
   * Size of the per-connection memory pools.
   */
  unsigned int pool_size;

  /**
   * Limit on the number of parallel connections.
   */
  unsigned int max_connections;

  /**
   * Daemon's options.
   */
  enum MHD_OPTION options;

  /**
   * Listen port.
   */
  unsigned short port;

};


#endif
