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
 * @file connection.c
 * @brief  Methods for managing connections
 * @author Daniel Pittman
 * @author Christian Grothoff
 */

#include "internal.h"
#include "connection.h"
#include "response.h"


/**
 * Get all of the headers from the request.
 *
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to iterator
 * @return number of entries iterated over
 */
int
MHD_get_connection_values(struct MHD_Connection * connection,
		       enum MHD_ValueKind kind,
		       MHD_KeyValueIterator iterator,
		       void * iterator_cls) {
  int ret;
  struct MHD_HTTP_Header * pos;

  if (connection == NULL)
    return -1;
  ret = 0;
  pos = connection->headers_received;
  while (pos != NULL) {
    if (0 != (pos->kind & kind)) {
      ret++;
      if ( (iterator != NULL) &&
	   (MHD_YES != iterator(iterator_cls,
				kind,
				pos->header,
				pos->value)) )
	return ret;
    }
    pos = pos->next;
  }
  return ret;
}


/**
 * Get a particular header value.  If multiple
 * values match the kind, return any one of them.
 *
 * @param key the header to look for
 * @return NULL if no such item was found
 */
const char *
MHD_lookup_connection_value(struct MHD_Connection * connection,
			 enum MHD_ValueKind kind,
			 const char * key) {
  struct MHD_HTTP_Header * pos;

  if (connection == NULL)
    return NULL;
  pos = connection->headers_received;
  while (pos != NULL) {
    if ( (0 != (pos->kind & kind)) &&
	 (0 == strcasecmp(key,
			  pos->header)) )
      return pos->value;
    pos = pos->next;
  }
  return NULL;
}

/**
 * Queue a response to be transmitted to the client (as soon as
 * possible).
 *
 * @param connection the connection identifying the client
 * @param status_code HTTP status code (i.e. 200 for OK)
 * @param response response to transmit
 * @return MHD_NO on error (i.e. reply already sent),
 *         MHD_YES on success or if message has been queued
 */
int
MHD_queue_response(struct MHD_Connection * connection,
		   unsigned int status_code,
		   struct MHD_Response * response) {
  if ( (connection == NULL) ||
       (response == NULL) ||
       (connection->response != NULL) ||
       (connection->bodyReceived == 0) ||
       (connection->headersReceived == 0) )
    return MHD_NO;	
  MHD_increment_response_rc(response);
  connection->response = response;
  connection->responseCode = status_code;
  return MHD_YES;
}


/**
 * Obtain the select sets for this connection
 *
 * @return MHD_YES on success
 */
int
MHD_connection_get_fdset(struct MHD_Connection * connection,
		      fd_set * read_fd_set,
		      fd_set * write_fd_set,
		      fd_set * except_fd_set,
		      int * max_fd) {
  int fd;

  fd = connection->socket_fd;
  if (fd == -1)
    return MHD_YES;
  if ( (connection->read_close == 0) &&
       ( (connection->headersReceived == 0) ||
	 (connection->readLoc < connection->read_buffer_size) ) )
    FD_SET(fd, read_fd_set);
  if (connection->response != NULL)
    FD_SET(fd, write_fd_set);
  if ( (fd > *max_fd) &&
       ( (connection->headersReceived == 0) ||
	 (connection->readLoc < connection->read_buffer_size) ||
	 (connection->response != NULL) ) )
    *max_fd = fd;
  return MHD_YES;
}

/**
 * Parse a single line of the HTTP header.  Remove it
 * from the read buffer.  If the current line does not
 * fit, consider growing the buffer.  If the line is
 * far too long, close the connection.  If no line is
 * found (incomplete, buffer too small, line too long),
 * return NULL.  Otherwise return a copy of the line.
 */
static char *
MHD_get_next_header_line(struct MHD_Connection * connection) {
  char * rbuf;
  size_t pos;
  size_t start;

  if (connection->readLoc == 0)
    return NULL;
  start = 0;
  pos = 0;
  rbuf = connection->read_buffer;
  while ( (pos < connection->readLoc - 1) &&
	  (rbuf[pos] != '\r') &&
	  (rbuf[pos] != '\n') )
    pos++;
  if (pos == connection->readLoc - 1) {
    /* not found, consider growing... */
    if (connection->readLoc == connection->read_buffer_size) {
      /* grow buffer to read larger header or die... */
      if (connection->read_buffer_size < 4 * MHD_MAX_BUF_SIZE) {
	rbuf = malloc(connection->read_buffer_size * 2);
	memcpy(rbuf,
	       connection->read_buffer,
	       connection->readLoc);
	free(connection->read_buffer);
	connection->read_buffer = rbuf;
	connection->read_buffer_size *= 2;
      } else {
	/* die, header far too long to be reasonable */
	MHD_DLOG(connection->daemon,
		 "Received excessively long header line (>%u), closing connection.\n",
		 4 * MHD_MAX_BUF_SIZE);
	CLOSE(connection->socket_fd);
	connection->socket_fd = -1;
      }
    }
    return NULL;
  }
  /* found, check if we have proper CRLF */
  rbuf = malloc(pos + 1);
  memcpy(rbuf,
	 connection->read_buffer,
	 pos);
  rbuf[pos] = '\0';
  if ( (connection->read_buffer[pos] == '\r') &&
       (connection->read_buffer[pos+1] == '\n') )
    pos++; /* skip both r and n */
  pos++;
  memmove(connection->read_buffer,
	  &connection->read_buffer[pos],
	  connection->readLoc - pos);
  connection->readLoc -= pos;
  return rbuf;
}

static void
MHD_connection_add_header(struct MHD_Connection * connection,
		       const char * key,
		       const char * value,
		       enum MHD_ValueKind kind) {
  struct MHD_HTTP_Header * hdr;

  hdr = malloc(sizeof(struct MHD_HTTP_Header));
  hdr->next = connection->headers_received;
  hdr->header = strdup(key);
  hdr->value = strdup(value);
  hdr->kind = kind;
  connection->headers_received = hdr;
}

/**
 * Process escape sequences ('+'=space, %HH)
 */ 
static void
MHD_http_unescape(char * val) {
  char * esc;
  unsigned int num;

  while (NULL != (esc = strstr(val, "+"))) 
    *esc = ' ';  
  while (NULL != (esc = strstr(val, "%"))) {
    if ( (1 == sscanf(&esc[1],
		    "%2x",
		    &num)) ||
	 (1 == sscanf(&esc[1],
		      "%2X",
		      &num)) ) {
      esc[0] = (unsigned char) num;
      memmove(&esc[1],
	      &esc[3],
	      strlen(&esc[3]));
    }
    val = esc+1;
  }
}

static void
MHD_parse_arguments(struct MHD_Connection * connection,
		    char * args) {
  char * equals;
  char * amper;

  while (args != NULL) {
    equals = strstr(args, "=");
    if (equals == NULL)
      return; /* invalid, ignore */
    equals[0] = '\0';
    equals++;
    amper = strstr(equals, "&");
    if (amper != NULL) {
      amper[0] = '\0';
      amper++;
    }
    MHD_http_unescape(args);
    MHD_http_unescape(equals);
    MHD_connection_add_header(connection,
			   args,
			   equals,
			   MHD_GET_ARGUMENT_KIND);
    args = amper;
  }
}

/**
 * Parse the cookie header (see RFC 2109).
 */
static void
MHD_parse_cookie_header(struct MHD_Connection * connection) {
  const char * hdr;
  char * cpy;
  char * pos;
  char * semicolon;
  char * equals;
  int quotes;

  hdr = MHD_lookup_connection_value(connection,
				 MHD_HEADER_KIND,
				 "Cookie");
  if (hdr == NULL)
    return;
  cpy = strdup(hdr);
  pos = cpy;
  while (pos != NULL) {
    equals = strstr(pos, "=");
    if (equals == NULL)
      break;
    equals[0] = '\0';
    equals++;
    quotes = 0;
    semicolon = equals;
    while ( (semicolon[0] != '\0') &&
	    ( (quotes != 0) ||
	      ( (semicolon[0] != ';') &&
		(semicolon[0] != ',') ) ) ) {
      if (semicolon[0] == '"')
	quotes = (quotes + 1) & 1;
      semicolon++;
    }
    if (semicolon[0] == '\0')
      semicolon = NULL;
    if (semicolon != NULL) {
      semicolon[0] = '\0';
      semicolon++;
    }
    /* remove quotes */
    if ( (equals[0] == '"') &&
	 (equals[strlen(equals)-1] == '"') ) {
      equals[strlen(equals)-1] = '\0';
      equals++;
    }
    MHD_connection_add_header(connection,
			   pos,
			   equals,
			   MHD_COOKIE_KIND);
    pos = semicolon;
  }
  free(cpy);
}


/**
 * This function is designed to parse the input buffer of a given connection.
 *
 * Once the header is complete, it should have set the
 * headers_received, url and method values and set
 * headersReceived to 1.  If no body is expected, it should
 * also set "bodyReceived" to 1.  Otherwise, it should
 * set "uploadSize" to the expected size of the body.  If the
 * size of the body is unknown, it should be set to -1.
 */
static void
MHD_parse_connection_headers(struct MHD_Connection * connection) {
  char * last;
  char * line;
  char * colon;
  char * uri;
  char * httpType;
  char * args;
  char * tmp;
  const char * clen;
  unsigned long long cval;

  if (connection->bodyReceived == 1)
    abort();
  last = NULL;
  while (NULL != (line = MHD_get_next_header_line(connection))) {
    if (last != NULL) {
      if ( (line[0] == ' ') ||
	   (line[0] == '\t') ) {
	/* value was continued on the next line, see
	   http://www.jmarshall.com/easy/http/ */
	if ( (strlen(line) + strlen(last) >
	      4 * MHD_MAX_BUF_SIZE) ) {
	  free(line);
	  free(last);
	  last = NULL;
	  MHD_DLOG(connection->daemon,
		   "Received excessively long header line (>%u), closing connection.\n",
		   4 * MHD_MAX_BUF_SIZE);
	  CLOSE(connection->socket_fd);
	  connection->socket_fd = -1;
  	  break;
	}
	tmp = malloc(strlen(line) + strlen(last) + 1);
	strcpy(tmp, last);
	free(last);
	last = tmp;
	tmp = line;
	while ( (tmp[0] == ' ') ||
		(tmp[0] == '\t') )
	  tmp++; /* skip whitespace at start of 2nd line */
	strcat(last, tmp);
	free(line);
	continue; /* possibly more than 2 lines... */
      } else {
	MHD_connection_add_header(connection,
			       last,
			       colon,
			       MHD_HEADER_KIND);
	free(last);
	last = NULL;    
      }
    }
    if (connection->url == NULL) {
      /* line must be request line */
      uri = strstr(line, " ");
      if (uri == NULL)
	goto DIE;
      uri[0] = '\0';
      connection->method = strdup(line);
      uri++;
      httpType = strstr(uri, " ");
      if (httpType != NULL) {
	httpType[0] = '\0';
	httpType++;
      }
      args = strstr(uri, "?");
      if (args != NULL) {
	args[0] = '\0';
	args++;
	MHD_parse_arguments(connection,
			    args);
      }
      connection->url = strdup(uri);
      if (httpType == NULL)
	connection->version = strdup("");
      else
	connection->version = strdup(httpType);
      free(line);
      continue;
    }
    /* check if this is the end of the header */
    if (strlen(line) == 0) {
      free(line);
      /* end of header */
      connection->headersReceived = 1;
      clen = MHD_lookup_connection_value(connection,
				      MHD_HEADER_KIND,
				      "Content-Length");
      if (clen != NULL) {
	if (1 != sscanf(clen,
			"%llu",
			&cval)) {
	  MHD_DLOG(connection->daemon,
		   "Failed to parse Content-Length header `%s', closing connection.\n",
		   clen);
	  goto DIE;
	}
	connection->uploadSize = cval;
	connection->bodyReceived = cval == 0 ? 1 : 0;
      } else {
	if (NULL == MHD_lookup_connection_value(connection,
					     MHD_HEADER_KIND,
					     "Transfer-Encoding")) {
	  /* this request does not have a body */
	  connection->uploadSize = 0;
	  connection->bodyReceived = 1;
	} else {
	  connection->uploadSize = -1; /* unknown size */
	  connection->bodyReceived = 0;
	}
      }
      break;
    }
    /* line should be normal header line, find colon */
    colon = strstr(line, ":");
    if (colon == NULL) {
      /* error in header line, die hard */
      MHD_DLOG(connection->daemon,
	       "Received malformed line (no colon), closing connection.\n");
      goto DIE;
    }
    /* zero-terminate header */
    colon[0] = '\0';
    colon++; /* advance to value */
    while ( (colon[0] != '\0') &&
	    ( (colon[0] == ' ') ||
	      (colon[0] == '\t') ) )
      colon++;
    /* we do the actual adding of the connection
       header at the beginning of the while
       loop since we need to be able to inspect
       the *next* header line (in case it starts
       with a space...) */
  }
  if (last != NULL) {
    MHD_connection_add_header(connection,
			   last,
			   colon,
			   MHD_HEADER_KIND);
    free(last);
  }
  MHD_parse_cookie_header(connection);
  return;
 DIE:
  CLOSE(connection->socket_fd);
  connection->socket_fd = -1;
}


/**
 * Find the handler responsible for this request.
 */
static struct MHD_Access_Handler *
MHD_find_access_handler(struct MHD_Connection * connection) {
  struct MHD_Access_Handler * pos;

  pos = connection->daemon->handlers;
  while (pos != NULL) {
    if (0 == strcmp(connection->url,
		    pos->uri_prefix))
      return pos;
    pos = pos->next;
  }
  return &connection->daemon->default_handler;
}

/**
 * Call the handler of the application for this
 * connection.
 */
void
MHD_call_connection_handler(struct MHD_Connection * connection) {
  struct MHD_Access_Handler * ah;
  unsigned int processed;

  if (connection->headersReceived == 0)
    abort(); /* bad timing... */
  ah = MHD_find_access_handler(connection);
  processed = connection->readLoc;
  if (MHD_NO == ah->dh(ah->dh_cls,
		       connection,
		       connection->url,
		       connection->method,
		       connection->version,
		       connection->read_buffer,
		       &processed)) {
    /* serios internal error, close connection */
    MHD_DLOG(connection->daemon,
	     "Internal application error, closing connection.");
    CLOSE(connection->socket_fd);
    connection->socket_fd = -1;
    return;
  }
  /* dh left "processed" bytes in buffer for next time... */
  memmove(connection->read_buffer,
	  &connection->read_buffer[connection->readLoc - processed],
	  processed);
  if (connection->uploadSize != -1)
    connection->uploadSize -= (connection->readLoc - processed);
  connection->readLoc = processed;
  if ( (connection->uploadSize == 0) ||
       ( (connection->readLoc == 0) &&
	 (connection->uploadSize == -1) &&
	 (connection->socket_fd == -1) ) ) {
    connection->bodyReceived = 1;
    connection->readLoc = 0;
    connection->read_buffer_size = 0;
    free(connection->read_buffer);
    connection->read_buffer = NULL;
  }
}


/**
 * This function handles a particular connection when it has been
 * determined that there is data to be read off a socket. All implementations
 * (multithreaded, external select, internal select) call this function
 * to handle reads.
 */
int
MHD_connection_handle_read(struct MHD_Connection * connection) {
  int bytes_read;
  void * tmp;

  if ( (connection->readLoc >= connection->read_buffer_size) &&
       (connection->headersReceived == 0) ) {
    /* need to grow read buffer */
    tmp = malloc(connection->read_buffer_size * 2 + MHD_MAX_BUF_SIZE);
    memcpy(tmp,
	   connection->read_buffer,
	   connection->read_buffer_size);
    connection->read_buffer_size = connection->read_buffer_size * 2 + MHD_MAX_BUF_SIZE;
    if (connection->read_buffer != NULL)
      free(connection->read_buffer);
    connection->read_buffer = tmp;
  }
  if (connection->readLoc >= connection->read_buffer_size) {
    MHD_DLOG(connection->daemon,
	     "Unexpected call to %s.\n",
	     __FUNCTION__);
    return MHD_NO;
  }
  bytes_read = RECV(connection->socket_fd,
		    &connection->read_buffer[connection->readLoc],
		    connection->read_buffer_size - connection->readLoc,
		    0);
  if (bytes_read < 0) {
    if (errno == EINTR)
      return MHD_NO;
    MHD_DLOG(connection->daemon,
	     "Failed to receive data: %s\n",
	     STRERROR(errno));
    CLOSE(connection->socket_fd);
    connection->socket_fd = -1;
    return MHD_YES;
  }
  if (bytes_read == 0) {
    /* other side closed connection */
    if (connection->readLoc > 0)
      MHD_call_connection_handler(connection);
    shutdown(connection->socket_fd, SHUT_RD);
    return MHD_YES;
  }
  connection->readLoc += bytes_read;
  if (connection->headersReceived == 0)
    MHD_parse_connection_headers(connection);
  if (connection->headersReceived == 1)
    MHD_call_connection_handler(connection);
  return MHD_YES;
}

/**
 * Check if we need to set some additional headers
 * for http-compiliance.
 */
static void
MHD_add_extra_headers(struct MHD_Connection * connection) {
  const char * have;
  char buf[128];

  if (connection->response->total_size == -1) {
    have = MHD_get_response_header(connection->response,
				   "Connection");
    if (have == NULL)
      MHD_add_response_header(connection->response,
			      "Connection",
			      "close");
  } else if (NULL == MHD_get_response_header(connection->response,
					     "Content-Length")) {
    _REAL_SNPRINTF(buf,
	     128,
	     "%llu",
	     (unsigned long long) connection->response->total_size);
    MHD_add_response_header(connection->response,
			    "Content-Length",
			    buf);
  }
}

/**
 * Allocate the connection's write buffer and
 * fill it with all of the headers from the
 * HTTPd's response.
 */
static void
MHD_build_header_response(struct MHD_Connection * connection) {
  size_t size;
  size_t off;
  struct MHD_HTTP_Header * pos;
  char code[32];
  char * data;

  MHD_add_extra_headers(connection);
  SPRINTF(code,
	  "HTTP/1.1 %u\r\n",
	  connection->responseCode);
  off = strlen(code);
  /* estimate size */
  size = off + 2; /* extra \r\n at the end */
  pos = connection->response->first_header;
  while (pos != NULL) {
    size += strlen(pos->header) + strlen(pos->value) + 4; /* colon, space, linefeeds */
    pos = pos->next;
  }
  /* produce data */
  data = malloc(size + 1);
  memcpy(data,
	 code,
	 off);
  pos = connection->response->first_header;
  while (pos != NULL) {
    SPRINTF(&data[off],
	    "%s: %s\r\n",
	    pos->header,
	    pos->value);
    off += strlen(pos->header) + strlen(pos->value) + 4;
    pos = pos->next;
  }
  sprintf(&data[off],
	  "\r\n");
  off += 2;
  if (off != size)
    abort();
  connection->write_buffer = data;
  connection->write_buffer_size = size;
}

/**
 * This function was created to handle writes to sockets when it has
 * been determined that the socket can be written to. All
 * implementations (multithreaded, external select, internal select)
 * call this function
 */
int
MHD_connection_handle_write(struct MHD_Connection * connection) {
  struct MHD_Response * response;
  int ret;

  response = connection->response;
  if(response == NULL) {
    MHD_DLOG(connection->daemon,
	     "Unexpected call to %s.\n",
	     __FUNCTION__);
    return MHD_NO;
  }
  if (! connection->headersSent) {
    if (connection->write_buffer == NULL)
      MHD_build_header_response(connection);
    ret = SEND(connection->socket_fd,
	       &connection->write_buffer[connection->writeLoc],
	       connection->write_buffer_size - connection->writeLoc,
	       0);
    if (ret < 0) {
      if (errno == EINTR)
	return MHD_YES;
      MHD_DLOG(connection->daemon,
	       "Failed to send data: %s\n",
	       STRERROR(errno));
      CLOSE(connection->socket_fd);
      connection->socket_fd = -1;
      return MHD_YES;
    }
    connection->writeLoc += ret;
    if (connection->writeLoc == connection->write_buffer_size) {
      connection->writeLoc = 0;
      free(connection->write_buffer);
      connection->write_buffer = NULL;
      connection->write_buffer_size = 0;
      connection->headersSent = 1;
    }
    return MHD_YES;
  }
  if (response->total_size <= connection->messagePos)
    abort(); /* internal error */
  if (response->crc != NULL)
    pthread_mutex_lock(&response->mutex);

  /* prepare send buffer */
  if ( (response->data == NULL) ||
       (response->data_start > connection->messagePos) ||
       (response->data_start + response->data_size < connection->messagePos) ) {
    if (response->data_size == 0) {
      if (response->data != NULL)
	free(response->data);
      response->data = malloc(MHD_MAX_BUF_SIZE);
      response->data_size = MHD_MAX_BUF_SIZE;
    }
    ret = response->crc(response->crc_cls,
			connection->messagePos,
			response->data,
			MAX(MHD_MAX_BUF_SIZE,
			    response->data_size - connection->messagePos));
    if (ret == -1) {
      /* end of message, signal other side by closing! */
      response->data_size = connection->messagePos;
      CLOSE(connection->socket_fd);
      connection->socket_fd = -1;
      if (response->crc != NULL)
	pthread_mutex_unlock(&response->mutex);
      return MHD_YES;
    }
    response->data_start = connection->messagePos;
    response->data_size = ret;
    if (ret == 0) {
      if (response->crc != NULL)
	pthread_mutex_unlock(&response->mutex);
      return MHD_YES;
    }
  }

  /* transmit */
  ret = SEND(connection->socket_fd,
	     &response->data[connection->messagePos - response->data_start],
	     response->data_size - (connection->messagePos - response->data_start),
	     0);
  if (response->crc != NULL)
    pthread_mutex_unlock(&response->mutex);
  if (ret < 0) {
    if (errno == EINTR)
      return MHD_YES;
    MHD_DLOG(connection->daemon,
	     "Failed to send data: %s\n",
	     STRERROR(errno));
    CLOSE(connection->socket_fd);
    connection->socket_fd = -1;
    return MHD_YES;
  }
  connection->messagePos += ret;
  if (connection->messagePos > response->data_size)
    abort(); /* internal error */
  if (connection->messagePos == response->data_size) {
    if ( (connection->bodyReceived == 0) ||
	 (connection->headersReceived == 0) )
      abort(); /* internal error */
    MHD_destroy_response(response);
    connection->responseCode = 0;
    connection->response = NULL;
    connection->headersReceived = 0;
    connection->headersSent = 0;
    connection->bodyReceived = 0;
    connection->messagePos = 0;
    free(connection->method);
    connection->method = NULL;
    free(connection->url);
    connection->url = NULL;
    free(connection->version);
    connection->version = NULL;
    free(connection->write_buffer);
    connection->write_buffer = NULL;
    connection->write_buffer_size = 0;
    if (connection->read_close != 0) {
      /* closed for reading => close for good! */
      CLOSE(connection->socket_fd);
      connection->socket_fd = -1;
    }
  }
  return MHD_YES;
}

/* end of connection.c */


