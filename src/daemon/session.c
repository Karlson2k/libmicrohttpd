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
 * @file session.c
 * @brief  Methods for managing sessions
 * @author Daniel Pittman
 * @author Christian Grothoff
 * @version 0.1.0
 */

#include "internal.h"
#include "session.h"
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
MHD_get_session_values(struct MHD_Session * session,
		       enum MHD_ValueKind kind,
		       MHD_KeyValueIterator iterator,
		       void * iterator_cls) {
  int ret;
  struct MHD_HTTP_Header * pos;

  if (session == NULL) 
    return -1;
  ret = 0;
  pos = session->headers_received;
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
MHD_lookup_session_value(struct MHD_Session * session,
			 enum MHD_ValueKind kind,
			 const char * key) {
  struct MHD_HTTP_Header * pos;

  if (session == NULL) 
    return NULL;
  pos = session->headers_received;
  while (pos != NULL) {
    if ( (0 != (pos->kind & kind)) &&
	 (0 == strcmp(key,
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
 * @param session the session identifying the client
 * @param status_code HTTP status code (i.e. 200 for OK)
 * @param response response to transmit
 * @return MHD_NO on error (i.e. reply already sent),
 *         MHD_YES on success or if message has been queued
 */
int 
MHD_queue_response(struct MHD_Session * session,
		   unsigned int status_code,
		   struct MHD_Response * response) {
  if ( (session == NULL) || 
       (response == NULL) ||
       (session->response != NULL) ||
       (session->bodyReceived == 0) ||
       (session->headers_received == 0) )
    return MHD_NO;	
  MHD_increment_response_rc(response);
  session->response = response;
  session->responseCode = status_code;
  return MHD_YES;
}


/**
 * Obtain the select sets for this session
 *
 * @return MHD_YES on success
 */
int 
MHD_session_get_fdset(struct MHD_Session * session,
		      fd_set * read_fd_set,
		      fd_set * write_fd_set,
		      fd_set * except_fd_set,
		      int * max_fd) {
  if ( (session->headers_received == 0) ||
       (session->readLoc < session->read_buffer_size) )
    FD_SET(session->socket_fd, read_fd_set);
  if (session->response != NULL) 
    FD_SET(session->socket_fd, write_fd_set);
  if ( (session->socket_fd > *max_fd) &&
       ( (session->headers_received == 0) ||
	 (session->readLoc < session->read_buffer_size) ||
	 (session->response != NULL) ) )
    *max_fd = session->socket_fd;
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
MHD_get_next_header_line(struct MHD_Session * session) {
  char * rbuf;
  size_t pos;
  size_t start;

  start = 0;
  pos = 0;
  rbuf = session->read_buffer;
  while ( (pos < session->readLoc - 1) &&
	  (rbuf[pos] != '\r') &&
	  (rbuf[pos] != '\n') )
    pos++;
  if (pos == session->readLoc) {
    /* not found, consider growing... */
    if (session->readLoc == session->read_buffer_size) {
      /* grow buffer to read larger header or die... */
      if (session->read_buffer_size < 4 * MHD_MAX_BUF_SIZE) {
	rbuf = malloc(session->read_buffer_size * 2);
	memcpy(rbuf,
	       session->read_buffer,
	       session->readLoc);
	free(session->read_buffer);
	session->read_buffer = rbuf;
	session->read_buffer_size *= 2;
      } else {
	/* die, header far too long to be reasonable */
	MHD_DLOG(session->daemon,
		 "Received excessively long header line (>%u), closing connection.\n",
		 4 * MHD_MAX_BUF_SIZE);
	close(session->socket_fd);
	session->socket_fd = -1;
      }
    }
    return NULL;
  }
  /* found, check if we have proper CRLF */
  rbuf = malloc(pos);
  memcpy(rbuf,
	 session->read_buffer,
	 pos-1);
  rbuf[pos-1] = '\0';
  if ( (rbuf[pos] == '\r') &&
       (rbuf[pos+1] == '\n') )
    pos++; /* skip both r and n */
  pos++; 
  memmove(session->read_buffer,
	  &session->read_buffer[pos],
	  session->readLoc - pos);
  session->readLoc -= pos;
  return rbuf;
}

/**
 * This function is designed to parse the input buffer of a given session.
 *
 * Once the header is complete, it should have set the
 * headers_received, url and method values and set 
 * headersReceived to 1.  If no body is expected, it should
 * also set "bodyReceived" to 1.  Otherwise, it should
 * set "uploadSize" to the expected size of the body.  If the
 * size of the body is unknown, it should be set to -1.
 */
static void
MHD_parse_session_headers(struct MHD_Session * session) {
  char * line;
  char * colon;
  char * uri;
  char * httpType;
  struct MHD_HTTP_Header * hdr;

  if (session->bodyReceived == 1)
    abort();
  while (NULL != (line = MHD_get_next_header_line(session))) {    
    if (session->url == NULL) {
      /* line must be request line */
      uri = strstr(line, " ");
      if (uri == NULL)
	goto DIE;
      uri[0] = '\0';
      session->method = strdup(line);
      uri++;
      httpType = strstr(uri, " ");
      if (httpType != NULL)
	httpType[0] = '\0';
      /* FIXME: parse URI some more here */
      session->url = strdup(uri);
      /* do we want to do anything with httpType? */
      free(line);
      continue;
    }
    /* check if this is the end of the header */
    if (strlen(line) == 0) {
      /* end of header */
      session->headersReceived = 1;
      /* FIXME: check with methods may have a body,
	 check headers to find out upload size */
      session->uploadSize = 0;
      session->bodyReceived = 1;
      free(line);
      break; 
    }
    /* ok, line should be normal header line, find colon */
    colon = strstr(line, ": ");
    if (colon == NULL) {
      /* error in header line, die hard */
      MHD_DLOG(session->daemon,
	       "Received malformed line (no colon), closing connection.\n");
      goto DIE;
    }
    /* zero-terminate header */
    colon[0] = '\0';
    colon += 2; /* advance to value */
    hdr = malloc(sizeof(struct MHD_HTTP_Header));
    hdr->next = session->headers_received;
    hdr->header = line;
    hdr->value = strdup(colon);
    hdr->kind = MHD_HEADER_KIND;
    session->headers_received = hdr;
  }
  /* FIXME: here: find cookie header and parse that! */
  if (session->bodyReceived == 0)
    return;
  return;
 DIE:
  close(session->socket_fd);
  session->socket_fd = -1;
}


/**
 * Find the handler responsible for this request.
 */ 
static struct MHD_Access_Handler * 
MHD_find_access_handler(struct MHD_Session * session) {
  struct MHD_Access_Handler * pos;

  pos = session->daemon->handlers;
  while (pos != NULL) {
    if (0 == strcmp(session->url,
		    pos->uri_prefix))
      return pos;
    pos = pos->next;
  }
  return &session->daemon->default_handler;
}

/**
 * Call the handler of the application for this
 * session. 
 */
void
MHD_call_session_handler(struct MHD_Session * session) {
  struct MHD_Access_Handler * ah;
  unsigned int processed;

  if (session->headers_received == 0)
    abort(); /* bad timing... */
  ah = MHD_find_access_handler(session);
  processed = session->readLoc;
  if (MHD_NO == ah->dh(ah->dh_cls,
		       session,
		       session->url,
		       session->method,
		       session->read_buffer,
		       &processed)) {
    /* serios internal error, close connection */
    MHD_DLOG(session->daemon,
	     "Internal application error, closing connection.");
    close(session->socket_fd);
    session->socket_fd = -1;
    return;
  }
  /* dh left "processed" bytes in buffer for next time... */
  memmove(session->read_buffer,
	  &session->read_buffer[session->readLoc - processed],
	  processed);
  session->readLoc = processed;
  session->uploadSize -= processed;
  if (session->uploadSize == 0) {
    session->bodyReceived = 1;
    session->readLoc = 0;
    session->read_buffer_size = 0;
    free(session->read_buffer);
    session->read_buffer = NULL;
  }
}


/**
 * This function handles a particular connection when it has been
 * determined that there is data to be read off a socket. All implementations
 * (multithreaded, external select, internal select) call this function
 * to handle reads. 
 */
int
MHD_session_handle_read(struct MHD_Session * session) {
  int bytes_read;
  void * tmp;
 

  if ( (session->readLoc >= session->read_buffer_size) &&
       (session->headers_received == 0) ) {
    /* need to grow read buffer */
    tmp = malloc(session->read_buffer_size * 2 + MHD_MAX_BUF_SIZE);
    memcpy(tmp,
	   session->read_buffer,
	   session->read_buffer_size);
    session->read_buffer_size = session->read_buffer_size * 2 + MHD_MAX_BUF_SIZE;
    if (session->read_buffer != NULL)
      free(session->read_buffer);
    session->read_buffer = tmp;
  }
  if (session->readLoc >= session->read_buffer_size) {
    MHD_DLOG(session->daemon,
	     "Unexpected call to %s.\n",
	     __FUNCTION__);
    return MHD_NO; 
  }
  bytes_read = recv(session->socket_fd,
		    &session->read_buffer[session->readLoc],
		    session->read_buffer_size - session->readLoc,
		    0);
  if (bytes_read < 0) {
    if (errno == EINTR)
      return MHD_NO;
    MHD_DLOG(session->daemon,
	     "Failed to receive data: %s\n",
	     strerror(errno));
    close(session->socket_fd);
    session->socket_fd = -1;
    return MHD_YES;
  }
  if (bytes_read == 0) {
    /* other side closed connection */
    /* FIXME: proper handling of end of upload!
       If we were receiving an unbounded upload,
       we should finish up nicely now! */
    close(session->socket_fd);
    session->socket_fd = -1;
    return MHD_YES;
  }
  session->readLoc += bytes_read;
  if (session->headersReceived == 0) 
    MHD_parse_session_headers(session);
  if (session->headersReceived == 1) 
    MHD_call_session_handler(session);
  return MHD_YES;
}

/**
 * Allocate the session's write buffer and
 * fill it with all of the headers from the
 * HTTPd's response.
 */
static void
MHD_build_header_response(struct MHD_Session * session) {
  size_t size;
  size_t off;
  struct MHD_HTTP_Header * pos;
  char code[32];
  char * data;

  sprintf(code,
	  "HTTP/1.1 %u\r\n", 
	  session->responseCode);
  off = strlen(code);
  /* estimate size */
  size = off + 2; /* extra \r\n at the end */
  pos = session->response->first_header;
  while (pos != NULL) {
    size += strlen(pos->header) + strlen(pos->value) + 4; /* colon, space, linefeeds */
    pos = pos->next;
  }
  /* produce data */
  data = malloc(size + 1);
  memcpy(data,
	 code,
	 off);
  pos = session->response->first_header;
  while (pos != NULL) {
    sprintf(&data[off],
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
  session->write_buffer = data;
  session->write_buffer_size = size;  
}

/**
 * This function was created to handle writes to sockets when it has
 * been determined that the socket can be written to. All
 * implementations (multithreaded, external select, internal select)
 * call this function
 */
int
MHD_session_handle_write(struct MHD_Session * session) {
  struct MHD_Response * response;
  int ret;

  response = session->response;
  if(response == NULL) {
    MHD_DLOG(session->daemon,
	     "Unexpected call to %s.\n",
	     __FUNCTION__);
    return MHD_NO;
  }
  if (! session->headersSent) {
    if (session->write_buffer == NULL)
      MHD_build_header_response(session);
    ret = send(session->socket_fd, 
	       &session->write_buffer[session->writeLoc],
	       session->write_buffer_size - session->writeLoc,
	       0);
    if (ret < 0) {
      if (errno == EINTR)
	return MHD_YES;
      MHD_DLOG(session->daemon,
	       "Failed to send data: %s\n",
	       strerror(errno));
      close(session->socket_fd);
      session->socket_fd = -1;
      return MHD_YES;
    }
    session->writeLoc += ret;
    if (session->writeLoc == session->write_buffer_size) {
      session->writeLoc = 0;
      free(session->write_buffer);
      session->write_buffer = NULL;
      session->write_buffer_size = 0;
      session->headersSent = 1;
    }
    return MHD_YES;
  }
  if (response->total_size <= session->messagePos) 
    abort(); /* internal error */
  if (response->crc != NULL)
    pthread_mutex_lock(&response->mutex);    

  /* prepare send buffer */
  if ( (response->data == NULL) ||
       (response->data_start > session->messagePos) ||
       (response->data_start + response->data_size < session->messagePos) ) {
    if (response->data_size == 0) {
      if (response->data != NULL)
	free(response->data);
      response->data = malloc(MHD_MAX_BUF_SIZE);
      response->data_size = MHD_MAX_BUF_SIZE;
    }
    ret = response->crc(response->crc_cls,
			session->messagePos,
			response->data,
			MAX(MHD_MAX_BUF_SIZE,
			    response->data_size - session->messagePos));
    if (ret == -1) {
      /* end of message, signal other side by closing! */
      response->data_size = session->messagePos;
      close(session->socket_fd);
      session->socket_fd = -1;
      return MHD_YES;
    }
    response->data_start = session->messagePos;
    response->data_size = ret;
    if (ret == 0)
      return MHD_YES; 
  }
  
  /* transmit */
  ret = send(session->socket_fd, 
	     &response->data[session->messagePos - response->data_start],
	     response->data_size - (session->messagePos - response->data_start),
	     0);
  if (response->crc != NULL)
    pthread_mutex_unlock(&response->mutex);    
  if (ret < 0) {
    if (errno == EINTR)
      return MHD_YES;
    MHD_DLOG(session->daemon,
	     "Failed to send data: %s\n",
	     strerror(errno));
    close(session->socket_fd);
    session->socket_fd = -1;
    return MHD_YES;
  }
  session->messagePos += ret;
  if (session->messagePos > response->data_size) 
    abort(); /* internal error */
  if (session->messagePos == response->data_size) {
    if ( (session->bodyReceived == 0) ||
	 (session->headers_received == 0) )
      abort(); /* internal error */
    MHD_destroy_response(response);
    session->responseCode = 0;
    session->response = NULL;
    session->headersReceived = 0;
    session->headersSent = 0;
    session->bodyReceived = 0;
    session->messagePos = 0;
    free(session->method);
    session->method = NULL;
    free(session->url);
    session->url = NULL;
    free(session->write_buffer);
    session->write_buffer = NULL;
    session->write_buffer_size = 0;
  }
  return MHD_YES;
}

/* end of session.c */


