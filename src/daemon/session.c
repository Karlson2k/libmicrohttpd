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

#include "microhttpd.h"
#include "session.h"
#include "response.h"
#include "internal.h"
#include "config.h"


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
       (session->response != NULL) )
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
  /* FIXME: need to be VERY careful here
     determining when the socket is ready for
     reading/writing; plenty of cases to handle!
     (the current code is one big bug) */
  FD_SET(session->socket_fd, read_fd_set);
  FD_SET(session->socket_fd, write_fd_set);
  if (session->socket_fd > *max_fd)
    *max_fd = session->socket_fd;
  return MHD_YES;
}



/* FIXME: implement/fix code below this line! */


/**
 * This function needs to do a lot more (i.e. break up get arguments)
 * but for now just seperates the prefix of the url from the document
 * portion.
 */
static void
MHD_parse_URL(struct MHD_Session * session) {
#if 0
	char * working;
	int pos,i;

	working = session->headers[0]->value;

	pos = 0;
	for(i = 0; i < strlen(working); i++) {
		if(working[i] == '/')
			pos = i+1;
	}
	if(pos >= strlen(working))
			pos = 0;

	session->documentName = session->headers[0]->value+pos;
#endif
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
#if 0
  const char * crlfcrlf = "\r\n\r\n";
  const char * crlf = "\r\n";

	char * saveptr;
  	char * saveptr1;

	struct MHD_HTTP_Header * newHeader;
	char * curTok;
   char * curTok1;

	int numBytes;

	curTok = strstr(session->inbuf, crlfcrlf);

	if(curTok == NULL) {
		return -1;
	} 

	memset(curTok+2, 0, 2);

	numBytes = strlen(session->inbuf) + 2;

	curTok = strtok_r(session->inbuf, crlf, &saveptr);

	session->requestType = strtok_r(curTok, " ", &saveptr1);
	
	newHeader = (struct MHD_HTTP_Header *)malloc(sizeof(struct MHD_HTTP_Header));
	if(newHeader == NULL) {
		if(session->daemon->options & MHD_USE_DEBUG)
			fprintf(stderr, "Error allocating memory!\n");
		return -1;
	}		
	newHeader->kind = MHD_GET_ARGUMENT_KIND;
	newHeader->header = session->requestType;
	newHeader->value = strtok_r(NULL, " ", &saveptr1);

	session->headers[session->firstFreeHeader++] = newHeader;

	curTok = strtok_r(NULL, crlf, &saveptr);
	while(curTok != NULL && session->firstFreeHeader < MHD_MAX_HEADERS) {
		curTok1 = strtok_r(curTok, ":", &saveptr1);
		newHeader = (struct MHD_HTTP_Header *)malloc(sizeof(struct MHD_HTTP_Header));
		if(newHeader == NULL) {
			if(session->daemon->options & MHD_USE_DEBUG)
				fprintf(stderr, "Error allocating memory!\n");
			return -1;
		}			
		newHeader->header = curTok1;
		newHeader->value = curTok + strlen(curTok1) + 2;
		//For now, everything is a get!
		newHeader->kind = MHD_GET_ARGUMENT_KIND;
		session->headers[session->firstFreeHeader++] = newHeader;
		curTok = strtok_r(NULL, crlf, &saveptr);
	}	
#endif
}


/**
 * Find the handler responsible for this request.
 */ 
static struct MHD_Access_Handler * 
MHD_find_access_handler(struct MHD_Session * session) {
  /* FIXME: do real lookup based on URI! */
  return &session->daemon->default_handler;
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
  struct MHD_Access_Handler * ah;
  unsigned int processed;

  if (session->bodyReceived) {
    /* FIXME: LOG: why are we in select set? */
    return MHD_NO; 
  }
  if (session->readLoc >= session->read_buffer_size) {
    /* need to grow read buffer */
    tmp = malloc(session->read_buffer_size * 2 + MHD_MAX_BUF_SIZE);
    memcpy(tmp,
	   session->read_buffer,
	   session->read_buffer_size);
    session->read_buffer_size = session->read_buffer_size * 2 + MHD_MAX_BUF_SIZE;
  }
  bytes_read = recv(session->socket_fd,
		    &session->read_buffer[session->readLoc],
		    session->read_buffer_size - session->readLoc,
		    0);
  if (bytes_read < 0) {
    if (errno == EINTR)
      return MHD_NO;
    /* FIXME: log error */
    return MHD_NO;
  }
  if (bytes_read == 0) {
    /* other side closed connection */
    close(session->socket_fd);
    session->socket_fd = -1;
    return MHD_NO;
  }
  session->readLoc += bytes_read;
  if (session->headersReceived == 0) 
    MHD_parse_session_headers(session);
  if (session->headersReceived == 1) {
    ah = MHD_find_access_handler(session);
    processed = session->readLoc;
    if (MHD_NO == ah->dh(ah->dh_cls,
			 session,
			 session->url,
			 session->method,
			 session->read_buffer,
			 &processed)) {
      /* serios error, close connection */
      close(session->socket_fd);
      session->socket_fd = -1;
      return MHD_NO;
    }
    /* dh left "processed" bytes in buffer for next time... */
    memmove(session->read_buffer,
	    &session->read_buffer[session->readLoc - processed],
	    processed);
    session->readLoc = processed;
    session->uploadSize -= processed;
    /* FIXME: proper handling of end of upload! */
  }
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
  data = malloc(size);
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
    /* FIXME: LOG: why are we here? */
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
      /* FIXME: log error */
      close(session->socket_fd);
      session->socket_fd = -1;
      return MHD_NO;
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
      return MHD_YES; /* or NO? */
  }
  
  /* transmit */
  ret = send(session->socket_fd, 
	     &response->data[session->messagePos - response->data_start],
	     response->data_size - (session->messagePos - response->data_start),
	     0);
  if (response->crc != NULL)
    pthread_mutex_unlock(&response->mutex);    
  if (ret == -1) {
    if (errno == EINTR)
      return MHD_YES;
    /* FIXME: log */
    return MHD_NO;
  }
  session->messagePos += ret;
  if (session->messagePos == response->data_size) {
    /* reset session, wait for next request! */
    MHD_destroy_response(response);
    session->responseCode = 0;
    session->response = NULL;
    session->headersReceived = 0;
    session->headersSent = 0;
    session->bodyReceived = 0;
    session->messagePos = 0;
    free(session->write_buffer);
    session->write_buffer = NULL;
    session->write_buffer_size = 0;
  }
  return MHD_YES;
}

/* end of session.c */


