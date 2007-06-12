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


#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdarg>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>

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
		       MHD_KeyValueIterator * iterator,
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
  ret = 0;
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
     reading/writing; plenty of cases to handle! */
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

	return numBytes;
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
static int
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
    memmove(session->readBuffer,
	    &session->readBuffer[session->readLoc - processed],
	    processed);
    session->readLoc = processed;
    session->uploadSize -= processed;
    /* FIXME: proper handling of end of upload! */
  }
  return MHD_YES;
}


/**
 * This function was created to handle writes to sockets when it has been
 * determined that the socket can be written to. If there is no data
 * to be written, however, the function call does nothing. All implementations
 * (multithreaded, external select, internal select) call this function
 */
int
MHD_session_handle_write(struct MHD_Session * session) {
  struct MHD_Response * response;
  int i;
  char * buffer[2048];
  char * responseMessage;
  int numBytesInMessage;

  response = session->response;
  if(response == NULL) {
    /* FIXME: LOG: why are we here? */
    return MHD_NO;
  }
  numBytesInMessage = 25;
  responseMessage = malloc(25);

	pthread_mutex_lock(&response->mutex);	

	if(!response->headersSent) {
		sprintf(responseMessage, "HTTP/1.1 %i Go to hell!\r\n", response->responseCode);
		fprintf(stderr, "%s\n", responseMessage);
		if(send(session->socket_fd, responseMessage, strlen(responseMessage), 0) != strlen(responseMessage)) {
			fprintf(stderr, "Error! could not send an entire header in one call to send! unable to handle this case as of this time.\n");
			pthread_mutex_unlock(&response->mutex);
			return MHD_NO;
		}

		for(i = 0; i < MHD_MAX_HEADERS; i++) {
			if(response->headers[i] == NULL)
				continue;

			if(strlen(response->headers[i]->header) + strlen(response->headers[i]->value) + 5 > numBytesInMessage) {
				free(responseMessage);
				responseMessage = malloc(strlen(response->headers[i]->header) + strlen(response->headers[i]->value) + 5);
				if(responseMessage == NULL) {
					 if(daemon->options & MHD_USE_DEBUG)
				       fprintf(stderr, "Error allocating memory!\n");
	    			 pthread_mutex_unlock(&response->mutex);
				    return MHD_NO;
				}				
				numBytesInMessage = strlen(response->headers[i]->header) + strlen(response->headers[i]->value) + 5;
			}
			sprintf(responseMessage, "%s: %s\r\n", response->headers[i]->header, response->headers[i]->value);
			fprintf(stderr, "%s\n", responseMessage);
			if(send(session->socket_fd, responseMessage, strlen(responseMessage), 0) != strlen(responseMessage)) {
				fprintf(stderr, "Error! could not send an entire header in one call to send! unable to handle this case as of this time.\n");
				pthread_mutex_unlock(&response->mutex);
				return MHD_NO;
			}
		}
		
		response->headersSent = 1;
	}

	if(response->data != NULL) {
		if(response->bytesSentSoFar == 0) {
			if(numBytesInMessage < 32) {
				free(responseMessage);
				responseMessage = malloc(32);	
				if(responseMessage == NULL) {
					 if(daemon->options & MHD_USE_DEBUG)
				       fprintf(stderr, "Error allocating memory!\n");
	    			 pthread_mutex_unlock(&response->mutex);
				    return MHD_NO;
				}					
			}
			sprintf(responseMessage, "Content-length: %llu\r\n\r\n", (unsigned long long)response->size);
			fprintf(stderr, "%s\n", responseMessage);
			if(send(session->socket_fd, responseMessage, strlen(responseMessage),0)!= strlen(responseMessage)) {
				fprintf(stderr, "Error! could not send an entire header in one call to send! unable to handle this case as of this time.\n");
				pthread_mutex_unlock(&response->mutex);
				return MHD_NO;
			}			
		}
		
		i = send(session->socket_fd, response->data+response->bytesSentSoFar, response->size-response->bytesSentSoFar,0);
		response->bytesSentSoFar += i;

		fprintf(stderr, "Sent %i bytes of data\nTotal to send is %llu bytes\n", i, (unsigned long long)response->size);

		if(response->bytesSentSoFar == response->size) {
			session->currentResponses[session->currentResponse] = NULL;
			session->currentResponse = (session->currentResponse + 1) % MHD_MAX_RESPONSE;
			response->currentSession = NULL;		

			if(response->freeWhenFinished) {
				pthread_mutex_unlock(&response->mutex);				
				MHD_destroy_response(response); 
			}
			/*THIS NEEDS TO BE HANDLED ANOTHER WAY!!! TIMEOUT, ect..., as of now this is the only way to get test case to work
			 * since client never disconnects on their own!
			 */
			if(session->currentResponses[session->currentResponse] == NULL) {
				MHD_destroy_session(session);
				daemon->connections[connection_id] = NULL;
				return MHD_NO;
			}						
		}
	} else {
		if(response->crc == NULL) {
			pthread_mutex_unlock(&response->mutex);
			return MHD_NO;
		}

		if(response->bytesSentSoFar == 0) {
			if(send(session->socket_fd, "\r\n", response->size,0) != 2) {
				fprintf(stderr, "Error! could not send an entire header in one call to send! unable to handle this case as of this time.\n");
				pthread_mutex_unlock(&response->mutex);
				return MHD_NO;
			}					
		}
		memset(buffer, 0, 2048);

		i = response->crc(response->crc_cls, response->bytesSentSoFar, (char *)buffer, 2048);

		if(i == -1) {
			pthread_mutex_unlock(&response->mutex);
				
			session->currentResponses[session->currentResponse] = NULL;
			session->currentResponse = (session->currentResponse + 1) % MHD_MAX_RESPONSE;		
			response->currentSession = NULL;			

			if(response->freeWhenFinished) {
				pthread_mutex_unlock(&response->mutex);
				MHD_destroy_response(response);
			}
			/*THIS NEEDS TO BE HANDLED ANOTHER WAY!!! TIMEOUT, ect..., as of now this is the only way to get test case to work
			 * since client never disconnects on their own!
			 */
			if(session->currentResponses[session->currentResponse] == NULL) {
				MHD_destroy_session(session);
				daemon->connections[connection_id] = NULL;
				return MHD_NO;
			}

		} else {
			i = send(session->socket_fd, buffer, i,0);
			response->bytesSentSoFar += i;				
		}
	}
	pthread_mutex_unlock(&response->mutex);	
	return MHD_YES;	
}




