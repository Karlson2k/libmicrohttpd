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
 * @file daemon.c
 * @brief  This is my implementation of the libmicrohttpd interface. Many features incomplete at this time. 
 * @author Daniel Pittman
 * @version 0.1.0
 */

#include "config.h"
#include "microhttpd.h"

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>


#define MHD_MAX_CONNECTIONS FD_SETSIZE -4 
#define MHD_MAX_BUF_SIZE 2048
#define MHD_MAX_HEADERS 1024
#define MHD_MAX_HANDLERS 1024
#define MHD_MAX_RESPONSE 1024


int MHD_handle_read(int, struct MHD_Daemon *);
int MHD_handle_write(int, struct MHD_Daemon *);
void * MHD_spawn_connections(void * data);
void * MHD_select(void * data);
int MHD_parse_message(struct MHD_Session * session);
void MHD_parse_URL(struct MHD_Session * session);

struct MHD_Daemon {
	unsigned int options;

	unsigned short port;
	int socket_fd;
	int max_fd;	

	MHD_AcceptPolicyCallback apc;
	void * apc_cls;
	
	fd_set read_fd_set;
	fd_set write_fd_set;
	fd_set except_fd_set;
	
	int shutdown;
	pthread_t pid;

	struct MHD_Session * connections[MHD_MAX_CONNECTIONS];

	int firstFreeHandler;
	struct MHD_Access_Handler * handlers[MHD_MAX_HANDLERS];
	MHD_AccessHandlerCallback dh;
	void * dh_cls;
};

struct MHD_Session {
	struct sockaddr_in addr;

	int readLoc;
	int writeLoc;

	int id;
	int socket_fd;
	pthread_t pid;

	struct MHD_Daemon * daemon;

	int bufPos;
	int messagePos;
	char inbuf[MHD_MAX_BUF_SIZE];

	int firstFreeHeader;
	char * requestType;
	char * documentName;
	struct MHD_HTTP_Header * headers[MHD_MAX_HEADERS];

	unsigned short responsePending;
	int currentResponse;
	struct MHD_Response * currentResponses[MHD_MAX_RESPONSE];
};


struct MHD_Response {
	pthread_mutex_t mutex;

	unsigned int responseCode;

	int freeWhenFinished;
	
	unsigned int headersSent;

	size_t size;
	void * data;
	int bytesSentSoFar;

	int must_free;
	MHD_ContentReaderCallback crc;

	void * crc_cls;
	MHD_ContentReaderFreeCallback crfc;

	int firstFreeHeader;
	struct MHD_HTTP_Header * headers[MHD_MAX_HEADERS];

	struct MHD_Session * currentSession;
};

struct MHD_Access_Handler {
	char * uri_prefix;
	MHD_AccessHandlerCallback dh;
	void * dh_cls;
};

struct MHD_HTTP_Header {
	char * header;
	char * headerContent;
	enum MHD_ValueKind kind;
};

/**
 * Add a header line to the response.
 *
 * @return MHD_NO on error (i.e. invalid header or content format).
 */
int
MHD_add_response_header(struct MHD_Response * response,
			const char * header,
			const char * content) {
	//Note that as of this time this function will also return 
	//an error if the maximum number of headers allowed is exceeded.

	char * saveptr;
	char * newHeader;
	char * newContent;
	int i;

	if(response == NULL || header == NULL || content == NULL || strlen(header) == 0 || strlen(content) == 0) {
		return MHD_NO;
	}
	/* CG: use linked list to avoid limitation and over-allocation! */
	if(response->firstFreeHeader >= MHD_MAX_HEADERS) {
		return MHD_NO;
	}

	newHeader = (char *)malloc(strlen(header)+1);
	newContent = (char *)malloc(strlen(content)+1);
	/* CG: useless check! */
	if(newHeader == NULL || newContent == NULL) {
	  /* CG: printf! */
	       fprintf(stderr, "Error allocating memory!\n");
	       return MHD_NO;
	}

	/* CG: do you mean strcpy/strdup? defer allocation
	   until you need to  (after malformed checks!) */
	sprintf(newHeader, "%s", header);
	sprintf(newContent, "%s", content);

	/* CG: why not use strstr? */
	if(strtok_r(newHeader, " \t\r\n", &saveptr) !=  NULL) {
		fprintf(stderr, "Malformed header!\n"); 
		free(newContent);
		free(newHeader);
		return MHD_NO;
	}

	/* CG: why not use strstr? */
	if(strtok_r(newContent, "\n", &saveptr) !=  NULL) {
		fprintf(stderr, "Malformed content!\n"); 
		free(newContent);
		free(newHeader);		
		return MHD_NO;
	}	

	/* CG: this is not C++ -- no need to cast after malloc! */
	struct MHD_HTTP_Header * newHTTPHeader = (struct MHD_HTTP_Header *)malloc(sizeof(struct MHD_HTTP_Header));

	if(newHTTPHeader == NULL) {
	  /* CG: useless check, printf */
	       fprintf(stderr, "Error allocating memory!\n");
	       free(newContent);
	       free(newHeader);
	       return MHD_NO;
	}

	/* CG: strdup here, avoids free's above! */
	response->headers[response->firstFreeHeader]->header = newHeader;
	response->headers[response->firstFreeHeader]->headerContent = newContent;

	//For now, everything is a HTTP Header... this needs to be improved!
	/* CG: what else are you thinking about? Cookies?
	   sounds like you are proposing an API change!!! */

	response->headers[response->firstFreeHeader]->kind = MHD_HEADER_KIND;

	/* CG: YUCK! Yet another reason for linked lists...
	   Why bother with the firstFreeHandler field if
	   you're O(n) anyway!? */
	response->firstFreeHeader=MHD_MAX_HEADERS;
	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		if(response->headers[i] == NULL) {
			response->firstFreeHeader = i;
			break;
		} 
	}

	return MHD_YES;
}

/**
 * This function accepts an incoming connection
 * and creates the MHD_Session object for it.
 * It also enforces policy by way of calling the accept policy callback
 */
int
MHD_create_connection(struct MHD_Daemon * daemon) {
	int i, first_free, size;

	if(daemon == NULL) 
		return -1;

   first_free = -1;
	for(i = 0; i < MHD_MAX_CONNECTIONS; i++) {
		if(daemon->connections[i] == NULL) {
			first_free = i;
			break;
		}
	}

	if(first_free == -1) 
		return -1;

	/* CG: delay allocation until at accept has succeeded! */
	daemon->connections[first_free] = (struct MHD_Session *)malloc(sizeof(struct MHD_Session));

	if(daemon->connections[first_free] == NULL) {
	  /* CG: use MACRO or (static) helper function
	     instead of writing this option check everywhere! */
		if((daemon->options & MHD_USE_DEBUG) != 0)
	        	fprintf(stderr, "Error allocating memory!\n");
	        return -1;
	}
	
	size = sizeof(struct sockaddr);
	daemon->connections[first_free]->socket_fd = 
	 
	accept(daemon->socket_fd, (struct sockaddr *)&daemon->connections[first_free]->addr, 
		(socklen_t *)&size); 
	
	if(daemon->connections[first_free]->socket_fd == -1) {
		free(daemon->connections[first_free]);
		daemon->connections[first_free] = NULL;
		if((daemon->options & MHD_USE_DEBUG) != 0) {
			fprintf(stderr, "Error accepting incoming connections!\n"); 
		}	
		return -1;
	}
	
	if(daemon->apc != NULL && daemon->apc(daemon->apc_cls, (const struct sockaddr *)&daemon->connections[first_free]->addr, (socklen_t)sizeof(struct sockaddr_in))==MHD_NO) {
		close(daemon->connections[first_free]->socket_fd);
		free(daemon->connections[first_free]);
		daemon->connections[first_free] = NULL;
		if((daemon->options & MHD_USE_DEBUG) != 0) {
			fprintf(stderr, "Connection denied based on accept policy callback!\n"); 
		}	
		return -1;
	}
	
	daemon->connections[first_free]->id = first_free;
	daemon->connections[first_free]->daemon = daemon;
	daemon->connections[first_free]->pid = (pthread_t)-1;
	daemon->connections[first_free]->bufPos = 0;
	daemon->connections[first_free]->messagePos= 0;
	daemon->connections[first_free]->responsePending = 0;
	memset(daemon->connections[first_free]->inbuf, '\0', MHD_MAX_BUF_SIZE);
	daemon->connections[first_free]->currentResponse = 0;
	daemon->connections[first_free]->firstFreeHeader = 0;

	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		daemon->connections[first_free]->headers[i] = NULL;
	}

	for(i = 0; i < MHD_MAX_RESPONSE; i++) {
		daemon->connections[first_free]->currentResponses[i] = NULL;
	}
	/* CG: maybe better to re-compute max_fd closer to select;
	   also handles deletion mo re graceful, need to iterate over
	   all connections anyway for FD_SET... */
	if(daemon->max_fd < daemon->connections[first_free]->socket_fd) {
		daemon->max_fd = daemon->connections[first_free]->socket_fd;
	}

	return first_free;
}

/**
 * Create a response object.  The response object can be extended with
 * header information and then be used any number of times.
 *
 * @param size size of the data portion of the response, -1 for unknown
 * @param crc callback to use to obtain response data
 * @param crc_cls extra argument to crc
 * @param crfc callback to call to free crc_cls resources
 * @return NULL on error (i.e. invalid arguments, out of memory)
 */
struct MHD_Response *
MHD_create_response_from_callback(size_t size,
				  MHD_ContentReaderCallback crc,
				  void * crc_cls,
				  MHD_ContentReaderFreeCallback crfc) {
	
	struct MHD_Response * retVal;
	int i;


	if(crc == NULL) {
	  /* CG: printf! */
            fprintf(stderr, "A ContentReaderCallback must be provided to MHD_create_response_from_callback!\n");
	    return NULL;
	}

	retVal = (struct MHD_Response *) malloc(sizeof(struct MHD_Response));
	if(retVal == NULL) {
	  /* CG: printf, useless check, useless cast */
           fprintf(stderr, "Error allocating memory!\n");
	   return NULL;
	}

	retVal->size  = size;

	retVal->crc = crc;
	retVal->crc_cls = crc_cls;

	retVal->crfc = crfc;

	retVal->firstFreeHeader = 0;
	
	retVal->responseCode = 0;

	retVal->headersSent = 0;

	retVal->bytesSentSoFar = 0;

	retVal->freeWhenFinished = 0;
	retVal->currentSession = NULL;

	if(pthread_mutex_init(&retVal->mutex, NULL) != 0) {
	   fprintf(stderr, "Error initializing mutex!\n");
           free(retVal);
	   return NULL;
	}
	/* CG: use memset? linked list!!? */
	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		retVal->headers[i] = NULL;
	}

	retVal->data = NULL;
	retVal->must_free = 0;

	return retVal;	
}

/**
 * Create a response object.  The response object can be extended with
 * header information and then be used any number of times.
 *
 * @param size size of the data portion of the response
 * @param data the data itself
 * @param must_free libmicrohttpd should free data when done
 * @param must_copy libmicrohttpd must make a copy of data 
 *        right away, the data maybe released anytime after
 *        this call returns
 * @return NULL on error (i.e. invalid arguments, out of memory)
 */
struct MHD_Response *
MHD_create_response_from_data(size_t size,
			      void * data,
			      int must_free,
			      int must_copy) {

	struct MHD_Response * retVal;
	int i;


	if(data == NULL) {
            fprintf(stderr, "data must be provided to MHD_Create_response_from_data!\n");
	    return NULL;
	}

	retVal = (struct MHD_Response *) malloc(sizeof(struct MHD_Response));
	if(retVal == NULL) {
            fprintf(stderr, "Error allocating memory!\n");
	    return NULL;
	}

	retVal->size  = size;

	retVal->crc = NULL;
	retVal->crc_cls = NULL;
	retVal->crfc = NULL;

	retVal->responseCode = 0;

	retVal->firstFreeHeader = 0;
	retVal->freeWhenFinished = 0;
	retVal->currentSession = NULL;

	retVal->headersSent = 0;

	retVal->bytesSentSoFar = 0;

	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		retVal->headers[i] = NULL;
	}

	if(pthread_mutex_init(&retVal->mutex, NULL) != 0) {
	   fprintf(stderr, "Error initializing mutex!\n");
           free(retVal);
	   return NULL;
	}

	if(must_copy) {
		retVal->data = malloc(size);
		if(retVal->data == NULL) {
          fprintf(stderr, "Error allocating memory!\n");
			 free(retVal);
		    return NULL;
		}		
		memcpy(retVal->data, data, size);
		retVal->must_free = 1;
	} else {
		retVal->data = data;
		retVal->must_free = must_free;
	}

	return retVal;
}

/**
 * Delete a header line from the response.
 *
 * @return MHD_NO on error (no such header known)
 */
int
MHD_del_response_header(struct MHD_Response * response,
			const char * header,
			const char * content) {
	int i;

	if(header == NULL || content == NULL) {
		return MHD_NO;
	}
	
	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		if(response->headers[i] != NULL && 
			strncmp(header, response->headers[i]->header, strlen(header)) == 0 && 
			strncmp(content, response->headers[i]->headerContent, strlen(header)) == 0) {
			free(response->headers[i]->header);
			free(response->headers[i]->headerContent);
			free(response->headers[i]);
			response->headers[i] = NULL;
			return MHD_YES;
		}
	}
	return MHD_NO;
}

/**
 * Destroy a response object and associated resources.  Note that
 * libmicrohttpd may keep some of the resources around if the response
 * is still in the queue for some clients, so the memory may not
 * necessarily be freed immediatley.
 */
void
MHD_destroy_response(struct MHD_Response * response) {
	int i;

	if(response == NULL) {
		return;
	}

	pthread_mutex_lock(&response->mutex);

	if(response->currentSession != NULL) {
		response->freeWhenFinished = 1;
		pthread_mutex_unlock(&response->mutex);
		return;
	} 

	if(response->must_free && response->data != NULL) {
		free(response->data);
	}
	
	if(response->crfc != NULL && response->crc_cls != NULL) {
		response->crfc(response->crc_cls);
	}

	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		if(response->headers[i] == NULL)
			continue;

		free(response->headers[i]->header);
		free(response->headers[i]->headerContent);
		free(response->headers[i]);
	}

	pthread_mutex_unlock(&response->mutex);
	pthread_mutex_destroy(&response->mutex);

	free(response);
}

/**
 * Thi function is similar to destroy_response except
 * that it was created to destroy the session object.
 */
void 
MHD_destroy_session(struct MHD_Session * session) {
	int i;

	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		if(session->headers[i] != NULL) {
			free(session->headers[i]);
		}
	}

	for(i = 0; i < MHD_MAX_RESPONSE; i++) {
		if(session->currentResponses[i] != NULL) {
			pthread_mutex_lock(&session->currentResponses[i]->mutex);
			session->currentResponses[i]->currentSession = NULL;
			pthread_mutex_unlock(&session->currentResponses[i]->mutex);
		}
	}
	
	close(session->socket_fd);
	free(session);
}

/**
 * Obtain the select sets for this daemon.
 *
 * @return MHD_YES on success, MHD_NO if this
 *         daemon was not started with the right
 *         options for this call.
 */
int 
MHD_get_fdset(struct MHD_Daemon * daemon,
	      fd_set * read_fd_set,
	      fd_set * write_fd_set,
	      fd_set * except_fd_set,
	      int * max_fd) {

	int i;

	if(daemon == NULL || read_fd_set == NULL || write_fd_set == NULL || except_fd_set == NULL || max_fd == NULL) {
		return MHD_NO;
	}

	if((daemon->options & MHD_USE_THREAD_PER_CONNECTION) != 0) {
		return MHD_NO;
	}

	FD_ZERO(read_fd_set);
	FD_ZERO(write_fd_set);
	FD_ZERO(except_fd_set);

	FD_SET(daemon->socket_fd, &daemon->read_fd_set);
	for(i = 0; i < MHD_MAX_CONNECTIONS; i++) {
		if(daemon->connections[i] != NULL) {
			FD_SET(daemon->connections[i]->socket_fd, read_fd_set);
			FD_SET(daemon->connections[i]->socket_fd, write_fd_set);
		}
	}		

	*max_fd = daemon->max_fd;

   return MHD_YES;
}

/**
 * Get all of the headers added to a response.
 *
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to iterator
 * @return number of entries iterated over
 */ 
int
MHD_get_response_headers(struct MHD_Response * response,
			 MHD_KeyValueIterator * iterator,
			 void * iterator_cls) {
	int i, numHeaders;

	if(response == NULL) {
		return -1;
	}

	numHeaders = 0;
	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		if(response->headers[i] != NULL) {
			if(iterator != NULL) {
				(*iterator)(iterator_cls, response->headers[i]->kind, response->headers[i]->header, response->headers[i]->headerContent);
			}
			numHeaders++;
		}
	}
	return numHeaders;
}

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
	int i, numHeaders;

	if(session == NULL) {
		return -1;
	}
	numHeaders = 0;
	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		if(session->headers[i] != NULL && session->headers[i]->kind == kind) {
			if(iterator != NULL) {
				(*iterator)(iterator_cls, session->headers[i]->kind, session->headers[i]->header, session->headers[i]->headerContent);
			}
			numHeaders++;
		}
	}
	return numHeaders;
}

/**
 * This function is intented to be called in the case of 
 * multithreaded connections. A thread will be spawned calling this 
 * function with a particular connection, and the thread will poll the connection
 * (this should be improved) until there is something to do
 */
void *
MHD_handle_connection(void * data) {
	struct MHD_Session * con;
	int num_ready;
	struct timeval timeout;
	fd_set read;
	fd_set write;

	con = data;

	if(con == NULL)
		return NULL;

	do {

		FD_ZERO(&read);
		FD_ZERO(&write);

		FD_SET(con->socket_fd, &read);
		FD_SET(con->socket_fd, &write);
	
		timeout.tv_sec = 0;
		timeout.tv_usec = 0; 		

		num_ready = select(con->socket_fd + 1,
				&read, &write, NULL, &timeout);

		if(num_ready > 0) {
			if(FD_ISSET(con->socket_fd, &read)) {
				if(MHD_handle_read(con->id, con->daemon) == MHD_NO) {
					pthread_detach(pthread_self());
					return NULL;
				}
			}
			if (FD_ISSET(con->socket_fd, &write)) {
				if(MHD_handle_write(con->id, con->daemon) == MHD_NO) {
					pthread_detach(pthread_self());
					return NULL;
				}
			}
		}
	} while (!con->daemon->shutdown);

   return NULL;
}

/**
 * This function is created to handle the except file descriptor
 * set, but it is doubtfull that it will ever be used.
 */
void
MHD_handle_except(int connection_id, struct MHD_Daemon * daemon) {
	//It is unlikely that this function will ever need to be implemented. 
}

/**
 * This function handles a particular connection when it has been
 * determined that there is data to be read off a socket. All implementations
 * (multithreaded, external select, internal select) call this function
 * to handle reads. 
 */
int
MHD_handle_read(int connection_id, struct MHD_Daemon * daemon) {
	int bytes_read,i;

	if((daemon->options & MHD_USE_DEBUG) != 0) {
		fprintf(stderr, "Enter MHD_handle_read\n");
	}	
	
	if(daemon == NULL || daemon->connections[connection_id]==NULL) {
		return MHD_NO;
	}

	if(daemon->connections[connection_id]->responsePending) {
		return MHD_YES;
	}

	daemon->connections[connection_id]->firstFreeHeader = 0;
	daemon->connections[connection_id]->requestType = NULL;

	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		daemon->connections[connection_id]->headers[i] = NULL;
	}



	memmove(daemon->connections[connection_id]->inbuf, daemon->connections[connection_id]->inbuf+daemon->connections[connection_id]->messagePos, daemon->connections[connection_id]->bufPos - daemon->connections[connection_id]->messagePos);

	memset(daemon->connections[connection_id]->inbuf + daemon->connections[connection_id]->bufPos - daemon->connections[connection_id]->messagePos,
			0, MHD_MAX_BUF_SIZE - daemon->connections[connection_id]->bufPos + (daemon->connections[connection_id]->bufPos - daemon->connections[connection_id]->messagePos));

	bytes_read = recv(daemon->connections[connection_id]->socket_fd, 
			daemon->connections[connection_id]->inbuf + daemon->connections[connection_id]->bufPos - daemon->connections[connection_id]->messagePos, 
			MHD_MAX_BUF_SIZE - (daemon->connections[connection_id]->bufPos - daemon->connections[connection_id]->messagePos), 0);

	daemon->connections[connection_id]->bufPos = bytes_read + daemon->connections[connection_id]->bufPos - daemon->connections[connection_id]->messagePos;

	if(bytes_read == 0) {
		MHD_destroy_session(daemon->connections[connection_id]);
		daemon->connections[connection_id] = NULL;
		return MHD_NO;
	} else {
		fprintf(stderr, "\"%s\"\n", daemon->connections[connection_id]->inbuf);
		i = MHD_parse_message(daemon->connections[connection_id]);
		if(i == -1) {
			daemon->connections[connection_id]->messagePos = daemon->connections[connection_id]->bufPos;
			return MHD_YES;
		} else {
			daemon->connections[connection_id]->messagePos = i;
			fprintf(stderr, "Number of bytes in header: %i\n", daemon->connections[connection_id]->messagePos);
		}

		daemon->connections[connection_id]->responsePending = 1;
		
		MHD_parse_URL(daemon->connections[connection_id]);

		for(i = 0; i < MHD_MAX_HANDLERS; i++) {
			if(daemon->handlers[i] == NULL) 
				continue;

			//header 0 will hold the url of the request
			if(strstr(daemon->connections[connection_id]->headers[0]->headerContent, daemon->handlers[i]->uri_prefix) != NULL){
				return daemon->handlers[i]->dh(daemon->handlers[i]->dh_cls, daemon->connections[connection_id], 
						daemon->connections[connection_id]->documentName, daemon->connections[connection_id]->requestType, NULL, NULL);
			}
		}
		return daemon->dh(daemon->dh_cls, daemon->connections[connection_id], 
				daemon->connections[connection_id]->documentName, daemon->connections[connection_id]->requestType, NULL, NULL);
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
MHD_handle_write(int connection_id, struct MHD_Daemon * daemon) {
	struct MHD_Session * session;

	struct MHD_Response * response;

	int i;
	
	char * buffer[2048];

	char * responseMessage;
	int numBytesInMessage;

	if((daemon->options & MHD_USE_DEBUG) != 0) {
		fprintf(stderr, "Enter MHD_handle_write\n");
	}	

	
	session = daemon->connections[connection_id];

	response = session->currentResponses[session->currentResponse];

	numBytesInMessage = 25;

	responseMessage = malloc(25);
	if(responseMessage == NULL) {
		 if(daemon->options & MHD_USE_DEBUG)
	       fprintf(stderr, "Error allocating memory!\n");
	    return MHD_NO;
	}
	
	if(response == NULL) 
		return MHD_NO;

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

			if(strlen(response->headers[i]->header) + strlen(response->headers[i]->headerContent) + 5 > numBytesInMessage) {
				free(responseMessage);
				responseMessage = malloc(strlen(response->headers[i]->header) + strlen(response->headers[i]->headerContent) + 5);
				if(responseMessage == NULL) {
					 if(daemon->options & MHD_USE_DEBUG)
				       fprintf(stderr, "Error allocating memory!\n");
	    			 pthread_mutex_unlock(&response->mutex);
				    return MHD_NO;
				}				
				numBytesInMessage = strlen(response->headers[i]->header) + strlen(response->headers[i]->headerContent) + 5;
			}
			sprintf(responseMessage, "%s: %s\r\n", response->headers[i]->header, response->headers[i]->headerContent);
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
	int i;

	for(i = 0; i < MHD_MAX_HEADERS; i++) {
		if(session->headers[i] != NULL &&
			 session->headers[i]->kind == kind &&
			 strncmp(session->headers[i]->header, key, strlen(session->headers[i]->header)) == 0) {
			return (const char *)session->headers[i]->headerContent;
		}
	}

	return NULL;
}


/**
 * This function is designed to parse the input buffer of a given session.
 * It is assumed that the data being parsed originates at buffer location
 * 0 (a valid assumption since the buffer is shifted after each message)
 */
int
MHD_parse_message(struct MHD_Session * session) {
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
	newHeader->headerContent = strtok_r(NULL, " ", &saveptr1);

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
		newHeader->headerContent = curTok + strlen(curTok1) + 2;
		//For now, everything is a get!
		newHeader->kind = MHD_GET_ARGUMENT_KIND;
		session->headers[session->firstFreeHeader++] = newHeader;
		curTok = strtok_r(NULL, crlf, &saveptr);
	}	

	return numBytes;
}

/**
 * This function needs to do a lot more (i.e. break up get arguments)
 * but for now just seperates the prefix of the url from the document
 * portion.
 */
void
MHD_parse_URL(struct MHD_Session * session) {
	char * working;
	int pos,i;

	working = session->headers[0]->headerContent;

	pos = 0;
	for(i = 0; i < strlen(working); i++) {
		if(working[i] == '/')
			pos = i+1;
	}
	if(pos >= strlen(working))
			pos = 0;

	session->documentName = session->headers[0]->headerContent+pos;
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

	//As of now this function can only support a fixed amount of queued responses, and will 
	//return MHD_NO if that queue is full

	int index;

	if(session == NULL || response == NULL) {
		return MHD_NO;
	}

	pthread_mutex_lock(&response->mutex);

	if(response->currentSession != NULL) {
		return MHD_NO;
	}

	if(session->currentResponses[session->currentResponse] == NULL) {
		index = session->currentResponse;
	} else if(session->currentResponses[session->currentResponse + 1 % MHD_MAX_RESPONSE] == NULL) {
		index = session->currentResponse + 1 % MHD_MAX_RESPONSE;
	} else {
		pthread_mutex_unlock(&response->mutex);		
		return MHD_NO;
	}
	
	response->responseCode = status_code;
	session->currentResponses[index] = response;
	response->currentSession = session;
	session->responsePending = 0;
	
	pthread_mutex_unlock(&response->mutex);		

	return MHD_YES;
}

/**
 * @return -1 if no data uploaded; otherwise number of bytes
 *            read into buf; 0 for end of transmission
 * Specification not complete at this time.
 */
int 
MHD_read_file_upload(struct MHD_Session * session,
		     void * buf,
		     size_t len) {
	//This function will not be implemented until the specification is completed.
	return -1;
}

/**
 * Run webserver operations (without blocking unless
 * in client callbacks).  This method should be called
 * by clients in combination with MHD_get_fdset
 * if the client-controlled select method is used. 
 *
 * @return MHD_YES on success, MHD_NO if this
 *         daemon was not started with the right
 *         options for this call.
 */
int
MHD_run(struct MHD_Daemon * daemon) {

	if((daemon->options & MHD_USE_THREAD_PER_CONNECTION) != 0) {
		daemon->shutdown = 0;
		if(pthread_create(&daemon->pid, NULL, (void *) &MHD_spawn_connections, (void *)daemon) == 0) {
		  return MHD_YES;
		} else {
			return MHD_NO;
		}
	} else if((daemon->options & MHD_USE_SELECT_INTERNALLY) != 0) {
		daemon->shutdown = 0;
		if(pthread_create(&daemon->pid, NULL, (void *) &MHD_select, (void *)daemon) == 0) {
		  return MHD_YES;
		} else {
			return MHD_NO;
		}
	} else {
		daemon->shutdown = 1;
		return (MHD_select((void *)daemon) == NULL);
	}	
}


/**
 * Register an access handler for all URIs beginning with uri_prefix.
 *
 * @param uri_prefix 
 * @return MRI_NO if a handler for this exact prefix
 *         already exists
 */
int 
MHD_register_handler(struct MHD_Daemon * daemon,
		     const char * uri_prefix,
		     MHD_AccessHandlerCallback dh,
		     void * dh_cls) {
	int i;
	
	//This function will also return MHD_NO if the maximum number of supported handlers is exceeded

	if(daemon == NULL || uri_prefix == NULL || dh == NULL) {
		return MHD_NO;
	}

	if(daemon->firstFreeHandler >= MHD_MAX_HANDLERS) {
		return MHD_NO;
	}

	daemon->handlers[daemon->firstFreeHandler] = malloc(sizeof(struct MHD_Access_Handler));

	if(daemon->handlers[daemon->firstFreeHandler] == NULL) {
		if((daemon->options & MHD_USE_DEBUG) != 0)
			fprintf(stderr, "Error allocating memory!\n");
		return MHD_NO;
	}

	daemon->handlers[daemon->firstFreeHandler]->uri_prefix = malloc(strlen(uri_prefix)+1);
	if(daemon->handlers[daemon->firstFreeHandler]->uri_prefix == NULL) {
		if((daemon->options & MHD_USE_DEBUG) != 0) {
			free(daemon->handlers[daemon->firstFreeHandler]);
			fprintf(stderr, "Error allocating memory!\n");
		}
		return MHD_NO;
	}
	sprintf(daemon->handlers[daemon->firstFreeHandler]->uri_prefix, "%s", uri_prefix);

	daemon->handlers[daemon->firstFreeHandler]->dh = dh;
	daemon->handlers[daemon->firstFreeHandler]->dh_cls = dh_cls;

	daemon->firstFreeHandler = MHD_MAX_HANDLERS;
	for(i = 0; i < MHD_MAX_HANDLERS; i++) {
		if(daemon->handlers[i] == NULL) {
			daemon->firstFreeHandler = i;
			break;
		}
	}

	return MHD_YES;
		
}

/**
 * This function is the entry point for either internal or external select.
 * The only differences between the two forms of running is whether the call is
 * made from a new thread or the main thread, and whether the initial value 
 * of shutdown is 0 or 1 (1 for loop, 0 for one time pass)
 */
void *
MHD_select(void * data) {
	struct MHD_Daemon * daemon;
	int i, num_ready;
	struct timeval timeout;

	daemon = data;
	if(daemon == NULL) {
		return NULL;
	}
	do {		
		FD_ZERO(&daemon->read_fd_set);
		FD_ZERO(&daemon->write_fd_set);
		FD_ZERO(&daemon->except_fd_set);

		FD_SET(daemon->socket_fd, &daemon->read_fd_set);
		for(i = 0; i < MHD_MAX_CONNECTIONS; i++) {
			if(daemon->connections[i] != NULL) {
				FD_SET(daemon->connections[i]->socket_fd, &daemon->read_fd_set);
				FD_SET(daemon->connections[i]->socket_fd, &daemon->write_fd_set);
			}
		}	

		timeout.tv_sec = 0;
		timeout.tv_usec = 0; 		

		num_ready = select(daemon->max_fd + 1,
				&(daemon->read_fd_set), &(daemon->write_fd_set), &(daemon->except_fd_set), &timeout);

		if(num_ready > 0) {
			for(i = 0; i < MHD_MAX_CONNECTIONS; i++) {
				if(daemon->connections[i] != NULL) {
					if(FD_ISSET(daemon->connections[i]->socket_fd, &(daemon->read_fd_set))) {
						if(MHD_handle_read(i, daemon) == MHD_NO)
						   continue;
					}
					if (FD_ISSET(daemon->connections[i]->socket_fd, &(daemon->write_fd_set))) {
						if(MHD_handle_write(i, daemon) == MHD_NO)
							continue;
					}
					if (FD_ISSET(daemon->connections[i]->socket_fd, &(daemon->except_fd_set))) {
						MHD_handle_except(i, daemon);
					}
				}
			}
			if(FD_ISSET(daemon->socket_fd, &(daemon->read_fd_set))) {
				if(MHD_create_connection(daemon) == -1) {
					continue;
				}
			}			
		}
	} while (!daemon->shutdown);

	return NULL;
}

/**
 * This function was created for the case of multithreaded connections.
 * A thread will spawned to sit on this function, and in turn spawns more
 * threads, one per connection.
 */
void *
MHD_spawn_connections(void * data) {
	struct MHD_Daemon * daemon;
	int con, num_ready;
	struct timeval timeout;
	fd_set read;

	daemon = data; 
	if(daemon == NULL) {
		return NULL;
	}

	do {
		FD_ZERO(&read);
		FD_SET(daemon->socket_fd, &read);
	
		timeout.tv_sec = 0;
		timeout.tv_usec = 0; 		

		num_ready = select(daemon->socket_fd + 1,&read, NULL, NULL, &timeout);
	
		if(num_ready > 0) {
			con = MHD_create_connection(daemon);
			if(con == -1) 
				continue;

			if(pthread_create(&daemon->connections[con]->pid, NULL, (void *) &MHD_handle_connection, (void *)daemon->connections[con]) != 0) {
				if((daemon->options & MHD_USE_DEBUG) != 0)
		   		fprintf(stderr, "Error creating connection handler!.\n");		  
			}				
		}				
	} while (!daemon->shutdown);

	return NULL;
}

/**
 * Start a webserver on the given port.
 * @param port port to bind to
 * @param apc callback to call to check which clients
 *        will be allowed to connect
 * @param apc_cls extra argument to apc
 * @param dh default handler for all URIs
 * @param dh_cls extra argument to dh
 * @return NULL on error, handle to daemon on success
 */
struct MHD_Daemon *
MHD_start_daemon(unsigned int options,
		 unsigned short port,
		 MHD_AcceptPolicyCallback apc,
		 void * apc_cls,
		 MHD_AccessHandlerCallback dh,
		 void * dh_cls) {


   struct MHD_Daemon * retVal = NULL;
   int socket_fd, opt, res, i;
   struct sockaddr_in servaddr;	
   struct hostent *hostptr;
   char hostid[32];	

   if((options & MHD_USE_SSL) != 0) {
	if((options & MHD_USE_DEBUG) != 0)
	   fprintf(stderr, "SSL at this time is unsupported.\n");
	return NULL;
   }
   if((options & MHD_USE_IPv6) != 0) {
	if((options & MHD_USE_DEBUG) != 0)
	   	fprintf(stderr, "IP version 6 is not supported at this time.\n");
	return NULL;
   }

   if((options & MHD_USE_IPv4) != 0) {
      if((options & MHD_USE_DEBUG) != 0)
         fprintf(stderr, "Enter MHD_start_daemon. Starting Daemon on port %i\n", port);

	 if(port < 1) {
	    if((options & MHD_USE_DEBUG) != 0)
	       fprintf(stderr, "Invalid port: %i!\n", port);
	          return NULL;
	 }

	 if(dh == NULL) {
	    if((options & MHD_USE_DEBUG) != 0)
	       fprintf(stderr, "A default access handler must be provided\n");
	    return NULL;
	 }

 	 retVal = (struct MHD_Daemon *)malloc(sizeof(struct MHD_Daemon));
	 if(retVal == NULL) {
	    if((options & MHD_USE_DEBUG) != 0)
	       fprintf(stderr, "Error allocating memory!\n");
	    return NULL;		
	 }
 
	 retVal->options = options;
	 retVal->port = port;
	 retVal->apc = apc;
	 retVal->apc_cls = apc_cls;
	 retVal->dh = dh;
	 retVal->dh_cls = dh_cls;
	 retVal->shutdown = 0;
	 retVal->pid = (pthread_t)-1;

	 retVal->firstFreeHandler = 0;
	 for(i = 0; i < MHD_MAX_HANDLERS; i++) {
	 	retVal->handlers[i] = NULL;
	 }

	 FD_ZERO(&retVal->read_fd_set);
	 FD_ZERO(&retVal->write_fd_set);
	 FD_ZERO(&retVal->except_fd_set);

	 for(i = 0; i < MHD_MAX_CONNECTIONS; i++) {
            retVal->connections[i] = NULL;
         }

	 socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	 if(socket_fd < 0) {
	    if((options & MHD_USE_DEBUG) != 0)
	       perror("Error creating socket!");
	    return NULL;
	 }

	 memset((void *)&servaddr, 0, (size_t)sizeof(servaddr));

   	 if (gethostname(hostid,32) < 0){
	    if((options & MHD_USE_DEBUG) != 0)
	       perror("server_tcp:gethostname");
	    return NULL;
	 }

   	 if ((hostptr = gethostbyname(hostid)) == NULL){
	    if((options & MHD_USE_DEBUG) != 0)
	       fprintf(stderr, "invalid host name, %s\n",hostid);
	    return NULL;
	 }	
	
	 servaddr.sin_family = AF_INET;
	 memcpy((void *)&(servaddr.sin_addr), (void *)(hostptr->h_addr), hostptr->h_length);
	 servaddr.sin_port = htons(port);
	

    	if (bind(socket_fd, (struct sockaddr *)&servaddr, (socklen_t)sizeof(servaddr)) < 0) {
	    if((options & MHD_USE_DEBUG) != 0)
	       perror("server:bind");
	    return NULL;
	 }
	
	 if(listen(socket_fd, 20) < 0) {
	    if((options & MHD_USE_DEBUG) != 0)
	       perror("server:bind");
	    return NULL;	 
         }
	
	 retVal->socket_fd = socket_fd;
	 retVal->max_fd = socket_fd;
	 FD_SET(socket_fd, &retVal->read_fd_set);

	 opt = fcntl(socket_fd, F_GETFL, 0);
	 res = fcntl(socket_fd, F_SETFL, opt | O_NONBLOCK);
	 if(res < 0) {
	    if((options & MHD_USE_DEBUG) != 0)
	       perror("Error disabling block on socket!");
	    return NULL;
	 }

	 return retVal;
   }
   
   if((options & MHD_USE_DEBUG) != 0)
       fprintf(stderr, "No options given to start_daemon!\n");

   return NULL;
	
}

/**
 * Shutdown an http daemon.
 */
void
MHD_stop_daemon(struct MHD_Daemon * daemon) {	
	int i, j;

	if(daemon == NULL) {
		return;
	}

	if((daemon->options & MHD_USE_DEBUG) != 0)
		fprintf(stderr, "Enter MHD_stop_daemon. Stopping daemon on port %i\n", daemon->port);

	daemon->shutdown = 1;

	if(daemon->pid != (pthread_t)-1) {
		pthread_join(daemon->pid, NULL);
	}

	for(i = 0; i < MHD_MAX_CONNECTIONS; i++) {
		if(daemon->connections[i] != NULL) {
			if(daemon->connections[i]->pid != (pthread_t)-1) {
				pthread_join(daemon->connections[i]->pid, NULL);
			}

			for(j = 0; j < MHD_MAX_RESPONSE; j++) {
				if(daemon->connections[i]->currentResponses[j] != NULL) {
					MHD_destroy_response(daemon->connections[i]->currentResponses[j]);
				}
			}
			MHD_destroy_session(daemon->connections[i]);
		}
	}

	for(i = 0; i < MHD_MAX_HANDLERS; i++) {
		if(daemon->handlers[i] != NULL) {
			free(daemon->handlers[i]->uri_prefix);
			free(daemon->handlers[i]);
		}
	}

	close(daemon->socket_fd);

	free(daemon);
}


/**
 * Unregister an access handler for the URIs beginning with
 * uri_prefix.
 *
 * @param uri_prefix 
 * @return MHD_NO if a handler for this exact prefix
 *         is not known for this daemon
 */
int 
MHD_unregister_handler(struct MHD_Daemon * daemon,
		       const char * uri_prefix,
		       MHD_AccessHandlerCallback dh,
		       void * dh_cls) {
	int i;

	for(i = 0; i < MHD_MAX_HANDLERS; i++) {
		if(daemon->handlers[i] != NULL) {
			if(strncmp(daemon->handlers[i]->uri_prefix, uri_prefix, strlen(daemon->handlers[i]->uri_prefix)) == 0) {
				if(daemon->handlers[i]->dh == dh && daemon->handlers[i]->dh_cls == dh_cls) {
					free(daemon->handlers[i]->uri_prefix);
					free(daemon->handlers[i]);
					return MHD_YES;
				}
			}
		}
	}

	return MHD_NO;
}

