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
 * @brief  A minimal-HTTP server library
 * @author Daniel Pittman
 * @author Christian Grothoff
 * @version 0.1.0
 */

#include "microhttpd.h"
#include "internal.h"
#include "response.h"
#include "session.h"
#include "config.h"

#define MHD_MAX_CONNECTIONS FD_SETSIZE -4 


/**
 * fprintf-like helper function for logging debug
 * messages.
 */
static void DLOG(const struct MHD_Daemon * daemon,
		 const char * format,
		 ...) {
  va_list va;
  
  if ( (daemon->options & MHD_USE_DEBUG) == 0)
    return;
  va_start(va, format);
  vfprintf(stderr, format, va);
  va_end(va);
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
  struct MHD_Access_Handler * ah;

  if ( (daemon == NULL) || 
       (uri_prefix == NULL) ||
       (dh == NULL) ) 
    return MHD_NO;	
  ah = daemon->handlers;
  while (ah != NULL) {
    if (0 == strcmp(uri_prefix,
		    ah->uri_prefix))
      return MHD_NO;
    ah = ah->next;
  }
  ah = malloc(sizeof(MHD_AccessHandlerCallback));
  ah->next = daemon->handlers;
  ah->uri_prefix = strdup(uri_prefix);
  ah->dh = dh;
  ah->dh_cls = dh_cls;
  daemon->handlers = ah;
  return MHD_YES;		
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
  struct MHD_Access_Handler * prev;
  struct MHD_Access_Handler * pos;

  if ( (daemon == NULL) || 
       (uri_prefix == NULL) ||
       (dh == NULL) ) 
    return MHD_NO;	
  pos = daemon->handlers;
  prev = NULL;
  while (pos != NULL) {
    if ( (dh == pos->dh) &&
	 (dh_cls == pos->dh_cls) &&
	 (0 == strcmp(uri_prefix,
		      pos->uri_prefix)) ) {
      if (prev == NULL)
	daemon->handlers = pos->next;
      else
	prev->next = pos->next;
      free(pos);
      return MHD_YES;
    }
    prev = pos;
    pos = pos->next;
  }
  return MHD_NO;
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
  struct MHD_Session * pos;

  if ( (daemon == NULL) ||
       (read_fd_set == NULL) || 
       (write_fd_set == NULL) ||
       (except_fd_set == NULL) ||
       (max_fd == NULL) ||
       ( (daemon->options & MHD_USE_THREAD_PER_CONNECTION) != 0) )
    return MHD_NO;	
  FD_SET(daemon->socket_fd, 
	 read_fd_set);
  if ( (*max_fd) < daemon->socket_fd)
    *max_fd = daemon->socket_fd;
  pos = daemon->connections;
  while (pos != NULL) {
    if (MHD_YES != MHD_session_get_fdset(pos,
					 read_fd_set,
					 write_fd_set,
					 except_fd_set,
					 max_fd))
      return MHD_NO;
    pos = pos->next;
  }
  return MHD_YES;
}


/**
 * Main function of the thread that handles an individual
 * connection.
 */
static void *
MHD_handle_connection(void * data) {
  struct MHD_Session * con = data;
  int num_ready;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  
  if (con == NULL)
    abort();
  while (! con->daemon->shutdown) {    
    FD_ZERO(&rs);
    FD_ZERO(&ws);    
    FD_ZERO(&es);    
    max = 0;
    MHD_session_get_fdset(con,
			  &rs,
			  &ws,
			  &es,
			  &max);
    num_ready = select(max + 1,
		       &rs, 
		       &ws,
		       &es, 
		       NULL);
    if (num_ready <= 0) {
      if (errno == EINTR)
	continue;
      break;
    }
    if ( ( (FD_ISSET(con->socket_fd, &rs)) &&
	   (MHD_YES != MHD_session_handle_read(con)) ) ||
	 ( (FD_ISSET(con->socket_fd, &ws)) &&
	   (MHD_YES != MHD_session_handle_write(con)) ) )
      break;
  } 
  close(con->socket_fd);
  con->socket_fd = -1;
  return NULL;
}


/**
 * Accept an incoming connection and create the MHD_Session object for
 * it.  This function also enforces policy by way of checking with the
 * accept policy callback.
 */
static int
MHD_accept_connection(struct MHD_Daemon * daemon) {
  struct MHD_Session * session;
  struct sockaddr addr;
  socklen_t addrlen;
  int s;

  addrlen = sizeof(struct sockaddr);
  memset(&addr, 
	 0,
	 sizeof(struct sockaddr));
  if ( (0 != (s = accept(daemon->socket_fd, 
			 &addr,
			 &addrlen))) ||
       (addrlen <= 0) ) {
    DLOG(daemon,
	 "Error accepting connection: %s\n",
	 strerror(errno));
    return MHD_NO;
  }
  if (MHD_NO == daemon->apc(daemon->apc_cls,
			    &addr,
			    addrlen)) {
    close(s);
    return MHD_YES;
  }
  session = malloc(sizeof(struct MHD_Session));
  memset(session,
	 0,
	 sizeof(struct MHD_Session));
  session->addr = malloc(addrlen);
  memcpy(session->addr,
	 &addr,
	 addrlen);
  session->addr_len = addrlen;
  session->socket_fd = s;
  session->daemon = daemon;
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION) ) &&
       (0 != pthread_create(&session->pid,
			    NULL, 
			    &MHD_handle_connection, 
			    session)) ) {
    DLOG(daemon,
	 "Failed to create a thread: %s\n",
	 strerror(errno));
    free(session->addr);
    close(s);
    free(session);
    return MHD_NO;
  }
  session->next = daemon->connections;
  daemon->connections = session;
  return MHD_YES;
}


/**
 * Free resources associated with all closed sessions.
 * (destroy responses, free buffers, etc.).  A session
 * is known to be closed if the socket_fd is -1.
 */
static void 
MHD_cleanup_sessions(struct MHD_Daemon * daemon) {
  struct MHD_Session * pos;
  struct MHD_Session * prev;

  pos = daemon->connections;
  prev = NULL;
  while (pos != NULL) {
    if (pos->socket_fd == -1) {
      if (prev == NULL)
	daemon->connections = pos->next;
      else
	prev->next = pos->next;
      free(pos->addr);
      /* FIXME: more to free here! */
      free(pos);
    }
    prev = pos;
    pos = pos->next;
  }
}


/**
 * Main select call.
 *
 * @return MHD_NO on serious errors, MHD_YES on success
 */
static int
MHD_select(struct MHD_Daemon * daemon) {
  struct MHD_Session * pos;
  int num_ready;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  
  if(daemon == NULL) 
    abort();
  FD_ZERO(&rs);
  FD_ZERO(&ws);    
  FD_ZERO(&es);      
  max = 0;

  if (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) {
    /* single-threaded, go over everything */
    if (MHD_NO == MHD_get_fdset(daemon,
				&rs,
				&ws,
				&es,
				&max))
      return MHD_NO;
  } else {
    /* accept only, have one thread per connection */
    max = daemon->socket_fd;
    FD_SET(daemon->socket_fd, &rs);
  }
  num_ready = select(max + 1,
		     &rs,
		     &ws,
		     &es,
		     NULL);  
  if (num_ready < 0) {    
    if (errno == EINTR)
      return MHD_YES;
    DLOG(daemon,
	 "Select failed: %s\n",
	 strerror(errno));
    return MHD_NO;    
  }
  if (FD_ISSET(daemon->socket_fd,
	       &rs))
    MHD_accept_connection(daemon);  
  if (0 == (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) {
    /* do not have a thread per connection, process all connections now */
    pos = daemon->connections;
    while (pos != NULL) {
      if (FD_ISSET(pos->socket_fd, &rs)) 
	MHD_session_handle_read(pos);
      if (FD_ISSET(pos->socket_fd, &ws))
	MHD_session_handle_write(pos);
      pos = pos->next;
    }
  }
  return MHD_YES;
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
  if ( (daemon->shutdown != 0) ||
       (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) ||
       (0 != (daemon->options & MHD_USE_SELECT_INTERNALLY)) )
    return MHD_NO;
  MHD_select(daemon);
  MHD_cleanup_sessions(daemon);
  return MHD_YES;
}


/**
 * Thread that runs the select loop until the daemon
 * is explicitly shut down.
 */
static void *
MHD_select_thread(void * cls) {
  struct MHD_Daemon * daemon = cls;
  while (daemon->shutdown == 0) {
    MHD_select(daemon);
    MHD_cleanup_sessions(daemon);
  }
  return NULL;
}


/**
 * Start a webserver on the given port.
 *
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
  struct MHD_Daemon * retVal;
  int socket_fd;
  int opt;
  int res;
  struct sockaddr_in servaddr;	

  if ((options & MHD_USE_SSL) != 0) 
    return NULL;   
  if ((options & MHD_USE_IPv6) != 0) 
    return NULL;  
  if ((options & MHD_USE_IPv4) == 0) 
    return NULL;  
  if ( (port == 0) ||
       (dh == NULL) )
    return NULL;
  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    /* FIXME: log error */
    return NULL;
  }
  memset(&servaddr,
	 0,
	 sizeof(struct sockaddr_in));  
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  if (bind(socket_fd, 
	   (struct sockaddr *)&servaddr, 
	   sizeof(struct sockaddr_in)) < 0) {
    /* FIXME: log error */
    close(socket_fd);
    return NULL;
  }	
  if (listen(socket_fd, 20) < 0) {
    /* FIXME: log error */
    return NULL;	 
  }	
  opt = fcntl(socket_fd, F_GETFL, 0);
  res = fcntl(socket_fd, F_SETFL, opt | O_NONBLOCK);
  if (res < 0) {
    /* FIXME: log error */
    close(socket_fd);
    return NULL;
  }

  retVal = malloc(sizeof(struct MHD_Daemon));
  memset(retVal,
	 0,
	 sizeof(struct MHD_Daemon));
  retVal->options = options;
  retVal->port = port;
  retVal->apc = apc;
  retVal->apc_cls = apc_cls;
  retVal->socket_fd = socket_fd;
  retVal->default_handler.dh = dh;
  retVal->default_handler.dh_cls = dh_cls;
  retVal->default_handler.uri_prefix = "";
  retVal->default_handler.next = NULL;
  if ( ( (0 != (options & MHD_USE_THREAD_PER_CONNECTION)) ||
	 (0 != (options & MHD_USE_SELECT_INTERNALLY)) ) &&
       (0 != pthread_create(&retVal->pid,
			    NULL, 
			    &MHD_select_thread, 
			    daemon)) ) {
    /* FIXME: log error */
    free(retVal);
    close(socket_fd);
    return NULL;    
  }
  return retVal;
}

/**
 * Shutdown an http daemon.
 */
void
MHD_stop_daemon(struct MHD_Daemon * daemon) {	
  void * unused;

  if (daemon == NULL) 
    return; 
  daemon->shutdown = 1;
  close(daemon->socket_fd);
  daemon->socket_fd = -1;
  if ( (0 != (daemon->options & MHD_USE_THREAD_PER_CONNECTION)) ||       
       (0 != (daemon->options & MHD_USE_SELECT_INTERNALLY)) )
    pthread_join(daemon->pid, &unused);

  while (daemon->connections != NULL) {
    if (-1 != daemon->connections->socket_fd) {
      close(daemon->connections->socket_fd);
      daemon->connections->socket_fd = -1;
    }
    pthread_join(daemon->connections->pid, &unused);

    MHD_cleanup_sessions(daemon);
  }
  free(daemon);
}

