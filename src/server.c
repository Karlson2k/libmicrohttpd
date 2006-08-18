/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 * 
 * date: Sat Mar 30 14:44:42 GMT 2002
 *
 * -- core server functions
 *
 */

#include "webserver_gnunet.h"
#include <stdio.h>
#include <signal.h>
#include <time.h>

#include "memory.h"
#include "client.h"
#include "socket.h"

#ifdef WIN32
#define SHUT_RDWR SD_BOTH
#endif

struct web_server {
  int socket;
  unsigned int port;
  struct gethandler * gethandler;
  struct web_client *client;
};


/*
 * initializate (allocate) handler list
 */
struct gethandler *__ILWS_init_handler_list() {
  struct gethandler *ret;
  
  ret = __ILWS_malloc(sizeof(struct gethandler));
  if (ret==NULL) 
    return NULL;
  ret->next = NULL;
  ret->func = NULL;
  ret->ctx = NULL;
  ret->str = NULL;
  return ret;
}

/* 
 * add an handler to list
 */
static int __ILWS_add_handler(struct gethandler * head, 
			      const char * mstr, 
			      void (*func)(), 
			      void * ctx) {
  struct gethandler * temp = head;
  while (temp->next != NULL)
    temp = temp->next;
	
  temp->next = __ILWS_malloc(sizeof(struct gethandler));
  if (temp->next==NULL) 
    return 0; 
  temp = temp->next;
  temp->str=__ILWS_malloc(strlen(mstr)+1);
  if (temp->str==NULL) {
    __ILWS_free(temp); 
    return 0;
  };
  memcpy(temp->str,
	 mstr,
	 strlen(mstr) + 1);
  temp->func = func;  
  temp->ctx = ctx;
  temp->next = NULL;
  return 1;
}                         

/* 
 * Deletes the entire handler list including the head
 */
static void __ILWS_delete_handler_list(struct gethandler * handler) {
  struct gethandler * next;
	
  while (handler) {
    next = handler->next;
    if (handler->str != NULL)
      __ILWS_free(handler->str);
    __ILWS_free(handler);
    handler = next;
  }
}

/*
 * to add a listen socket
 */
static int __ILWS_listensocket(short port, 
			       int saddr) {
  struct sockaddr_in sa;
  int ret;
  int sockopt=1; 

  sa.sin_addr.s_addr=saddr;
  sa.sin_port=htons((short)port);
  sa.sin_family=AF_INET;
  ret=socket(AF_INET,SOCK_STREAM,6); // tcp
  if(ret==-1) 
    return -1;
  
  setsockopt(ret,
	     SOL_SOCKET,
	     SO_REUSEADDR,
	     (char *)&sockopt,
	     sizeof(sockopt));
  
  if (bind(ret,
	   (struct sockaddr *)&sa,
	   sizeof(sa))==-1) {
    close(ret); 
    return -1;
  }
  
  if (listen(ret,512)==-1) { // 512 backlog 
    close(ret); 
    return -1;
  }
  return ret;
}


/*
 * Add an handler to request data
 */
int web_server_addhandler(struct web_server *server,
			  const char *mstr,
			  void (*func)(),
			  void * hctx) {
  return __ILWS_add_handler(server->gethandler,
			    mstr,
			    func,
			    hctx);
}

/*
 * This function initialize one web_server handler
 */
int web_server_init(struct web_server *server,
		    int port,
		    int flags) {
#ifdef WIN32	
  unsigned long t=IOC_INOUT;
  WSADATA WSAinfo;
  WSAStartup(2,&WSAinfo); // Damn w32 sockets
#endif
  server->port=port;
  // Create a listen socket port 'port' and listen addr (0) (all interfaces)
  server->socket=__ILWS_listensocket((short)server->port,0);	
  if (server->socket==-1) {
#ifdef WIN32		
    WSACleanup();
#endif
    return 0;
  };
#ifdef WIN32
  ioctlsocket(server->socket,
	      FIONBIO,
	      &t);  //non blocking sockets for win32
#else
  fcntl(server->socket,
	F_SETFL,
	O_NONBLOCK);
#endif
  
  // Setup Flags  
  server->client = __ILWS_init_client_list();
  server->gethandler = __ILWS_init_handler_list();
  
#ifndef WIN32	
  signal(SIGPIPE, SIG_IGN);
#endif
  return 1;
}                            

/*
 * This function shuts down a running web server, frees its allocated memory,
 * and closes its socket. If called on a struct web_server that has already
 * been shut down, this is a noop.
 */
void web_server_shutdown(struct web_server * server) {
  // free and close things in opposite order of web_server_init
  __ILWS_delete_handler_list(server->gethandler);
  server->gethandler = NULL;
  __ILWS_delete_client_list(server->client);
  server->client = NULL; 
  if(server->socket > 0) {
#ifdef WIN32
    closesocket(server->socket);
#else
    close(server->socket);
#endif
    server->socket = -1;
  }  
#ifdef WIN32
  WSACleanup();
#endif
}

/*
 * Core function, return 2 if no client to process, 1 if some client processed, 0 if error
 */
int web_server_run(struct web_server *server) {
  struct web_client * client;
  struct web_client * pos;
  int rt;
  size_t tsalen=0;
  int tsocket=0;
  int cond;
  struct sockaddr_in tsa;
  
  tsalen = sizeof(client->sa);
  tsocket = accept(server->socket,
		 (struct sockaddr *)&tsa,
		 &tsalen);
  if (tsocket == -1) {
#ifdef WIN32
    cond = WSAGetLastError() != WSAEWOULDBLOCK;
#else			
    cond = errno!=EAGAIN;
#endif
    if (cond) {
      // client fucked up? warn somebody? (error or log or something?)
      return 0; 
    }
  } else {
    client = __ILWS_malloc(sizeof(struct web_client));
    if (client == NULL) {
      rt = shutdown(tsocket,
		    SHUT_RDWR);
#ifdef WIN32
      rt=closesocket(tsocket); 
#else
      rt=close(tsocket); 
#endif
      return 0;
    };
    client->salen=tsalen;
    client->socket=tsocket;
    client->sa=tsa;
    if(!__ILWS_add_client(server->client,client)) 
      return 0;
  };
  // end search for client
  client = server->client; // init list
  if(!client->next) { // think of Rocco Carbone (rocco@tecsiel.it)
    return 2; // i don't need to process the list (nothing next) returns 2 if there is no client to process
  }
  while (client->next != NULL) { // Process the client and swap to next;
    pos = client->next;
    switch (pos->stat) {
    case 1: 
      __ILWS_read_client(pos);
      break;
    case 2: 
      __ILWS_process_client(pos, server->gethandler);
      break;
    case 4: 
      __ILWS_output_client(pos);	
      break;
    case 5: 
      __ILWS_delete_next_client(client); 
      continue;
    }
    client=client->next;    
  }
  return 1;  // return 1 if something processed
}

