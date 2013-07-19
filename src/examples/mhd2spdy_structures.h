/*
    Copyright (C) 2013 Andrey Uzunov

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file structures.h
 * @author Andrey Uzunov
 */
#ifndef STRUCTURES_H
#define STRUCTURES_H

#define _GNU_SOURCE
 
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <microhttpd.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <spdylay/spdylay.h>
#include <getopt.h>

struct Proxy;

struct SPDY_Connection {
  SSL *ssl;
  //SSL_CTX *ssl_ctx;
  spdylay_session *session;
  struct SPDY_Connection *prev;
  struct SPDY_Connection *next;
  struct Proxy *proxies_head;
  struct Proxy *proxies_tail;
  char *host;
  /* WANT_READ if SSL connection needs more input; or WANT_WRITE if it
     needs more output; or IO_NONE. This is necessary because SSL/TLS
     re-negotiation is possible at any time. Spdylay API offers
     similar functions like spdylay_session_want_read() and
     spdylay_session_want_write() but they do not take into account
     SSL connection. */
  int fd;
  int want_io;
  uint counter;
  uint streams_opened;
  bool is_tls;
};


struct URI
{
  char * full_uri;
  char * scheme;
  char * host_and_port;
  //char * host_and_port_for_connecting;
  char * host;
  char * path;
  char * path_and_more;
  char * query;
  char * fragment;
  uint16_t port;
};

struct HTTP_URI;

struct Proxy
{
	struct MHD_Connection *http_connection;
	struct MHD_Response *http_response;
	struct URI *uri;
  struct HTTP_URI *http_uri; //TODO remove me
  struct SPDY_Connection *spdy_connection;
  struct Proxy *next;
  struct Proxy *prev;
	//char *path;
	char *url;
	//struct SPDY_Request *request;
	//struct SPDY_Response *response;
	//CURL *curl_handle;
	//struct curl_slist *curl_headers;
	//struct SPDY_NameValue *headers;
	char *version;
	//char *status_msg;
	void *http_body;
	size_t http_body_size;
	ssize_t length;
	int status;
	int id;
	bool done;
  bool http_active;
  bool spdy_active;
};

struct HTTP_URI
{
  char * uri;
  struct Proxy * proxy;
};

struct SPDY_Headers
{
  const char **nv;
  int num;
  int cnt;
};

struct global_options
{
  char *spdy2http_str;
  struct SPDY_Connection *spdy_connection;
  struct SPDY_Connection *spdy_connections_head;
  struct SPDY_Connection *spdy_connections_tail;
  int streams_opened;
  int responses_pending;
  regex_t uri_preg;
  size_t global_memory;
  SSL_CTX *ssl_ctx;
  uint32_t total_spdy_connections;
  uint16_t spdy_proto_version;
  uint16_t listen_port;
  bool verbose;
  bool only_proxy;
  bool spdy_data_received;
} glob_opt;

/*

#define SOCK_ADDR_IN_PTR(sa)	((struct sockaddr_in *)(sa))
#define SOCK_ADDR_IN_FAMILY(sa)	SOCK_ADDR_IN_PTR(sa)->sin_family
#define SOCK_ADDR_IN_PORT(sa)	SOCK_ADDR_IN_PTR(sa)->sin_port
#define SOCK_ADDR_IN_ADDR(sa)	SOCK_ADDR_IN_PTR(sa)->sin_addr

#ifdef HAS_IPV6

#define SOCK_ADDR_IN6_PTR(sa)	((struct sockaddr_in6 *)(sa))
#define SOCK_ADDR_IN6_FAMILY(sa) SOCK_ADDR_IN6_PTR(sa)->sin6_family
#define SOCK_ADDR_IN6_PORT(sa)	SOCK_ADDR_IN6_PTR(sa)->sin6_port
#define SOCK_ADDR_IN6_ADDR(sa)	SOCK_ADDR_IN6_PTR(sa)->sin6_addr

#endif
*/

//forbidden headers
#define SPDY_HTTP_HEADER_TRANSFER_ENCODING "transfer-encoding"
#define SPDY_HTTP_HEADER_PROXY_CONNECTION "proxy-connection"
#define SPDY_HTTP_HEADER_KEEP_ALIVE "keep-alive"
#define SPDY_HTTP_HEADER_CONNECTION "connection"

#define MAX_SPDY_CONNECTIONS 100


/**
 * Insert an element at the head of a DLL. Assumes that head, tail and
 * element are structs with prev and next fields.
 *
 * @param head pointer to the head of the DLL (struct ? *)
 * @param tail pointer to the tail of the DLL (struct ? *)
 * @param element element to insert (struct ? *)
 */
#define DLL_insert(head,tail,element) do { \
	(element)->next = (head); \
	(element)->prev = NULL; \
	if ((tail) == NULL) \
		(tail) = element; \
	else \
		(head)->prev = element; \
	(head) = (element); } while (0)


/**
 * Remove an element from a DLL. Assumes
 * that head, tail and element are structs
 * with prev and next fields.
 *
 * @param head pointer to the head of the DLL (struct ? *)
 * @param tail pointer to the tail of the DLL (struct ? *)
 * @param element element to remove (struct ? *)
 */
#define DLL_remove(head,tail,element) do { \
	if ((element)->prev == NULL) \
		(head) = (element)->next;  \
	else \
		(element)->prev->next = (element)->next; \
	if ((element)->next == NULL) \
		(tail) = (element)->prev;  \
	else \
		(element)->next->prev = (element)->prev; \
	(element)->next = NULL; \
	(element)->prev = NULL; } while (0)


#define PRINT_INFO(msg) do{\
  if(glob_opt.verbose){\
	printf("%i:%s\n", __LINE__, msg);\
	fflush(stdout);\
	}\
  }\
	while(0)


#define PRINT_INFO2(fmt, ...) do{\
  if(glob_opt.verbose){\
	printf("%i\n", __LINE__);\
	printf(fmt,##__VA_ARGS__);\
	printf("\n");\
	fflush(stdout);\
	}\
	}\
	while(0)
  

#define DIE(msg) do{\
	printf("FATAL ERROR (line %i): %s\n", __LINE__, msg);\
	fflush(stdout);\
  exit(EXIT_FAILURE);\
	}\
	while(0)
  
  


void
free_uri(struct URI * uri);

int
init_parse_uri(regex_t * preg);

void
deinit_parse_uri(regex_t * preg);
  
int
parse_uri(regex_t * preg, char * full_uri, struct URI ** uri);

void
free_proxy(struct Proxy *proxy);

void *au_malloc(size_t size);

#endif
