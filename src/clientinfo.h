/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * date: Wed Oct  9 19:05:48 GMT 2002
 *
 *
 * --
 *
 */

#ifndef _CLIENTINFO_H_
#define _CLIENTINFO_H_

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include "client.h"
#include "utils.h"
#include "memory.h"

/*
 * Next's structs are redudant but it is an case of logic (spell)
 */
struct _Header {
	char *id;
	char *data;
	struct _Header *next;
};
struct _Query {
	unsigned int index;
	unsigned int idf;
	char *id;
	char *data;
	struct _Query *next;
};
struct _Post {
	unsigned int index;
	unsigned int idf;
	char *id;
	char *data;
	struct _Post *next;
};

struct _MultiPart {
	char *id;
	char *data;
	unsigned int size;
	char *filename;
	struct _MultiPart *next;
};

struct _Cookie {
	char *id;
	char *data;
	struct _Cookie *next;
};

struct ClientInfo {
	int outfd;
	char *inetname;
	char *request;
	char *method;
	char *user;
	char *pass;
	
	char *(*Header)(char *);
	char *(*Query)(char *);
	char *(*Post)(char *);
	char *(*Cookie)(char *); // TODO
	struct _MultiPart (*MultiPart)(char *); 
	// not necessary for web_server.h
	char *QueryString;
	char *CookieString;
	char *PostData;
	struct memrequest *mem;
	struct _Header *HeaderList; // Not necessary for web_server.h
	struct _Query *QueryList; // Not necessary for web_server.h
	struct _Post *PostList; // Not necessary for web_server.h
	struct _MultiPart *MultiPartList; // Not necessary for web_server.h
	struct _Cookie *CookieList; // Not necessary for web_server.h
};


void __ILWS_init_clientinfo(struct ClientInfo *ClientInfo);
void __ILWS_free_clientinfo(struct ClientInfo *ClientInfo);
char *__ILWS_clientinfo_getquerystring(struct ClientInfo *ClientInfo);
char *__ILWS_clientinfo_getpostdata(struct ClientInfo *ClientInfo);
char *__ILWS_clientinfo_getcookiestring(struct ClientInfo *ClientInfo);
char *__ILWS_clientinfo_getmethod(struct ClientInfo *ClientInfo);
char *__ILWS_clientinfo_getreqname(struct ClientInfo *ClientInfo);
char *__ILWS_Header(struct ClientInfo *ClientInfo, char *);
char *__ILWS_Query(struct ClientInfo *ClientInfo, char *);
char *__ILWS_Post(struct ClientInfo *ClientInfo, char *);
struct _MultiPart __ILWS_MultiPart(struct ClientInfo *ClientInfo, char *);
char *__ILWS_Cookie(struct ClientInfo *ClientInfo, char *);

#endif

