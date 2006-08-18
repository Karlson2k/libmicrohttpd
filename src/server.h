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
 *
 * --
 *
 */

#ifndef _SERVER_H_
#define _SERVER_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif         

#include <stdio.h>
#include <signal.h>
#include <time.h>


#include "memory.h"
#include "client.h"
#include "gethandler.h"
#include "socket.h"
#include "error.h"

#include "debug.h"

#ifdef WIN32

#define SHUT_RDWR SD_BOTH
#endif




extern char *_libwebserver_version;
extern struct web_server *current_web_server; 
struct web_server {
	int socket;
	unsigned int port;
	char *logfile;
	char *conffile;
	time_t conffiletime; // tested only on win
	char *mimefile;
	char *dataconf;
	FILE *weblog;
	int flags;
	struct gethandler *gethandler;
	struct web_client *client;
	int usessl;
#ifdef HAVE_OPENSSL
	char *cert_file;
	SSL_CTX *ctx;
#else
	void *pad[2];
#endif 

};                                                                                                                             
#define WS_LOCAL 1 // Can be only accessed by localhost
#define WS_USESSL 2 // Use ssl conections (openssl lib required)      
#define WS_USEEXTCONF 4 // Use external config file (new 0.5.0)


void web_server_useSSLcert(struct web_server *,const char *); // Mandatory if WS_USESSL set
void web_server_useMIMEfile(struct web_server*,const char *); // new on 0.5.2
int web_server_init(struct web_server *,int,const char *,int);
void web_server_shutdown(struct web_server *);
int web_server_addhandler(struct web_server *,const char *,void (*)(),int);
int web_server_aliasdir(struct web_server *, const char *, char *,int );
int web_server_run(struct web_server *);
int web_server_setup(struct web_server *server,const char *conffile); // (new on 0.5.0)
char *web_server_getconf(struct web_server *, const char *,const char *); // (new on 0.5.0)


#include "weblog.h"

#endif

