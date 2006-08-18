/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * Fri Dec 28 12:51:11 GMT 2001
 *      Luis Figueiredo -- I Corrected the input to handle only data when \n\r(twice) is arrived
 *
 * Mon Feb 25 06:27:58 GMT 2002
 *      Luis Figueiredo -- Many corrections and new functions were added, until today
 *
 * Mon Mar 25 14:46:13 GMT 2002
 *      Luis Figueiredo -- wow, one month later..., discard web_server_addstr, and now process the stdout to server
 *                         using a tmpfile for streaming (not so good, but :o))
 * Wed Mar 27 18:59:10 GMT 2002
 *      Luis Figueiredo -- using regex instead of fnmatch(fnmatch only appears becouse of apache, i didn't knew it)
 * Mon Apr  8 15:04:31 GMT 2002
 *	Luis Figueiredo -- Oh my.. kurt cobain is dead :o), restructured the code, separated into various files                                                                 
 * Wed Apr 10 20:02:55 GMT 2002
 *	Luis Figueiredo -- Make use of autoconf , removed open_memstream (doesn't work well w/ stdout structure on netbsd portability)
 *                         linux slack 7.1 uses "extern FILE *stdout", netbsd uses "extern FILE __sF[]" so i cannot make use of pointers
 * Mon Oct  7 16:56:15 GMT 2002
 *      Luis Figueiredo -- Repaired some safe bugs, Added vars to stats proposes, inserted an liblogo, added debug instructions
 *
 *  VERSION 0.5.3
 */

#ifndef _WEB_SERVER_H_
#define _WEB_SERVER_H_

#include <stdio.h> // for struct FILE
#include <time.h> // for time_t

#ifdef __cplusplus
extern "C"{
#endif 

extern char *_libwebserver_version;
extern char *_tmpnameprefix;
extern int WEBTIMEOUT;

struct _MultiPart {
	char *id;
	char *data;
	unsigned int size;
	char *filename;
	void *pad;
};
char *__Header(char *);
char *__Query(char *);
char *__Post(char *);
struct _MultiPart __MultiPart(char *);
char *__Cookie(char *);

extern struct ClientInfo {
	int outfd;
	char *inetname;
	char *request;
	char *method;
	char *user;
	char *pass;
	char *(*Header)(char *);
	char *(*Query)(char *);
	char *(*Post)(char *);
	char *(*Cookie)(char *);
	char *(*Conf)(char *,char *); // new on 0.5.0
	struct _MultiPart (*MultiPart)(char *); 
	void *__pad[9];

} *ClientInfo;      // PROTOTYPE    

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
	void *pad[2];    // SSL pad
};                                                                                                                             

#define WS_LOCAL 1 	    // Can be only accessed by localhost (usefull for local programs gui's)
#define WS_USESSL 2     // Use ssl conections (openssl lib required) (security transation) (there is no sense using WS_LOCAL & WS_USESSL together)
#define WS_USEEXTCONF 4 // Use external config file (new 0.5.0)
#define WS_DYNVAR 8     // Use dynamic variables on output (new 0.5.1)
#define WS_USELEN 16     //Use Content-length calculator(new 0.5.1)


void web_server_useSSLcert(struct web_server *,const char *);  // useless if not using openssl
void web_server_useMIMEfile(struct web_server *,const char *); // new on 0.5.2
int web_server_init(struct web_server *,int,const char *,int);
void web_server_shutdown(struct web_server *);
char *web_server_getconf(struct web_server *,char *,char *);
int web_server_addhandler(struct web_server *,const char *,void (*)(),int);
int web_server_aliasdir(struct web_server *, const char *,char *,int); // new on 0.5.2
int web_server_run(struct web_server *);


int web_client_addfile(char *);
extern unsigned char GLOBALGIFPAL[256][3];
void web_client_gifsetpalette(const char *);
int web_client_gifoutput(char *,int,int,int);

void web_client_setcookie(char *,char *,char *,char *, char *,int); // improved on 0.5.1
void web_client_deletecookie(char *);                // improved on 0.5.1
int web_client_setvar(char *,char *); //(new (0.5.1)
char *web_client_getvar(char *);        //(new (0.5.1)
int web_client_delvar(char *);        //(new (0.5.1)

void web_client_HTTPdirective(char *);   
void web_client_contenttype(char *); // 0.5.2
void web_log(const char *,...);           


#ifdef __cplusplus
}
#endif

#endif

