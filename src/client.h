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

#ifndef _CLIENT_H_
#define _CLIENT_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "socket.h"
#include "memory.h"
#include "utils.h"
#include "fnmatch.h"
#include "clientinfo.h"

#ifdef WIN32
#include "flock.h"     // my flock
#include "dirent.h"
#else
#include <sys/file.h>  // for flock
#include <dirent.h>
#endif

struct gethandler {
  char * str;
  void (*func)();  
  void * ctx;
  struct gethandler * next;
};      



#define READMAX 100000  // 1Mb upload 

#define WRITEMAX 100000 // 1Mb download 1mb per client? // smaller is better for multi read bigger is better for big downloads

#define MAXURLSIZE 2000 // 

extern int WEBTIMEOUT;    //to be changed externaly
//#define WEBTIMEOUT 10000 // TIMEOUT WITHOUT RECEIVING DATA (not in seconds but in read tries)

struct web_var {
  char *name;
  char *value;
  struct web_var *next;
};

struct web_client {
  int socket;
  struct sockaddr_in sa;
  unsigned int salen;
  char *HTTPdirective;
  unsigned char stat;  /* 0001b idle,0010b down streaming, 0011 done down streaming, 0100b out streaming,0101 done out streaming */
  // Read control	
  char *rbuf;
  unsigned long rbufsize;
  int newdata_try;
  unsigned long contentlength; // for read propose (optimize speed 0.5.1)
  unsigned long headersize;
  
  // Write control
  struct outstream *outstream;
  struct web_var *varlist;
  char *cookies; // cookie header (0.5.1)		 
  long writelength;
  long readsize;
  long range;
  int skipped;
  long wheadersize; 
  struct web_client * next;
};                      

struct web_client *__ILWS_init_client_list(void);

int __ILWS_add_client(struct web_client *,
		      struct web_client *);

void __ILWS_delete_next_client(struct web_client *);

void __ILWS_delete_client_list(struct web_client *);

void __ILWS_read_client(struct web_client *);

void __ILWS_process_client(struct web_client *,struct gethandler *);

void __ILWS_output_client(struct web_client *);

void __ILWS_web_client_writef(struct web_client *,const char *,...);

int web_client_addfile(char *);

void web_client_contenttype(char *); // new on 0.5.2

void web_client_HTTPdirective(char *);

char *__ILWS_web_client_getreqline();

char *__ILWS_web_client_getreq();

// new (0.5.1)
int web_client_setvar(char *,char *);

char *web_client_getvar(char *);

int web_client_delvar(char *);

// put in var.h
struct web_var *__ILWS_init_var_list();

int __ILWS_add_var(struct web_var *, char *, char *);

int __ILWS_del_var(struct web_var *, char *);

void __ILWS_delete_var_list(struct web_var *);

char *__ILWS_get_var(struct web_var *list , char *name);

int __ILWS_lws_list(char *); // new on 0.5.2

#endif

