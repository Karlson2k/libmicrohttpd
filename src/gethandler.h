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


#ifndef _GETHANDLER_H_
#define _GETHANDLER_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif         
#include <stdio.h>


#include "memory.h"
#include "error.h"


#define MATCHMAX 200

//#define WS_LOCAL 0x1
#define WS_DYNVAR 0x8
#define WS_USELEN 0x10


/*********************
 * get handler types *
 *********************/
#define GH_FUNCTION 0   // new on 0.5.2
#define GH_DIRECTORY 1  // new on 0.5.2
#define GH_CGI 2        // new on 0.5.2 (just the flag)


struct gethandler {
	char *str;
	int type;           // new on 0.5.2  types
	union hdl_u{        // changed on 0.5.3 named union (Hilobok Andrew (han@km.if.ua) said that wasn't compiling on FreeBSD)
		void (*func)();   // it is a function
		char *path;       // it is a path (dir or cgi)
	}hdl;
	int flag; 
	struct gethandler *next;
};      

struct gethandler *__ILWS_init_handler_list();
int __ILWS_add_handler(struct gethandler *,const char *,void (*func)(),char *, int,int);
void __ILWS_delete_handler_list(struct gethandler *);

#endif
