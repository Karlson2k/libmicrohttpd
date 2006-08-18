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

#ifndef _SOCKET_H_
#define _SOCKET_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif         

#include <stdio.h>
#include <stdarg.h>

#ifdef WIN32
#include <winsock2.h>
#include <io.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h> // struct tv
#include <sys/types.h>  // freebsd need it i gues that is no problem if other system includes it
#endif





#include "debug.h"

extern int errno;

int __ILWS_newdata(int);
int __ILWS_listensocket(short, int);
int __ILWS_read(int,void *,size_t);

#endif

