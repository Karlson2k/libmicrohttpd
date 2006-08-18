/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * date: Sat Mar 30 14:25:25 GMT 2002 
 *
 *  memory functions
 */

#ifndef _WEBLOG_H_
#define _WEBLOG_H_



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef WIN32
#define snprintf _snprintf
#endif



#include "debug.h"

extern FILE *_logfile;

void web_log(const char *,...);           
FILE *open_weblog(const char *);
char *mydate();
#endif
