/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * file: utils.h
 *
 * description: Header
 *
 * date: 19:50,07-50-2002
 */

#ifndef _UTILS_H_ 
#define _UTILS_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif         

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#else
#include <time.h>
#endif

#include "debug.h"
#include "error.h"
#include "memory.h"

#ifdef WIN32

#define strncasecmp strnicmp
#define snprintf _snprintf
#define lstat stat
#define vsnprintf _vsnprintf

#endif


#define TMPNAMESIZE 8
extern char *_tmpnameprefix;


char *__ILWS_stristr(char *, const char *);
char *__ILWS_tmpfname();
int __ILWS_base64decode(char *, const char *);
char *__ILWS_date(time_t,const char *);


#endif
