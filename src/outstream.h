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
 *  stream functions
 */

#ifndef _OUTSTREAM_H_
#define _OUTSTREAM_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include "debug.h"
#include "memory.h"
#include "error.h"





struct outstream {
	FILE *fstream;
	char *fname;
	int todelete;
	int wsize,rsize; 
	long wrotesize;
	long varsize;
	int flags;
	struct outstream *next;
};

int __ILWS_add_outstream(struct outstream *, char *,FILE *,int);
struct outstream *__ILWS_init_outstream_list();
void __ILWS_delete_next_outstream(struct outstream *);
void __ILWS_delete_outstream_list(struct outstream *);
void __ILWS_delete_outstream(struct outstream *);
#endif
