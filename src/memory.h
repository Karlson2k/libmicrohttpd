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

#ifndef _MEMORY_H_
#define _MEMORY_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif         


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h> // Johannes E. Schindelin

#include "debug.h"

extern int errno;

void *__ILWS_malloc(size_t);
void *__ILWS_calloc(size_t,size_t);
void *__ILWS_realloc(void *,size_t);
void __ILWS_free(void *);

struct memrequest {
	char *ptr;
	struct memrequest *next;
};
struct memrequest *__ILWS_init_buffer_list();
void *__ILWS_add_buffer(struct memrequest *,unsigned int);
void __ILWS_delete_buffer(struct memrequest *);
void __ILWS_delete_next_buffer(struct memrequest *);
void __ILWS_delete_buffer_list(struct memrequest *);

#endif
