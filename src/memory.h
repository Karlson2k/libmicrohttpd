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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h> 

#define __ILWS_malloc malloc
#define __ILWS_calloc calloc
#define __ILWS_realloc realloc
#define __ILWS_free free

struct memrequest;

struct memrequest *__ILWS_init_buffer_list();

void *__ILWS_add_buffer(struct memrequest *,
			unsigned int);

void __ILWS_delete_buffer(struct memrequest *);

void __ILWS_delete_next_buffer(struct memrequest *);

void __ILWS_delete_buffer_list(struct memrequest *);

#endif
