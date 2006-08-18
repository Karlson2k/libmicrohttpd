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
 * -- memory functions
 */
#include "memory.h"

struct memrequest {
  char *ptr;
  struct memrequest *next;
};

/*
 *  Add a buffer to memrequest list
 */
void *__ILWS_add_buffer(struct memrequest *list,unsigned int size) {
  struct memrequest *tmem;
  if(size==0) {
    return NULL;
  };
  if(list!=NULL) {
    tmem=list;
  }else {
    return NULL;
  };
  while(tmem->next!=NULL)tmem=tmem->next;
  tmem->next=__ILWS_malloc(sizeof(struct memrequest));
  if(tmem->next==NULL) return NULL;           // ERROR
  tmem->next->ptr=__ILWS_malloc(size);
  tmem->next->next=NULL;
  return tmem->next->ptr;
}

/*
 * Initialize memrequest list of buffers
 */
struct memrequest *__ILWS_init_buffer_list() {
  struct memrequest *newlist;
  newlist=__ILWS_malloc(sizeof(struct memrequest));
  if(newlist==NULL) 
    return NULL;  
  newlist->next=NULL;
  newlist->ptr=NULL;
  return newlist;
}

/*
 * Delete memrequest buffer node (free)
 */
void __ILWS_delete_buffer(struct memrequest *mem) {
  __ILWS_free(mem->ptr);
  __ILWS_free(mem);
}

/*
 * Delete memrequest next buffer
 */
void __ILWS_delete_next_buffer(struct memrequest *mem) {
  struct memrequest *tmem;
  tmem=mem->next;
  mem->next=mem->next->next;
  __ILWS_delete_buffer(tmem);
}

/*
 * Delete whole memrequest buffer list
 */
void __ILWS_delete_buffer_list(struct memrequest *list) {
  struct memrequest *tmem=list;
  if (tmem==NULL) 
    return;
  
  while(tmem->next!=NULL) {
    __ILWS_delete_next_buffer(tmem);
  };
  __ILWS_delete_buffer(tmem);
}

