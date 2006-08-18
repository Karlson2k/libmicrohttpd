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

IFDEBUG(int _t=0;)

/*********************************************************************************************************/
/*
 * same as malloc with error reporting and libwebserver debug
 */
void * __ILWS_malloc(size_t s) {
	void *ret;

	ret=malloc(s);
	if(ret==NULL) {
		IFDEBUG(fprintf(stderr,"memory.c: malloc: %s (size %d)\n",strerror(errno),s);fflush(stderr));
		return NULL;
	};
	IFDEBUG(_t++;);
	
	IFDEBUG(fprintf(stderr,"memory.c (%d): Allocated %d bytes to %p\n",_t,s,ret);fflush(stderr));
	return ret;
}

/*********************************************************************************************************/
/*
 * same as calloc with error reporting and libwebserver debug
 */
void * __ILWS_calloc(size_t nmemb,size_t s) {
	void *ret;
	ret=calloc(nmemb,s);
	if(ret==NULL) {
		IFDEBUG(fprintf(stderr,"memory.c: calloc %s\n",strerror(errno));fflush(stderr));
		return NULL;
	};
	IFDEBUG(_t++;);
	IFDEBUG(fprintf(stderr,"memory.c (%d): Allocated %d bytes to %p\n",_t,s*nmemb,ret);fflush(stderr));
	return ret;
}

/*********************************************************************************************************/
/* 
 * same as realloc with error reporting and libwebserver debug
 */
void * __ILWS_realloc(void *buf,size_t s) {
	void *ret;
	ret=realloc(buf,s);
#ifdef DEBUG
	if(buf==NULL) {
		_t++;
		IFDEBUG(fprintf(stderr,"memory.c (%d): Allocated %d bytes to %p\n",_t,s,ret);fflush(stderr));
	};
#endif
	if(ret==NULL) {
		IFDEBUG(fprintf(stderr,"memory.c: realloc: %s\n",strerror(errno));fflush(stderr));
		return NULL;
	};
	IFDEBUG(fprintf(stderr,"memory.c: Realloc buffer %p to %d\n",buf,s);fflush(stderr));
	return ret;
}


/*********************************************************************************************************/
/*
 * same as free with error report and libwebserver debug
 */ 
void __ILWS_free(void *ptr) {
	if(ptr!=NULL) {
		free(ptr);
		IFDEBUG(fprintf(stderr,"memory.c (%d): Buffer %p freed\n",_t,ptr);fflush(stderr));
		IFDEBUG(_t--;);
	};
}


/*********************************************************************************************************/
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

/*********************************************************************************************************/
/*
 * Initialize memrequest list of buffers
 */
struct memrequest *__ILWS_init_buffer_list() {
	struct memrequest *newlist;
	newlist=__ILWS_malloc(sizeof(struct memrequest));
	if(newlist==NULL) return NULL;
	
	newlist->next=NULL;
	newlist->ptr=NULL;
	return newlist;
}

/*********************************************************************************************************/
/*
 * Delete memrequest buffer node (free)
 */
void __ILWS_delete_buffer(struct memrequest *mem) {
	__ILWS_free(mem->ptr);
	__ILWS_free(mem);
}

/*********************************************************************************************************/
/*
 * Delete memrequest next buffer
 */
void __ILWS_delete_next_buffer(struct memrequest *mem) {
	struct memrequest *tmem;
	tmem=mem->next;
	mem->next=mem->next->next;
	__ILWS_delete_buffer(tmem);
}

/*********************************************************************************************************/
/*
 * Delete whole memrequest buffer list
 */
void __ILWS_delete_buffer_list(struct memrequest *list) {
	struct memrequest *tmem=list;
	if(tmem==NULL) return;

	while(tmem->next!=NULL) {
		__ILWS_delete_next_buffer(tmem);
	};
	__ILWS_delete_buffer(tmem);
}

