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
 * -- handlers functions
 *
 */



#include "gethandler.h"


/*********************************************************************************************************/
/*
 * initializate (allocate) handler list
 */
struct gethandler *__ILWS_init_handler_list() {
	struct gethandler *ret;
	
	ret=__ILWS_malloc(sizeof(struct gethandler));
	if(ret==NULL) {
		LWSERR(LE_MEMORY);
		return NULL;
	};
	ret->next=NULL;
	ret->hdl.func=NULL; // or path
	ret->flag=0;
	ret->str=NULL;
	return ret;
}

/*********************************************************************************************************/
/* 
 * add an handler to list
 */
int __ILWS_add_handler(struct gethandler *handler, const char *mstr, void (*func)(), char *path, int flag, int type) {
	struct gethandler *temp=handler;
	while(temp->next!=NULL)temp=temp->next;
	
	temp->next=__ILWS_malloc(sizeof(struct gethandler));
	if(temp->next==NULL) {
		LWSERR(LE_MEMORY);
		return 0;
	};
	
	temp->next->str=__ILWS_malloc(strlen(mstr)+1);
	if(temp->next->str==NULL) {
		__ILWS_free(temp->next); // free last malloced
		LWSERR(LE_MEMORY);
		return 0;
	};
	memcpy(temp->next->str,mstr,strlen(mstr));
	temp->next->str[strlen(mstr)]='\0';
	
	temp->next->type=type;
	switch (temp->next->type) {
		case 0:
			temp->next->hdl.func=func;         // for function
			break;
		case 1: // new on 0.5.2            // directory or cgi
		case 2:
			if(!(temp->next->hdl.path=strdup(path))) {
				__ILWS_free(temp->next->str);
				__ILWS_free(temp->next);
				LWSERR(LE_MEMORY);
				return 0;
			};
			
			break;
	};
	
	temp->next->flag=flag;
    temp->next->next=NULL;
    return 1;
}                         

/*********************************************************************************************************/
/* 
 * Deletes the entire handler list
 */
void __ILWS_delete_handler_list(struct gethandler *handler) {
	struct gethandler *next;
	
	while(handler) {
		next = handler->next;
		__ILWS_free(handler);
		handler = next;
	}
}
