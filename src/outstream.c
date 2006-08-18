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
 * -- stream list functions
 */


#include "outstream.h"

/*********************************************************************************************************/ 
/*
 *	add_outstream, add a file to output (client) stream
 */
int __ILWS_add_outstream(struct outstream *list,char *fname,FILE* stream,int istmp){
	struct outstream *temp=list;
	FILE *tmp;
	while(temp->next!=NULL)temp=temp->next;
	
	if(!(temp->next=__ILWS_malloc(sizeof(struct outstream)))) {
		LWSERR(LE_MEMORY);
		return 0;
	};
	// file check (0.5.3);
	tmp=fopen(fname,"rb");
	if(tmp==NULL) {
		__ILWS_free(temp->next);
		temp->next=NULL;
		return 0;
	};
	fclose(tmp);
	// -- 
	temp->next->fname=NULL;
	if(fname!=NULL) {
		if(!(temp->next->fname=__ILWS_malloc(strlen(fname)+1))) {
			__ILWS_free(temp->next);
			temp->next=NULL;
			LWSERR(LE_MEMORY);
			return 0;
		};
		memcpy(temp->next->fname,fname,strlen(fname));
		temp->next->fname[strlen(fname)]='\0'; 
	};
	temp->next->todelete=istmp;
	temp->next->fstream=stream;
	temp->next->wsize=1;
	temp->next->rsize=0;
	temp->next->wrotesize=0;
	temp->next->varsize=0;
	temp->next->next=NULL;	
	return 1;	
}

/*********************************************************************************************************/
/*
 * Initializate (allocate) outstream list
 */
struct outstream *__ILWS_init_outstream_list() {
	struct outstream *ret;
	
	
	if(!(ret=__ILWS_malloc(sizeof(struct outstream)))) {
		LWSERR(LE_MEMORY);
		return NULL;
	};
	ret->todelete=0;
	ret->fname=NULL;
	ret->flags=0;
	ret->fstream=NULL;
	ret->next=NULL;
	return ret;
}

/*********************************************************************************************************/
/*
 * Delete a especific node
 */
void __ILWS_delete_outstream(struct outstream *node) { // Changed
	int rt;
	if(node->fstream!=NULL)fclose(node->fstream); // better here;
	if(node->todelete) { // is temporary file
		rt=unlink(node->fname);
		if(rt==-1) {
			LWSERR(LE_FILESYS);
		};
		
	};
	if(node->fname!=NULL)__ILWS_free(node->fname);
	__ILWS_free(node);
}

/*********************************************************************************************************/
/*
 * delete next node 
 */
void __ILWS_delete_next_outstream(struct outstream *node) {
	struct outstream *temp=node->next;
	node->next=node->next->next;
	__ILWS_delete_outstream(temp);
}

/*********************************************************************************************************/
/*
 * delete all nodes on the list (reset list)
 */
void __ILWS_delete_outstream_list(struct outstream *list) {
	struct outstream *temp=list;
	while(temp->next!=NULL) {
		
		__ILWS_delete_next_outstream(temp);
	};
	
	__ILWS_delete_outstream(temp);
	
}

