/* by Luis Figueiredo (stdio@netc.pt)
 *
 * file: sound_buffers.c
 *
 * description: Sounddata procedures
 *
 * date: 13:23,29-23-2002
 */

#include "soundbuffers.h"


/*
 * init list
 */
struct sound_buf *sbuf_init() {
	struct sound_buf *head;
	head=malloc(sizeof(struct sound_buf));
	head->next=NULL;
	head->data_i=0;
	head->data=NULL;
	head->id=NULL;
	return head;
};

struct sound_buf *sbuf_select(struct sound_buf *list,char *id) {
	struct sound_buf *temp=list;
	while(temp->next!=NULL) {
		if(temp->next->id!=NULL) {
			if(!strcmp(temp->next->id,id)) {
				return temp->next;
			};
		};
		temp=temp->next;
	};
	return NULL;
};


/*
 * next prototipe go to select_buffer
 */
struct sound_buf *sbuf_add(struct sound_buf *list,char *id) {
	struct sound_buf *temp=list;
	while(temp->next!=NULL) {
		if(temp->next->id!=NULL) {
			if(!strcmp(temp->next->id,id)) {
				return NULL;
			};
			temp=temp->next; // Next buffer
		};
	};
	// id is new lets create this buffer
	temp->next=malloc(sizeof(struct sound_buf));
	// lets copy the new id	
	temp->next->id=malloc(strlen(id)+1);
	strncpy(temp->next->id,id,strlen(id));
	temp->next->id[strlen(id)]=0;
	// zero the rest;
	temp->next->data=NULL;
	temp->next->data_i=0;
	temp->next->play_i=0;
	temp->next->mode=0;
	temp->next->volume=128;
	temp->next->next=NULL;
	return temp->next;
};

int sbuf_delete(struct sound_buf *list,char *id) {
	struct sound_buf *temp=list;
	struct sound_buf *t;
	while(temp->next!=NULL) {
		if(temp->next->id!=NULL) {
			if(!strcmp(temp->next->id,id)) {
				t=temp->next;
				temp->next=temp->next->next;
				free(t->data);
				free(t->id);
				free(t);
				return 1;
			};
		};
		temp=temp->next;
	};
	return 0;
};
