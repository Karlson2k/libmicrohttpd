/* by Luis Figueiredo (stdio@netc.pt)
 *
 * file: sound_buffers.h
 *
 * description: Holds sound data structures and functions
 *
 * date: 13:14,29-14-2002
 */

#ifndef _SOUND_BUFFERS_H_ 
#define _SOUND_BUFFERS_H_

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

struct sound_buf {
	char *id;
	unsigned char *data;
	unsigned int data_i;
	unsigned int play_i;
	unsigned int startloop,endloop;
	unsigned char volume;
	unsigned char channels;
	int mode;
	struct sound_buf *next;
};


struct sound_buf *sbuf_init();
struct sound_buf *sbuf_add(struct sound_buf *list,char *id);
struct sound_buf *sbuf_select(struct sound_buf *list,char *id);
int sbuf_delete(struct sound_buf *list,char *id);


	

#endif
