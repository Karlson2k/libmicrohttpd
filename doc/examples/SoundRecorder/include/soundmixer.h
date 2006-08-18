/* by Luis Figueiredo (stdio@netc.pt)
 *
 * file: soundmixer.h
 *
 * description: Sound mixer using (soundbuffers.c)
 *
 * date: 17:13,13-13-2002
 */

#ifndef _SOUNDMIXER_H_ 
#define _SOUNDMIXER_H_

#include <stdio.h>
#include <unistd.h>


#include "soundbuffers.h"

#define _SDMAX 44100 // quarter second *2 *2

void sound_process(int soundfd,struct sound_buf *list);

#endif
