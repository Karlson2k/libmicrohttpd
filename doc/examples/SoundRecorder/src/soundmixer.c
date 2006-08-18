/* by Luis Figueiredo (stdio@netc.pt)
 *
 * file: soundmixer.c
 *
 * description: Sound mixer using (soundbuffers.c)
 *
 * date: 17:13,13-13-2002
 */


#include "soundmixer.h"


int SDMAX=_SDMAX;
#define ADJUST_VOLUME(s, v)     (s = (s*v)/128)

int soundout_i=-1;
void sound_process(int soundfd,struct sound_buf *list) {
	int soundin_i;
	struct sound_buf *sbuf;
	unsigned char soundin[_SDMAX+1];
	unsigned char soundout[_SDMAX+1];
	int playit=0;
	int i;	
	short src1,src2;
	int dst_sample;
	const int max_audioval =((1<<(16-1))-1);
	const int min_audioval =-(1<<(16-1));
	soundin_i=read(soundfd,soundin,_SDMAX);
	sbuf=list->next;
	while(sbuf!=NULL) {
		if(soundin_i>0) {
			if(sbuf->mode==2) {
					sbuf->data=realloc(sbuf->data,sbuf->data_i+soundin_i);
					memcpy(sbuf->data+sbuf->data_i,soundin,soundin_i);
					sbuf->data_i+=soundin_i;
			};
		};
		if(sbuf->mode==1 && soundout_i==-1) {
			for(i=0;i<SDMAX && (sbuf->play_i+i)<sbuf->data_i;i+=4) {
				// LEFT
				src1=((sbuf->data[sbuf->play_i+i+1]<<8) | sbuf->data[sbuf->play_i+i]);
				ADJUST_VOLUME(src1,sbuf->volume);
				src2=((soundout[i+1]<<8) | soundout[i]);
				dst_sample=src1+src2;
				if ( dst_sample > max_audioval ) {
					dst_sample = max_audioval;
				} else if ( dst_sample < min_audioval ) {
					dst_sample = min_audioval;
				}
				soundout[i]=dst_sample &0xFF;
				dst_sample>>=8;
				soundout[i+1]=dst_sample & 0xFF;
				// RIGHT
				src1=((sbuf->data[sbuf->play_i+i+1+2]<<8) | sbuf->data[sbuf->play_i+i+2]);
				ADJUST_VOLUME(src1,sbuf->volume);
				if(sbuf->channels==2) {	
					src2=((soundout[i+1+2]<<8) | soundout[i+2]); // join left to right
				} else {
					src2=((soundout[i+1]<<8) | soundout[i]); // separate
				};
				dst_sample=src1+src2;
				if ( dst_sample > max_audioval ) {
					dst_sample = max_audioval;
				} else if ( dst_sample < min_audioval ) {
					dst_sample = min_audioval;
				}
				soundout[i+2]=dst_sample &0xFF;
				dst_sample>>=8;
				soundout[i+2+1]=dst_sample & 0xFF;

			};
			sbuf->play_i+=SDMAX;
			if(sbuf->play_i>sbuf->data_i){ 
				if(sbuf->mode==1) {
					sbuf->mode=0; // end,stop it
				}
				if(sbuf->mode==3) {
					sbuf->play_i=0;
				};
			}
			playit=1;
		};
		sbuf=sbuf->next;// next buffer
	};
	if(playit) {
		soundout_i=0;
		playit=0;
	};
	if(soundout_i<SDMAX && soundout_i!=-1) {
		i=write(soundfd,soundout+soundout_i,SDMAX-soundout_i);
		if(i>0) {
			soundout_i+=i;
		};
	} else {
		memset(soundout,0,SDMAX);
		soundout_i=-1;
	};

}




