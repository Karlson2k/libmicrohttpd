/* by Luis Figueiredo (stdio@netc.pt)
 *
 * file: soundcard.c
 *
 * description: handlers soundcard setup
 *
 * date: 17:00,13-00-2002
 */

#include "soundcard.h"






int soundcard_init(const char *dev, struct soundcard_setup *ss) {
        int ret;
	int soundfd;
	soundfd=open(dev,O_RDWR|O_NONBLOCK);
	if(soundfd <1) {
		perror("open");
		return -1;
	}
        IFDEBUG(fprintf(stderr,"soundcard.c: Setting soundcard:\n"));
        IFDEBUG(fprintf(stderr,"soundcard.c: rate: %d\n",ss->rate));
        ret=ioctl(soundfd,SNDCTL_DSP_SPEED,&ss->rate);
        if(ret==-1) {
                perror("ioctl");
                return-1 ;
        };
        IFDEBUG(fprintf(stderr,"soundcard.c: channels: %d\n",ss->channels));
        ret=ioctl(soundfd,SNDCTL_DSP_CHANNELS,&ss->channels);
        if(ret==-1) {
                perror("ioctl");
                return -1;
        };
        IFDEBUG(fprintf(stderr,"soundcard.c: fmt %d\n",ss->fmt));
        ret=ioctl(soundfd,SNDCTL_DSP_SETFMT,&ss->fmt);
        if(ret==-1) {
                perror("ioctl");
                return -1;
        };
        IFDEBUG(fprintf(stderr,"Sound card setup sucessfull\n"));
	return soundfd;
};



