/* by Luis Figueiredo (stdio@netc.pt)
 *
 * file: soundcard.h
 *
 * description: handlers soundcard setup
 *
 * date: 17:00,13-00-2002
 */

#ifndef _SOUNDCARD_H_ 
#define _SOUNDCARD_H_

#include <fcntl.h>
#include <sys/soundcard.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include "debug.h"

struct soundcard_setup {
        int rate;
        char channels;
        int fmt;
};

int soundcard_init(const char *, struct soundcard_setup *);




#endif
