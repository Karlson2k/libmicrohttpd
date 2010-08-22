#ifndef MD5_H
#define MD5_H

#include "MHD_config.h"

#ifdef WORDS_BIGENDIAN
#define HIGHFIRST
#endif

#define MD5_DIGEST_SIZE 16

struct MD5Context 
{
  uint32_t buf[4];
  uint32_t bits[2];
  unsigned char in[64];
};


void 
MD5Init(struct MD5Context *ctx);

void
MD5Update(struct MD5Context *ctx,
	  const void *buf,
	  unsigned len);

void MD5Final(unsigned char digest[MD5_DIGEST_SIZE],
	      struct MD5Context *ctx);

#endif /* !MD5_H */
