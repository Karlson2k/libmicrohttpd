#ifndef SHA1_H
#define SHA1_H
/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain

Test Vectors (from FIPS PUB 180-1)
"abc"
  A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
A million repetitions of "a"
  34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

#include "MHD_config.h"

#ifndef WORDS_BIGENDIAN
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif 
#endif

#include <stdio.h>
#include <string.h>

struct SHA1Context {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
};

#define SHA1_DIGEST_SIZE 20

void SHA1Init(struct SHA1Context* context);
void SHA1Update(struct SHA1Context* context,
		const void* data, 
		unsigned int len);
void SHA1Final(unsigned char digest[SHA1_DIGEST_SIZE], 
	       struct SHA1Context* context);


#endif
