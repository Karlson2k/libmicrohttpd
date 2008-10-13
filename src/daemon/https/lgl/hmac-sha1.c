/* hmac-sha1.c -- hashed message authentication codes
   Copyright (C) 2005, 2006 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Written by Simon Josefsson.  */

#include "MHD_config.h"

#include "hmac.h"

#include "memxor.h"
#include "sha1.h"

#include <string.h>

#define IPAD 0x36
#define OPAD 0x5c

int
MHD_hmac_sha1 (const void *key, size_t keylen,
               const void *in, size_t inlen, void *resbuf)
{
  struct MHD_sha1_ctx inner;
  struct MHD_sha1_ctx outer;
  char optkeybuf[20];
  char block[64];
  char innerhash[20];

  /* Reduce the key's size, so that it becomes <= 64 bytes large.  */

  if (keylen > 64)
    {
      struct MHD_sha1_ctx keyhash;

      MHD_sha1_init_ctx (&keyhash);
      MHD_sha1_process_bytes (key, keylen, &keyhash);
      MHD_sha1_finish_ctx (&keyhash, optkeybuf);

      key = optkeybuf;
      keylen = 20;
    }

  /* Compute INNERHASH from KEY and IN.  */

  MHD_sha1_init_ctx (&inner);

  memset (block, IPAD, sizeof (block));
  MHD_memxor (block, key, keylen);

  MHD_sha1_process_block (block, 64, &inner);
  MHD_sha1_process_bytes (in, inlen, &inner);

  MHD_sha1_finish_ctx (&inner, innerhash);

  /* Compute result from KEY and INNERHASH.  */

  MHD_sha1_init_ctx (&outer);

  memset (block, OPAD, sizeof (block));
  MHD_memxor (block, key, keylen);

  MHD_sha1_process_block (block, 64, &outer);
  MHD_sha1_process_bytes (innerhash, 20, &outer);

  MHD_sha1_finish_ctx (&outer, resbuf);

  return 0;
}
