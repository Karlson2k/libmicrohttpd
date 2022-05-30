/*
 * This code implements the BASE64 algorithm.
 * This code is in the public domain; do with it what you wish.
 *
 * @file base64.c
 * @brief This code implements the BASE64 algorithm
 * @author Matthieu Speder
 * @author Karlson2k (Evgeny Grin): fixes and improvements
 */
#include "mhd_options.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif /* HAVE_STDDEF_H */
#include "base64.h"

static const char base64_digits[] =
{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
  0, 0, 0, -1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
  14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26,
  27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
  45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


char *
BASE64Decode (const char *src,
              size_t in_len,
              size_t *out_len)
{
  unsigned char *dest;
  char *result;

  if (in_len % 4)
  {
    /* Wrong base64 string length */
    return NULL;
  }
  dest = (unsigned char *) malloc (in_len / 4 * 3 + 1);
  result = (char *) dest;
  if (NULL == result)
    return NULL; /* out of memory */
  for (; 0 < in_len && 0 != *src; in_len -= 4)
  {
    char a = base64_digits[(unsigned char) *(src++)];
    char b = base64_digits[(unsigned char) *(src++)];
    char c = base64_digits[(unsigned char) *(src++)];
    char d = base64_digits[(unsigned char) *(src++)];
    if (((char) -1 == a) || (0 == a) || (0 == b) || (0 == c) || (0 == d))
    {
      free (result);
      return NULL;
    }
    *(dest++) = (unsigned char) (((unsigned char) a) << 2)
                | (unsigned char) ((((unsigned char) b) & 0x30) >> 4);
    if (c == (char) -1)
      break;
    *(dest++) = (unsigned char) ((((unsigned char) b) & 0x0f) << 4)
                | (unsigned char) ((((unsigned char) c) & 0x3c) >> 2);
    if (d == (char) -1)
      break;
    *(dest++) = (unsigned char) ((((unsigned char) c) & 0x03) << 6)
                | ((unsigned char) d);
  }
  *dest = 0;
  if (NULL != out_len)
    *out_len = (size_t) (dest - (unsigned char *) result);
  return result;
}


/* end of base64.c */
