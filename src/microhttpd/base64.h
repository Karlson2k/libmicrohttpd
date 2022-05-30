/*
 * This code implements the BASE64 algorithm.
 * This code is in the public domain; do with it what you wish.
 *
 * @file base64.c
 * @brief This code implements the BASE64 algorithm
 * @author Matthieu Speder
 */
#ifndef BASE64_H
#define BASE64_H

#include "mhd_options.h"
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#elif defined(HAVE_STDLIB_H)
#include <stdlib.h>
#else
#include <stdio.h>
#endif

char *
BASE64Decode (const char *src,
              size_t in_len,
              size_t *out_len);

#endif /* !BASE64_H */
