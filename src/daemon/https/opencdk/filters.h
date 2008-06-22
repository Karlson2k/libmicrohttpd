/* filters.h - Filter structs
 *        Copyright (C) 2002, 2003 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * OpenCDK is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * OpenCDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef CDK_FILTERS_H
#define CDK_FILTERS_H

enum {
    STREAMCTL_READ  = 0,
    STREAMCTL_WRITE = 1,
    STREAMCTL_FREE  = 2
};

typedef struct {
  gcry_cipher_hd_t hd;
  gcry_md_hd_t mdc;
  int mdc_method;
  cdk_dek_t dek;
  u32 datalen;
  struct {
    size_t on;
    off_t size;
    off_t nleft;
  } blkmode;
  cdk_stream_t s;
} cipher_filter_t;

typedef struct {
  int digest_algo;
  gcry_md_hd_t md;
} md_filter_t;

typedef struct {
  const char *le; /* line endings */
  const char *hdrlines;
  u32 crc;
  int crc_okay;
  int idx, idx2;
} armor_filter_t;

typedef struct {
  cdk_lit_format_t mode;
  char *orig_filename; /* This original name of the input file. */
  char *filename;
  gcry_md_hd_t md;
  struct {
    size_t on;
    off_t size;
  } blkmode;
} literal_filter_t;

typedef struct {
  size_t inbufsize;
  byte inbuf[8192];
  size_t outbufsize;
  byte outbuf[8192];
  int algo; /* compress algo */
  int level;
} compress_filter_t;

typedef struct {
    const char * lf;
} text_filter_t;


/*-- armor.c -*/
int _cdk_filter_armor( void * opaque, int ctl, FILE * in, FILE * out );

/*-- cipher.c --*/
cdk_error_t _cdk_filter_hash( void * opaque, int ctl, FILE * in, FILE * out );
cdk_error_t _cdk_filter_cipher( void * opaque, int ctl,
                                FILE * in, FILE * out );

/*-- literal.c --*/
int _cdk_filter_literal( void * opaque, int ctl, FILE * in, FILE * out );
int _cdk_filter_text( void * opaque, int ctl, FILE * in, FILE * out );

/*-- compress.c --*/
cdk_error_t _cdk_filter_compress( void * opaque, int ctl,
                                  FILE * in, FILE * out );

#endif /* CDK_FILTERS_H */

        
