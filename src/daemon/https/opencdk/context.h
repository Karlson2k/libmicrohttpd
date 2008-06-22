/* context.h
 *       Copyright (C) 2002, 2003, 2007 Timo Schulz
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
#ifndef CDK_CONTEXT_H
#define CDK_CONTEXT_H

#include "types.h"

struct cdk_listkey_s {
  unsigned init:1;
  cdk_stream_t inp;
  cdk_keydb_hd_t db;
  int type;
  union {
    char *patt;
    cdk_strlist_t fpatt;  
  } u;
  cdk_strlist_t t;   
};


struct cdk_s2k_s {
  int mode;
  byte hash_algo;
  byte salt[8];
  u32 count;
};


struct cdk_ctx_s {
  int cipher_algo;
  int digest_algo;
  struct {
    int algo;
    int level;
  } compress;
  struct {
    int mode;
    int digest_algo;
  } _s2k;
  struct {
    unsigned blockmode:1;
    unsigned armor:1;
    unsigned textmode:1;
    unsigned compress:1;
    unsigned mdc:1;
    unsigned overwrite;
    unsigned force_digest:1;
  } opt;
  struct {
    cdk_verify_result_t verify;
  } result;
  struct {
    cdk_pkt_seckey_t sk;
    unsigned on:1;
  } cache;
  cdk_dek_t dek;
  struct {
    cdk_keydb_hd_t sec;
    cdk_keydb_hd_t pub;
    unsigned int close_db:1;
  } db;
  char *(*passphrase_cb) (void *opaque, const char *prompt);
  void * passphrase_cb_value;
};

struct cdk_prefitem_s {
  byte type;
  byte value;
};

struct cdk_desig_revoker_s {
  struct cdk_desig_revoker_s * next;
  byte r_class;
  byte algid;
  byte fpr[KEY_FPR_LEN];
};

struct cdk_subpkt_s {
  struct cdk_subpkt_s * next;
  u32 size;
  byte type;
  byte d[1];  
};

struct cdk_keylist_s {
  struct cdk_keylist_s * next;
  union {
    cdk_pkt_pubkey_t pk;
    cdk_pkt_seckey_t sk;
  } key;
  int version;
  int type;  
};

struct cdk_dek_s {
  int algo;
  int keylen;
  int use_mdc;
  byte key[32]; /* 256-bit */
};

struct cdk_strlist_s {
  struct cdk_strlist_s * next;
  char d[1]; 
};

#endif /* CDK_CONTEXT_H */
