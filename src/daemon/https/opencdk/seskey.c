/* seskey.c - Session key routines
 *        Copyright (C) 2002, 2003, 2007 Timo Schulz
 *        Copyright (C) 1998-2000, 2002 Free Software Foundation, Inc.
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
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <gcrypt.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"


/* We encode the MD in this way:
 *
 * 0  1 PAD(n bytes)   0  ASN(asnlen bytes)  MD(len bytes)
 *
 * PAD consists of FF bytes.
 */
static cdk_error_t
do_encode_md (byte ** r_frame, size_t * r_flen, const byte * md, int algo,
              size_t len, unsigned nbits, const byte * asn, size_t asnlen)
{
  byte *frame = NULL;
  size_t nframe = (nbits + 7) / 8;
  size_t i, n = 0;

  if (!asn || !md || !r_frame || !r_flen)
    return CDK_Inv_Value;

  if (len + asnlen + 4 > nframe)
    return CDK_General_Error;

  frame = cdk_calloc (1, nframe);
  if (!frame)
    return CDK_Out_Of_Core;
  frame[n++] = 0;
  frame[n++] = 1;
  i = nframe - len - asnlen - 3;
  if (i < 0)
    {
      cdk_free (frame);
      return CDK_Inv_Value;
    }
  memset (frame + n, 0xFF, i);
  n += i;
  frame[n++] = 0;
  memcpy (frame + n, asn, asnlen);
  n += asnlen;
  memcpy (frame + n, md, len);
  n += len;
  if (n != nframe)
    {
      cdk_free (frame);
      return CDK_Inv_Value;
    }
  *r_frame = frame;
  *r_flen = n;
  return 0;
}



/* RFC2437 format:
 *  
 *  0  2  RND(n bytes)  0  [A  DEK(k bytes)  CSUM(2 bytes)]
 *  
 *  RND - randomized bytes for padding.
 *  A - cipher algorithm.
 *  DEK - random session key.
 *  CKSUM - algebraic checksum of the DEK.
 */

/**
 * cdk_dek_encode_pkcs1
 * @dek: DEK object
 * @nbits: size of the multi precision integer frame
 * @r_enc: output of the encoded multiprecision integer
 * 
 * Encode the given random session key in the DEK object
 * into a multiprecision integer.
 **/
cdk_error_t
cdk_dek_encode_pkcs1 (cdk_dek_t dek, size_t nbits, gcry_mpi_t * r_enc)
{
  gcry_mpi_t a = NULL;
  gcry_error_t err;
  byte *p, *frame;
  size_t n;
  size_t nframe;
  size_t i;
  u16 chksum;

  if (!r_enc || !dek)
    return CDK_Inv_Value;

  *r_enc = NULL;
  chksum = 0;
  for (i = 0; i < dek->keylen; i++)
    chksum += dek->key[i];
  nframe = (nbits + 7) / 8;
  frame = cdk_salloc (nframe + 1, 1);
  if (!frame)
    return CDK_Out_Of_Core;
  n = 0;
  frame[n++] = 0x00;
  frame[n++] = 0x02;
  i = nframe - 6 - dek->keylen;
  p = gcry_random_bytes (i, GCRY_STRONG_RANDOM);
  /* Replace zero bytes by new values */
  for (;;)
    {
      size_t j, k;
      byte *pp;

      /* count the zero bytes */
      for (j = k = 0; j < i; j++)
        {
          if (!p[j])
            k++;
        }
      if (!k)
        break;                  /* No zeroes remain. */
      k += k / 128;             /* better get some more */
      pp = gcry_random_bytes (k, GCRY_STRONG_RANDOM);
      for (j = 0; j < i && k; j++)
        {
          if (!p[j])
            p[j] = pp[--k];
        }
      cdk_free (pp);
    }
  memcpy (frame + n, p, i);
  cdk_free (p);
  n += i;
  frame[n++] = 0;
  frame[n++] = dek->algo;
  memcpy (frame + n, dek->key, dek->keylen);
  n += dek->keylen;
  frame[n++] = chksum >> 8;
  frame[n++] = chksum;
  err = gcry_mpi_scan (&a, GCRYMPI_FMT_USG, frame, nframe, &nframe);
  cdk_free (frame);
  if (err)
    return map_gcry_error (err);
  *r_enc = a;
  return 0;
}


/**
 * cdk_dek_decode_pkcs1:
 * @ret_dek: the decoded DEK object
 * @esk: the pkcs#1 encoded session key.
 * 
 * Decode the given multi precision integer in pkcs#1 and
 * store it into the DEK object.
 **/
cdk_error_t
cdk_dek_decode_pkcs1 (cdk_dek_t * ret_dek, gcry_mpi_t esk)
{
  cdk_dek_t dek;
  byte frame[MAX_MPI_BYTES + 2 + 1];
  size_t nframe, n;
  u16 csum, csum2;
  gcry_error_t err;

  if (!ret_dek || !esk)
    return CDK_Inv_Value;

  *ret_dek = NULL;              /* reset */
  nframe = DIM (frame) - 1;
  err = gcry_mpi_print (GCRYMPI_FMT_USG, frame, nframe, &nframe, esk);
  if (err)
    return map_gcry_error (err);
  dek = cdk_salloc (sizeof *dek, 1);
  if (!dek)
    return CDK_Out_Of_Core;

  /* Now get the DEK (data encryption key) from the frame
   *
   *     0  2  RND(n bytes)  0  A  DEK(k bytes)  CSUM(2 bytes)
   *
   * (gcry_mpi_print already removed the leading zero).
   *
   * RND are non-zero randow bytes.
   * A   is the cipher algorithm
   * DEK is the encryption key (session key) with length k
   * CSUM
   */
  n = 0;
  if (frame[n] != 2)
    {
      cdk_free (dek);
      return CDK_Inv_Mode;
    }
  for (n++; n < nframe && frame[n]; n++)
    ;
  n++;
  dek->keylen = nframe - (n + 1) - 2;
  dek->algo = frame[n++];
  if (dek->keylen != gcry_cipher_get_algo_keylen (dek->algo))
    {
      _cdk_log_debug ("pkcs1 decode: invalid cipher keylen %d\n",
                      dek->keylen);
      cdk_free (dek);
      return CDK_Inv_Algo;
    }
  csum = frame[nframe - 2] << 8;
  csum |= frame[nframe - 1];
  memcpy (dek->key, frame + n, dek->keylen);
  csum2 = 0;
  for (n = 0; n < dek->keylen; n++)
    csum2 += dek->key[n];
  if (csum != csum2)
    {
      _cdk_log_debug ("pkcs decode: checksum does not match\n");
      cdk_free (dek);
      return CDK_Chksum_Error;
    }
  *ret_dek = dek;
  return 0;
}


/* Encode the given digest into a pkcs#1 compatible format. */
cdk_error_t
_cdk_digest_encode_pkcs1 (byte ** r_md, size_t * r_mdlen, int pk_algo,
                          const byte * md, int digest_algo, unsigned nbits)
{
  gcry_error_t err;
  size_t dlen;

  if (!md || !r_md || !r_mdlen)
    return CDK_Inv_Value;

  dlen = gcry_md_get_algo_dlen (digest_algo);
  if (!dlen)
    return CDK_Inv_Algo;
  if (is_DSA (pk_algo))         /* DSS does not use a special encoding. */
    {
      *r_md = cdk_malloc (dlen + 1);
      if (!*r_md)
        return CDK_Out_Of_Core;
      *r_mdlen = dlen;
      memcpy (*r_md, md, dlen);
      return 0;
    }
  else
    {
      byte *asn;
      size_t asnlen;
      cdk_error_t rc;

      err = gcry_md_get_asnoid (digest_algo, NULL, &asnlen);
      if (err)
        return map_gcry_error (err);
      asn = cdk_malloc (asnlen + 1);
      if (!asn)
        return CDK_Out_Of_Core;
      err = gcry_md_get_asnoid (digest_algo, asn, &asnlen);
      if (err)
        {
          cdk_free (asn);
          return map_gcry_error (err);
        }
      rc = do_encode_md (r_md, r_mdlen, md, digest_algo, dlen,
                         nbits, asn, asnlen);
      cdk_free (asn);
      return rc;
    }
  return 0;
}


/* FIXME: The prompt should be provided in a more generic way.
   Like: (keyid, algorithm, [user-id]) */
static char *
passphrase_prompt (cdk_pkt_seckey_t sk)
{
  u32 keyid = cdk_pk_get_keyid (sk->pk, NULL);
  int bits = cdk_pk_get_nbits (sk->pk), pk_algo = sk->pubkey_algo;
  const char *algo = "???", *fmt;
  char *p;

  if (is_RSA (pk_algo))
    algo = "RSA";
  else if (is_ELG (pk_algo))
    algo = "ELG";
  else if (is_DSA (pk_algo))
    algo = "DSA";

  fmt = "%d-bit %s key, ID %08lX\nEnter Passphrase: ";
  p = cdk_calloc (1, 64 + strlen (fmt) + strlen (algo) + 1);
  if (!p)
    return NULL;
  sprintf (p, fmt, bits, algo, keyid);
  return p;
}


/* Try to unprotect the secret key, if needed, automatically.
   The passphrase callback is used to get the passphrase directly
   from the user. */
cdk_error_t
_cdk_sk_unprotect_auto (cdk_ctx_t hd, cdk_pkt_seckey_t sk)
{
  char *pw, *p;
  cdk_error_t rc;

  if (!sk->is_protected)
    return 0;

  p = passphrase_prompt (sk);
  pw = _cdk_passphrase_get (hd, p);
  cdk_free (p);
  if (!pw)
    return CDK_No_Passphrase;

  rc = cdk_sk_unprotect (sk, pw);

  wipemem (pw, strlen (pw));
  cdk_free (pw);
  return rc;
}


/**
 * cdk_dek_extract:
 * @ret_dek: the raw DEK object
 * @hd: the session handle
 * @enc: the public key encrypted packet
 * @sk: the secret key.
 * 
 * Try to extract the DEK from the public key encrypted packet. 
 **/
cdk_error_t
cdk_dek_extract (cdk_dek_t * ret_dek, cdk_ctx_t hd,
                 cdk_pkt_pubkey_enc_t enc, cdk_pkt_seckey_t sk)
{
  gcry_mpi_t skey = NULL;
  cdk_dek_t dek;
  cdk_error_t rc;

  if (!enc || !sk || !ret_dek)
    return CDK_Inv_Value;

  /* FIXME: it is not very elegant that we need the session handle here. */
  if (sk->is_protected)
    {
      rc = _cdk_sk_unprotect_auto (hd, sk);
      if (rc)
        return rc;
    }

  rc = cdk_pk_decrypt (sk, enc, &skey);
  if (rc)
    return rc;

  rc = cdk_dek_decode_pkcs1 (&dek, skey);
  gcry_mpi_release (skey);
  if (rc)
    {
      cdk_dek_free (dek);
      dek = NULL;
    }
  *ret_dek = dek;
  return rc;
}


/**
 * cdk_dek_new:
 * @r_dek: the new DEK object
 * 
 * Create a new DEK object.
 **/
cdk_error_t
cdk_dek_new (cdk_dek_t * r_dek)
{
  cdk_dek_t dek;

  if (!r_dek)
    return CDK_Inv_Value;
  *r_dek = NULL;
  dek = cdk_salloc (sizeof *dek, 1);
  if (!dek)
    return CDK_Out_Of_Core;
  *r_dek = dek;
  return 0;
}


/**
 * cdk_dek_set_cipher:
 * @dek: the DEK object
 * @algo: the cipher algorithm to use
 * 
 * Set the cipher for the given DEK object.
 **/
cdk_error_t
cdk_dek_set_cipher (cdk_dek_t dek, int algo)
{
  if (!dek)
    return CDK_Inv_Value;

  if (!algo)
    algo = GCRY_CIPHER_AES128;
  if (gcry_cipher_test_algo (algo))
    return CDK_Inv_Algo;
  dek->algo = algo;
  dek->keylen = gcry_cipher_get_algo_keylen (dek->algo);
  return 0;
}

cdk_error_t
cdk_dek_get_cipher (cdk_dek_t dek, int *r_algo)
{
  if (!dek || !r_algo)
    return CDK_Inv_Value;


  *r_algo = dek->algo;
  return 0;
}


/**
 * cdk_dek_set_key:
 * @dek: the DEK object
 * @key: the random session key
 * @keylen: the length of the session key.
 * 
 * Set the random session key for the given DEK object.
 * If @key and @keylen is NULL (0) a random key will be generated.
 * In any case, cdk_dek_set_cipher must be called first. 
 **/
cdk_error_t
cdk_dek_set_key (cdk_dek_t dek, const byte * key, size_t keylen)
{
  gcry_cipher_hd_t hd;
  size_t i;

  if (!dek)
    return CDK_Inv_Value;

  /* The given key must be compatible with the symmetric
     cipher algorithm set before. */
  if (keylen > 0 && keylen != dek->keylen)
    return CDK_Inv_Mode;

  if (!key && !keylen)
    {
      gcry_error_t err;

      /* Used to generate a random session key. The extra code is used
         to detect weak keys, if they are possible at all. */
      err = gcry_cipher_open (&hd, dek->algo, GCRY_CIPHER_MODE_CFB,
                              GCRY_CIPHER_ENABLE_SYNC);
      if (err)
        return map_gcry_error (err);
      gcry_randomize (dek->key, dek->keylen, GCRY_STRONG_RANDOM);
      for (i = 0; i < 8; i++)
        {
          if (!gcry_cipher_setkey (hd, dek->key, dek->keylen))
            {
              gcry_cipher_close (hd);
              return 0;
            }
          gcry_randomize (dek->key, dek->keylen, GCRY_STRONG_RANDOM);
        }
      gcry_cipher_close (hd);
      return CDK_Weak_Key;
    }

  memcpy (dek->key, key, dek->keylen);
  return 0;
}


/**
 * cdk_dek_set_mdc_flag:
 * @dek: the DEK object
 * @val: value to enable or disable the use
 * 
 * Enable or disable the MDC flag for the given DEK object.
 **/
void
cdk_dek_set_mdc_flag (cdk_dek_t dek, int val)
{
  if (dek)
    dek->use_mdc = val;
}


int
cdk_dek_get_mdc_flag (cdk_dek_t dek)
{
  if (!dek)
    return 0;
  return dek->use_mdc;
}


/**
 * cdk_dek_free:
 * @dek: the DEK object
 * 
 * Release the DEK object.
 **/
void
cdk_dek_free (cdk_dek_t dek)
{
  if (!dek)
    return;

  /* Make sure sentensive data is overwritten. */
  wipemem (dek->key, sizeof (dek->key));
  cdk_free (dek);
}


/* Hash the passphrase to produce the a DEK.
   If create is set, a random salt will be generated. */
static cdk_error_t
hash_passphrase (cdk_dek_t dek, const char *pw, cdk_s2k_t s2k, int create)
{
  gcry_md_hd_t md;
  byte zero[1] = { 0x00 };
  int pass, i;
  int used = 0, pwlen;
  gcry_error_t err;

  if (!dek || !pw || !s2k)
    return CDK_Inv_Value;

  if (!s2k->hash_algo)
    s2k->hash_algo = GCRY_MD_SHA1;
  pwlen = strlen (pw);

  dek->keylen = gcry_cipher_get_algo_keylen (dek->algo);
  err = gcry_md_open (&md, s2k->hash_algo, 0);
  if (err)
    return map_gcry_error (err);

  for (pass = 0; used < dek->keylen; pass++)
    {
      if (pass)
        {
          gcry_md_reset (md);
          for (i = 0; i < pass; i++)    /* preset the hash context */
            gcry_md_write (md, zero, 1);
        }
      if (s2k->mode == CDK_S2K_SALTED || s2k->mode == CDK_S2K_ITERSALTED)
        {
          int len2 = pwlen + 8;
          u32 count = len2;
          if (create && !pass)
            {
              gcry_randomize (s2k->salt, 8, GCRY_STRONG_RANDOM);
              if (s2k->mode == 3)
                s2k->count = 96;        /* 65536 iterations */
            }
          if (s2k->mode == 3)
            {
              count = (16ul + (s2k->count & 15)) << ((s2k->count >> 4) + 6);
              if (count < len2)
                count = len2;
            }
          /* a little bit complicated because we need a ulong for count */
          while (count > len2)
            {                   /* maybe iterated+salted */
              gcry_md_write (md, s2k->salt, 8);
              gcry_md_write (md, pw, pwlen);
              count -= len2;
            }
          if (count < 8)
            gcry_md_write (md, s2k->salt, count);
          else
            {
              gcry_md_write (md, s2k->salt, 8);
              count -= 8;
              gcry_md_write (md, pw, count);
            }
        }
      else
        gcry_md_write (md, pw, pwlen);
      gcry_md_final (md);
      i = gcry_md_get_algo_dlen (s2k->hash_algo);
      if (i > dek->keylen - used)
        i = dek->keylen - used;
      memcpy (dek->key + used, gcry_md_read (md, s2k->hash_algo), i);
      used += i;
    }
  gcry_md_close (md);
  return 0;
}


/**
 * cdk_dek_from_passphrase:
 * @ret_dek: the new DEK.
 * @cipher_algo: symmetric key algorithm to use
 * @s2k: the S2K to use
 * @rndsalt: 1=create random salt
 * @pw: the passphrase.
 * 
 * Transform a passphrase into a DEK object.
 */
cdk_error_t
cdk_dek_from_passphrase (cdk_dek_t * ret_dek, int cipher_algo, cdk_s2k_t s2k,
                         int rndsalt, const char *pw)
{
  cdk_dek_t dek;
  cdk_error_t rc;

  if (!ret_dek)
    return CDK_Inv_Value;

  *ret_dek = NULL;
  rc = cdk_dek_new (&dek);
  if (rc)
    return rc;
  rc = cdk_dek_set_cipher (dek, cipher_algo);
  if (!rc)
    rc = hash_passphrase (dek, pw, s2k, rndsalt);
  if (rc)
    {
      cdk_dek_free (dek);
      return rc;
    }

  *ret_dek = dek;
  return 0;
}


/**
 * cdk_s2k_new:
 * @ret_s2k: output for the new S2K object
 * @mode: the S2K mode (simple, salted, iter+salted)
 * @digest_algo: the hash algorithm
 * @salt: random salt
 * 
 * Create a new S2K object with the given parameter.
 * The @salt parameter must be always 8 octets.
 **/
cdk_error_t
cdk_s2k_new (cdk_s2k_t * ret_s2k, int mode, int digest_algo,
             const byte * salt)
{
  cdk_s2k_t s2k;

  if (!ret_s2k)
    return CDK_Inv_Value;

  if (mode != 0x00 && mode != 0x01 && mode != 0x03)
    return CDK_Inv_Mode;

  if (gcry_md_test_algo (digest_algo))
    return CDK_Inv_Algo;

  s2k = cdk_calloc (1, sizeof *s2k);
  if (!s2k)
    return CDK_Out_Of_Core;
  s2k->mode = mode;
  s2k->hash_algo = digest_algo;
  if (salt)
    memcpy (s2k->salt, salt, 8);
  *ret_s2k = s2k;
  return 0;
}


/**
 * cdk_s2k_free:
 * @s2k: the S2K object
 * 
 * Release the given S2K object.
 **/
void
cdk_s2k_free (cdk_s2k_t s2k)
{
  cdk_free (s2k);
}


/* Make a copy of the source s2k into R_DST. */
cdk_error_t
_cdk_s2k_copy (cdk_s2k_t * r_dst, cdk_s2k_t src)
{
  cdk_s2k_t dst;
  cdk_error_t err;

  err = cdk_s2k_new (&dst, src->mode, src->hash_algo, src->salt);
  if (err)
    return err;
  dst->count = src->count;
  *r_dst = dst;

  return 0;
}
