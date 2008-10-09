/* gc-gnulib.c --- Common gnulib internal crypto interface functions
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007  Simon Josefsson
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1, or (at your
 * option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/* Note: This file is only built if GC uses internal functions. */

#include "MHD_config.h"

/* Get prototype. */
#include "gc.h"

#include <stdlib.h>
#include <string.h>

/* For randomize. */
#ifdef GNULIB_GC_RANDOM
# include <unistd.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <errno.h>
#endif

/* Hashes. */
#ifdef GNULIB_GC_MD5
# include "md5.h"
#endif
#ifdef GNULIB_GC_SHA1
# include "sha1.h"
#endif
#if defined(GNULIB_GC_HMAC_MD5) || defined(GNULIB_GC_HMAC_SHA1)
# include "hmac.h"
#endif

/* Ciphers. */
#ifdef GNULIB_GC_ARCFOUR
# include "arcfour.h"
#endif
#ifdef GNULIB_GC_ARCTWO
# include "arctwo.h"
#endif
#ifdef GNULIB_GC_DES
# include "des.h"
#endif
#ifdef GNULIB_GC_RIJNDAEL
# include "rijndael-api-fst.h"
#endif

/* The results of open() in this file are not used with fchdir,
 therefore save some unnecessary work in fchdir.c.  */
#undef open
#undef close

Gc_rc
MHD_gc_init (void)
{
  return GC_OK;
}

void
MHD_gc_done (void)
{
  return;
}

#ifdef GNULIB_GC_RANDOM

/* Randomness. */

static Gc_rc
randomize (int level, char *data, size_t datalen)
{
  int fd;
  const char *device;
  size_t len = 0;
  int rc;

  switch (level)
    {
    case 0:
      device = NAME_OF_NONCE_DEVICE;
      break;

    case 1:
      device = NAME_OF_PSEUDO_RANDOM_DEVICE;
      break;

    default:
      device = NAME_OF_RANDOM_DEVICE;
      break;
    }

  if (strcmp (device, "no") == 0)
    return GC_RANDOM_ERROR;

  fd = open (device, O_RDONLY);
  if (fd < 0)
    return GC_RANDOM_ERROR;

  do
    {
      ssize_t tmp;

      tmp = read (fd, data, datalen);

      if (tmp < 0)
        {
          int save_errno = errno;
          close (fd);
          errno = save_errno;
          return GC_RANDOM_ERROR;
        }

      len += tmp;
    }
  while (len < datalen);

  rc = close (fd);
  if (rc < 0)
    return GC_RANDOM_ERROR;

  return GC_OK;
}

Gc_rc
MHD_gc_nonce (char *data, size_t datalen)
{
  return randomize (0, data, datalen);
}

Gc_rc
MHD_gc_pseudo_random (char *data, size_t datalen)
{
  return randomize (1, data, datalen);
}

Gc_rc
MHD_gc_random (char *data, size_t datalen)
{
  return randomize (2, data, datalen);
}

#endif

/* Memory allocation. */
void
MHD_gc_set_allocators (MHD_gc_malloc_t func_malloc,
                   MHD_gc_malloc_t secure_malloc,
                   MHD_gc_secure_check_t secure_check,
                   MHD_gc_realloc_t func_realloc, MHD_gc_free_t func_free)
{
  return;
}

/* Ciphers. */

typedef struct _MHD_gc_cipher_ctx
{
  Gc_cipher alg;
  Gc_cipher_mode mode;
#ifdef GNULIB_GC_ARCTWO
  arctwo_context arctwoContext;
  char arctwoIV[ARCTWO_BLOCK_SIZE];
#endif
#ifdef GNULIB_GC_ARCFOUR
  arcfour_context arcfourContext;
#endif
#ifdef GNULIB_GC_DES
  MHD_gl_des_ctx desContext;
#endif
#ifdef GNULIB_GC_RIJNDAEL
  rijndaelKeyInstance aesEncKey;
  rijndaelKeyInstance aesDecKey;
  rijndaelCipherInstance aesContext;
#endif
} _MHD_gc_cipher_ctx;

Gc_rc
MHD_gc_cipher_open (Gc_cipher alg,
                Gc_cipher_mode mode, MHD_gc_cipher_handle * outhandle)
{
  _MHD_gc_cipher_ctx *ctx;
  Gc_rc rc = GC_OK;

  ctx = calloc (sizeof (*ctx), 1);
  if (!ctx)
    return GC_MALLOC_ERROR;

  ctx->alg = alg;
  ctx->mode = mode;

  switch (alg)
    {
#ifdef GNULIB_GC_ARCTWO
    case GC_ARCTWO40:
      switch (mode)
        {
        case GC_ECB:
        case GC_CBC:
          break;

        default:
          rc = GC_INVALID_CIPHER;
        }
      break;
#endif

#ifdef GNULIB_GC_ARCFOUR
    case GC_ARCFOUR128:
    case GC_ARCFOUR40:
      switch (mode)
        {
        case GC_STREAM:
          break;

        default:
          rc = GC_INVALID_CIPHER;
        }
      break;
#endif

#ifdef GNULIB_GC_DES
    case GC_DES:
      switch (mode)
        {
        case GC_ECB:
          break;

        default:
          rc = GC_INVALID_CIPHER;
        }
      break;
#endif

#ifdef GNULIB_GC_RIJNDAEL
    case GC_AES128:
    case GC_AES192:
    case GC_AES256:
      switch (mode)
        {
        case GC_ECB:
        case GC_CBC:
          break;

        default:
          rc = GC_INVALID_CIPHER;
        }
      break;
#endif

    default:
      rc = GC_INVALID_CIPHER;
    }

  if (rc == GC_OK)
    *outhandle = ctx;
  else
    free (ctx);

  return rc;
}

Gc_rc
MHD_gc_cipher_setkey (MHD_gc_cipher_handle handle, size_t keylen, const char *key)
{
  _MHD_gc_cipher_ctx *ctx = handle;

  switch (ctx->alg)
    {
#ifdef GNULIB_GC_ARCTWO
    case GC_ARCTWO40:
      arctwo_setkey (&ctx->arctwoContext, keylen, key);
      break;
#endif

#ifdef GNULIB_GC_ARCFOUR
    case GC_ARCFOUR128:
    case GC_ARCFOUR40:
      arcfour_setkey (&ctx->arcfourContext, key, keylen);
      break;
#endif

#ifdef GNULIB_GC_DES
    case GC_DES:
      if (keylen != 8)
        return GC_INVALID_CIPHER;
      MHD_gl_des_setkey (&ctx->desContext, key);
      break;
#endif

#ifdef GNULIB_GC_RIJNDAEL
    case GC_AES128:
    case GC_AES192:
    case GC_AES256:
      {
        rijndael_rc rc;
        size_t i;
        char keyMaterial[RIJNDAEL_MAX_KEY_SIZE + 1];

        for (i = 0; i < keylen; i++)
          sprintf (&keyMaterial[2 * i], "%02x", key[i] & 0xFF);

        rc = MHD_rijndaelMakeKey (&ctx->aesEncKey, RIJNDAEL_DIR_ENCRYPT,
                              keylen * 8, keyMaterial);
        if (rc < 0)
          return GC_INVALID_CIPHER;

        rc = MHD_rijndaelMakeKey (&ctx->aesDecKey, RIJNDAEL_DIR_DECRYPT,
                              keylen * 8, keyMaterial);
        if (rc < 0)
          return GC_INVALID_CIPHER;

        rc = MHD_MHD_rijndaelCipherInit (&ctx->aesContext, RIJNDAEL_MODE_ECB, NULL);
        if (rc < 0)
          return GC_INVALID_CIPHER;
      }
      break;
#endif

    default:
      return GC_INVALID_CIPHER;
    }

  return GC_OK;
}

Gc_rc
MHD_gc_cipher_setiv (MHD_gc_cipher_handle handle, size_t ivlen, const char *iv)
{
  _MHD_gc_cipher_ctx *ctx = handle;

  switch (ctx->alg)
    {
#ifdef GNULIB_GC_ARCTWO
    case GC_ARCTWO40:
      if (ivlen != ARCTWO_BLOCK_SIZE)
        return GC_INVALID_CIPHER;
      memcpy (ctx->arctwoIV, iv, ivlen);
      break;
#endif

#ifdef GNULIB_GC_RIJNDAEL
    case GC_AES128:
    case GC_AES192:
    case GC_AES256:
      switch (ctx->mode)
        {
        case GC_ECB:
          /* Doesn't use IV. */
          break;

        case GC_CBC:
          {
            rijndael_rc rc;
            size_t i;
            char ivMaterial[2 * RIJNDAEL_MAX_IV_SIZE + 1];

            for (i = 0; i < ivlen; i++)
              sprintf (&ivMaterial[2 * i], "%02x", iv[i] & 0xFF);

            rc = MHD_MHD_rijndaelCipherInit (&ctx->aesContext, RIJNDAEL_MODE_CBC,
                                     ivMaterial);
            if (rc < 0)
              return GC_INVALID_CIPHER;
          }
          break;

        default:
          return GC_INVALID_CIPHER;
        }
      break;
#endif

    default:
      return GC_INVALID_CIPHER;
    }

  return GC_OK;
}

Gc_rc
MHD_gc_cipher_encrypt_inline (MHD_gc_cipher_handle handle, size_t len, char *data)
{
  _MHD_gc_cipher_ctx *ctx = handle;

  switch (ctx->alg)
    {
#ifdef GNULIB_GC_ARCTWO
    case GC_ARCTWO40:
      switch (ctx->mode)
        {
        case GC_ECB:
          arctwo_encrypt (&ctx->arctwoContext, data, data, len);
          break;

        case GC_CBC:
          for (; len >= ARCTWO_BLOCK_SIZE; len -= ARCTWO_BLOCK_SIZE,
               data += ARCTWO_BLOCK_SIZE)
            {
              size_t i;
              for (i = 0; i < ARCTWO_BLOCK_SIZE; i++)
                data[i] ^= ctx->arctwoIV[i];
              arctwo_encrypt (&ctx->arctwoContext, data, data,
                              ARCTWO_BLOCK_SIZE);
              memcpy (ctx->arctwoIV, data, ARCTWO_BLOCK_SIZE);
            }
          break;

        default:
          return GC_INVALID_CIPHER;
        }
      break;
#endif

#ifdef GNULIB_GC_ARCFOUR
    case GC_ARCFOUR128:
    case GC_ARCFOUR40:
      arcfour_stream (&ctx->arcfourContext, data, data, len);
      break;
#endif

#ifdef GNULIB_GC_DES
    case GC_DES:
      for (; len >= 8; len -= 8, data += 8)
        MHD_gl_des_ecb_encrypt (&ctx->desContext, data, data);
      break;
#endif

#ifdef GNULIB_GC_RIJNDAEL
    case GC_AES128:
    case GC_AES192:
    case GC_AES256:
      {
        int nblocks;

        nblocks = MHD_rijndaelBlockEncrypt (&ctx->aesContext, &ctx->aesEncKey,
                                        data, 8 * len, data);
        if (nblocks < 0)
          return GC_INVALID_CIPHER;
      }
      break;
#endif

    default:
      return GC_INVALID_CIPHER;
    }

  return GC_OK;
}

Gc_rc
MHD_gc_cipher_decrypt_inline (MHD_gc_cipher_handle handle, size_t len, char *data)
{
  _MHD_gc_cipher_ctx *ctx = handle;

  switch (ctx->alg)
    {
#ifdef GNULIB_GC_ARCTWO
    case GC_ARCTWO40:
      switch (ctx->mode)
        {
        case GC_ECB:
          arctwo_decrypt (&ctx->arctwoContext, data, data, len);
          break;

        case GC_CBC:
          for (; len >= ARCTWO_BLOCK_SIZE; len -= ARCTWO_BLOCK_SIZE,
               data += ARCTWO_BLOCK_SIZE)
            {
              char tmpIV[ARCTWO_BLOCK_SIZE];
              size_t i;
              memcpy (tmpIV, data, ARCTWO_BLOCK_SIZE);
              arctwo_decrypt (&ctx->arctwoContext, data, data,
                              ARCTWO_BLOCK_SIZE);
              for (i = 0; i < ARCTWO_BLOCK_SIZE; i++)
                data[i] ^= ctx->arctwoIV[i];
              memcpy (ctx->arctwoIV, tmpIV, ARCTWO_BLOCK_SIZE);
            }
          break;

        default:
          return GC_INVALID_CIPHER;
        }
      break;
#endif

#ifdef GNULIB_GC_ARCFOUR
    case GC_ARCFOUR128:
    case GC_ARCFOUR40:
      arcfour_stream (&ctx->arcfourContext, data, data, len);
      break;
#endif

#ifdef GNULIB_GC_DES
    case GC_DES:
      for (; len >= 8; len -= 8, data += 8)
        MHD_gl_des_ecb_decrypt (&ctx->desContext, data, data);
      break;
#endif

#ifdef GNULIB_GC_RIJNDAEL
    case GC_AES128:
    case GC_AES192:
    case GC_AES256:
      {
        int nblocks;

        nblocks = MHD_rijndaelBlockDecrypt (&ctx->aesContext, &ctx->aesDecKey,
                                        data, 8 * len, data);
        if (nblocks < 0)
          return GC_INVALID_CIPHER;
      }
      break;
#endif

    default:
      return GC_INVALID_CIPHER;
    }

  return GC_OK;
}

Gc_rc
MHD_gc_cipher_close (MHD_gc_cipher_handle handle)
{
  _MHD_gc_cipher_ctx *ctx = handle;

  if (ctx)
    free (ctx);

  return GC_OK;
}

/* Hashes. */

#define MAX_DIGEST_SIZE 20

typedef struct _MHD_gc_hash_ctx
{
  Gc_hash alg;
  Gc_hash_mode mode;
  char hash[MAX_DIGEST_SIZE];
#ifdef GNULIB_GC_MD5
  struct MHD_md5_ctx md5Context;
#endif
#ifdef GNULIB_GC_SHA1
  struct MHD_sha1_ctx sha1Context;
#endif
} _MHD_gc_hash_ctx;

Gc_rc
MHD_gc_hash_open (Gc_hash hash, Gc_hash_mode mode, MHD_gc_hash_handle * outhandle)
{
  _MHD_gc_hash_ctx *ctx;
  Gc_rc rc = GC_OK;

  ctx = calloc (sizeof (*ctx), 1);
  if (!ctx)
    return GC_MALLOC_ERROR;

  ctx->alg = hash;
  ctx->mode = mode;

  switch (hash)
    {
#ifdef GNULIB_GC_MD5
    case GC_MD5:
      MHD_md5_init_ctx (&ctx->md5Context);
      break;
#endif

#ifdef GNULIB_GC_SHA1
    case GC_SHA1:
      MHD_sha1_init_ctx (&ctx->sha1Context);
      break;
#endif

    default:
      rc = GC_INVALID_HASH;
      break;
    }

  switch (mode)
    {
    case 0:
      break;

    default:
      rc = GC_INVALID_HASH;
      break;
    }

  if (rc == GC_OK)
    *outhandle = ctx;
  else
    free (ctx);

  return rc;
}

Gc_rc
MHD_gc_hash_clone (MHD_gc_hash_handle handle, MHD_gc_hash_handle * outhandle)
{
  _MHD_gc_hash_ctx *in = handle;
  _MHD_gc_hash_ctx *out;

  *outhandle = out = calloc (sizeof (*out), 1);
  if (!out)
    return GC_MALLOC_ERROR;

  memcpy (out, in, sizeof (*out));

  return GC_OK;
}

size_t
MHD_gc_hash_digest_length (Gc_hash hash)
{
  size_t len;

  switch (hash)
    {
    case GC_MD2:
      len = GC_MD2_DIGEST_SIZE;
      break;

    case GC_MD4:
      len = GC_MD4_DIGEST_SIZE;
      break;

    case GC_MD5:
      len = GC_MD5_DIGEST_SIZE;
      break;

    case GC_RMD160:
      len = GC_RMD160_DIGEST_SIZE;
      break;

    case GC_SHA1:
      len = GC_SHA1_DIGEST_SIZE;
      break;

    default:
      return 0;
    }

  return len;
}

void
MHD_gc_hash_write (MHD_gc_hash_handle handle, size_t len, const char *data)
{
  _MHD_gc_hash_ctx *ctx = handle;

  switch (ctx->alg)
    {
#ifdef GNULIB_GC_MD5
    case GC_MD5:
      MHD_md5_process_bytes (data, len, &ctx->md5Context);
      break;
#endif

#ifdef GNULIB_GC_SHA1
    case GC_SHA1:
      MHD_sha1_process_bytes (data, len, &ctx->sha1Context);
      break;
#endif

    default:
      break;
    }
}

const char *
MHD_gc_hash_read (MHD_gc_hash_handle handle)
{
  _MHD_gc_hash_ctx *ctx = handle;
  const char *ret = NULL;

  switch (ctx->alg)
    {
#ifdef GNULIB_GC_MD5
    case GC_MD5:
      MHD_md5_finish_ctx (&ctx->md5Context, ctx->hash);
      ret = ctx->hash;
      break;
#endif

#ifdef GNULIB_GC_SHA1
    case GC_SHA1:
      MHD_sha1_finish_ctx (&ctx->sha1Context, ctx->hash);
      ret = ctx->hash;
      break;
#endif

    default:
      return NULL;
    }

  return ret;
}

void
MHD_gc_hash_close (MHD_gc_hash_handle handle)
{
  _MHD_gc_hash_ctx *ctx = handle;

  free (ctx);
}

Gc_rc
MHD_gc_hash_buffer (Gc_hash hash, const void *in, size_t inlen, char *resbuf)
{
  switch (hash)
    {
#ifdef GNULIB_GC_MD5
    case GC_MD5:
      MHD_md5_buffer (in, inlen, resbuf);
      break;
#endif

#ifdef GNULIB_GC_SHA1
    case GC_SHA1:
      MHD_sha1_buffer (in, inlen, resbuf);
      break;
#endif

    default:
      return GC_INVALID_HASH;
    }

  return GC_OK;
}

#ifdef GNULIB_GC_MD5
Gc_rc
MHD_gc_md5 (const void *in, size_t inlen, void *resbuf)
{
  MHD_md5_buffer (in, inlen, resbuf);
  return GC_OK;
}
#endif

#ifdef GNULIB_GC_SHA1
Gc_rc
MHD_gc_sha1 (const void *in, size_t inlen, void *resbuf)
{
  MHD_sha1_buffer (in, inlen, resbuf);
  return GC_OK;
}
#endif

#ifdef GNULIB_GC_HMAC_MD5
Gc_rc
MHD_gc_MHD_hmac_md5 (const void *key, size_t keylen,
             const void *in, size_t inlen, char *resbuf)
{
  MHD_hmac_md5 (key, keylen, in, inlen, resbuf);
  return GC_OK;
}
#endif

#ifdef GNULIB_GC_HMAC_SHA1
Gc_rc
MHD_gc_MHD_hmac_sha1 (const void *key,
              size_t keylen, const void *in, size_t inlen, char *resbuf)
{
  MHD_hmac_sha1 (key, keylen, in, inlen, resbuf);
  return GC_OK;
}
#endif
