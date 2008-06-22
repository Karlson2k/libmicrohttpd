/*
 * Copyright (C) 2000, 2002, 2003, 2004, 2005, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_compress.h>
#include <gnutls_algorithms.h>
#include "gnutls_errors.h"

/* The flag d is the direction (compress, decompress). Non zero is
 * decompress.
 */
comp_hd_t
_gnutls_comp_init (gnutls_compression_method_t method, int d)
{
  comp_hd_t ret;
  int err;

  ret = gnutls_malloc (sizeof (struct comp_hd_t_STRUCT));
  if (ret == NULL)
    {
      gnutls_assert ();
      return NULL;
    }

  ret->algo = method;
  ret->handle = NULL;

  switch (method)
    {
#ifdef HAVE_LIBZ
    case GNUTLS_COMP_DEFLATE:
      {
        int window_bits, mem_level;
        int comp_level;
        z_stream *zhandle;

        window_bits = _gnutls_compression_get_wbits (method);
        mem_level = _gnutls_compression_get_mem_level (method);
        comp_level = _gnutls_compression_get_comp_level (method);

        ret->handle = gnutls_malloc (sizeof (z_stream));
        if (ret->handle == NULL)
          {
            gnutls_assert ();
            goto cleanup_ret;
          }

        zhandle = ret->handle;

        zhandle->zalloc = (alloc_func) 0;
        zhandle->zfree = (free_func) 0;
        zhandle->opaque = (voidpf) 0;

        if (d)
          err = inflateInit2 (zhandle, window_bits);
        else
          {
            err = deflateInit2 (zhandle,
                                comp_level, Z_DEFLATED,
                                window_bits, mem_level, Z_DEFAULT_STRATEGY);
          }
        if (err != Z_OK)
          {
            gnutls_assert ();
            gnutls_free (ret->handle);
            goto cleanup_ret;
          }
        break;
      }
#endif
    case GNUTLS_COMP_NULL:
      break;
    }
  return ret;

cleanup_ret:
  gnutls_free (ret);
  return NULL;
}

/* The flag d is the direction (compress, decompress). Non zero is
 * decompress.
 */
void
_gnutls_comp_deinit (comp_hd_t handle, int d)
{
  int err;

  if (handle != NULL)
    {
      switch (handle->algo)
        {
#ifdef HAVE_LIBZ
        case GNUTLS_COMP_DEFLATE:
          if (d)
            err = inflateEnd (handle->handle);
          else
            err = deflateEnd (handle->handle);
          break;
#endif
        default:
          break;
        }
      gnutls_free (handle->handle);
      gnutls_free (handle);

    }
}

/* These functions are memory consuming 
 */

int
_gnutls_compress (comp_hd_t handle, const opaque * plain,
                  size_t plain_size, opaque ** compressed,
                  size_t max_comp_size)
{
  int compressed_size = GNUTLS_E_COMPRESSION_FAILED;
  int err;

  /* NULL compression is not handled here
   */
  if (handle == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  switch (handle->algo)
    {

#ifdef HAVE_LIBZ
    case GNUTLS_COMP_DEFLATE:
      {
        uLongf size;
        z_stream *zhandle;

        size = (plain_size + plain_size) + 10;
        *compressed = gnutls_malloc (size);
        if (*compressed == NULL)
          {
            gnutls_assert ();
            return GNUTLS_E_MEMORY_ERROR;
          }

        zhandle = handle->handle;

        zhandle->next_in = (Bytef *) plain;
        zhandle->avail_in = plain_size;
        zhandle->next_out = (Bytef *) * compressed;
        zhandle->avail_out = size;

        err = deflate (zhandle, Z_SYNC_FLUSH);

        if (err != Z_OK || zhandle->avail_in != 0)
          {
            gnutls_assert ();
            gnutls_free (*compressed);
            *compressed = NULL;
            return GNUTLS_E_COMPRESSION_FAILED;
          }

        compressed_size = size - zhandle->avail_out;
        break;
      }
#endif
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }                           /* switch */

#ifdef COMPRESSION_DEBUG
  _gnutls_debug_log ("Compression ratio: %f\n",
                     (float) ((float) compressed_size / (float) plain_size));
#endif

  if ((size_t) compressed_size > max_comp_size)
    {
      gnutls_free (*compressed);
      *compressed = NULL;
      return GNUTLS_E_COMPRESSION_FAILED;
    }

  return compressed_size;
}



int
_gnutls_decompress (comp_hd_t handle, opaque * compressed,
                    size_t compressed_size, opaque ** plain,
                    size_t max_record_size)
{
  int plain_size = GNUTLS_E_DECOMPRESSION_FAILED, err;
  int cur_pos;

  if (compressed_size > max_record_size + EXTRA_COMP_SIZE)
    {
      gnutls_assert ();
      return GNUTLS_E_DECOMPRESSION_FAILED;
    }

  /* NULL compression is not handled here
   */

  if (handle == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  switch (handle->algo)
    {
#ifdef HAVE_LIBZ
    case GNUTLS_COMP_DEFLATE:
      {
        uLongf out_size;
        z_stream *zhandle;

        *plain = NULL;
        out_size = compressed_size + compressed_size;
        plain_size = 0;

        zhandle = handle->handle;

        zhandle->next_in = (Bytef *) compressed;
        zhandle->avail_in = compressed_size;

        cur_pos = 0;

        do
          {
            out_size += 512;
            *plain = gnutls_realloc_fast (*plain, out_size);
            if (*plain == NULL)
              {
                gnutls_assert ();
                return GNUTLS_E_MEMORY_ERROR;
              }

            zhandle->next_out = (Bytef *) (*plain + cur_pos);
            zhandle->avail_out = out_size - cur_pos;

            err = inflate (zhandle, Z_SYNC_FLUSH);

            cur_pos = out_size - zhandle->avail_out;

          }
        while ((err == Z_BUF_ERROR && zhandle->avail_out == 0
                && out_size < max_record_size)
               || (err == Z_OK && zhandle->avail_in != 0));

        if (err != Z_OK)
          {
            gnutls_assert ();
            gnutls_free (*plain);
            *plain = NULL;
            return GNUTLS_E_DECOMPRESSION_FAILED;
          }

        plain_size = out_size - zhandle->avail_out;
        break;
      }
#endif
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }                           /* switch */

  if ((size_t) plain_size > max_record_size)
    {
      gnutls_assert ();
      gnutls_free (*plain);
      *plain = NULL;
      return GNUTLS_E_DECOMPRESSION_FAILED;
    }

  return plain_size;
}
