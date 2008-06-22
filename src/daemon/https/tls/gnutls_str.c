/*
 * Copyright (C) 2002, 2004, 2005, 2007  Free Software Foundation
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
#include <gnutls_errors.h>
#include <gnutls_num.h>
#include <gnutls_str.h>

/* These function are like strcat, strcpy. They only
 * do bound checking (they shouldn't cause buffer overruns),
 * and they always produce null terminated strings.
 *
 * They should be used only with null terminated strings.
 */
void _gnutls_str_cat(char *dest,
                     size_t dest_tot_size,
                     const char *src)
{
  size_t str_size = strlen(src);
  size_t dest_size = strlen(dest);

  if (dest_tot_size - dest_size > str_size)
    {
      strcat(dest, src);
    }
  else
    {
      if (dest_tot_size - dest_size > 0)
        {
          strncat(dest, src, (dest_tot_size - dest_size) - 1);
          dest[dest_tot_size - 1] = 0;
        }
    }
}

void _gnutls_str_cpy(char *dest,
                     size_t dest_tot_size,
                     const char *src)
{
  size_t str_size = strlen(src);

  if (dest_tot_size > str_size)
    {
      strcpy(dest, src);
    }
  else
    {
      if (dest_tot_size > 0)
        {
          strncpy(dest, src, (dest_tot_size) - 1);
          dest[dest_tot_size - 1] = 0;
        }
    }
}

void _gnutls_mem_cpy(char *dest,
                     size_t dest_tot_size,
                     const char *src,
                     size_t src_size)
{

  if (dest_tot_size >= src_size)
    {
      memcpy(dest, src, src_size);
    }
  else
    {
      if (dest_tot_size > 0)
        {
          memcpy(dest, src, dest_tot_size);
        }
    }
}

void _gnutls_string_init(gnutls_string * str,
                         gnutls_alloc_function alloc_func,
                         gnutls_realloc_function realloc_func,
                         gnutls_free_function free_func)
{
  str->data = NULL;
  str->max_length = 0;
  str->length = 0;

  str->alloc_func = alloc_func;
  str->free_func = free_func;
  str->realloc_func = realloc_func;
}

void _gnutls_string_clear(gnutls_string * str)
{
  if (str == NULL || str->data == NULL)
    return;
  str->free_func(str->data);

  str->data = NULL;
  str->max_length = 0;
  str->length = 0;
}

/* This one does not copy the string.
 */
gnutls_datum_t _gnutls_string2datum(gnutls_string * str)
{
  gnutls_datum_t ret;

  ret.data = str->data;
  ret.size = str->length;

  return ret;
}

#define MIN_CHUNK 256

int _gnutls_string_copy_str(gnutls_string * dest,
                            const char *src)
{
  size_t src_len = strlen(src);
  size_t max;
  if (dest->max_length >= src_len)
    {
      memcpy(dest->data, src, src_len);
      dest->length = src_len;

      return src_len;
    }
  else
    {
      max = (src_len > MIN_CHUNK) ? src_len : MIN_CHUNK;
      dest->data = dest->realloc_func(dest->data, max);
      if (dest->data == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
      dest->max_length = MAX (MIN_CHUNK, src_len);

      memcpy(dest->data, src, src_len);
      dest->length = src_len;

      return src_len;
    }
}

int _gnutls_string_append_str(gnutls_string * dest,
                              const char *src)
{
  size_t src_len = strlen(src);
  size_t tot_len = src_len + dest->length;

  if (dest->max_length >= tot_len)
    {
      memcpy(&dest->data[dest->length], src, src_len);
      dest->length = tot_len;

      return tot_len;
    }
  else
    {
      size_t new_len=
        MAX (src_len, MIN_CHUNK) + MAX (dest->max_length, MIN_CHUNK);

      dest->data = dest->realloc_func(dest->data, new_len);
      if (dest->data == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
      dest->max_length = new_len;

      memcpy(&dest->data[dest->length], src, src_len);
      dest->length = tot_len;

      return tot_len;
    }
}

int _gnutls_string_append_data(gnutls_string * dest,
                               const void *data,
                               size_t data_size)
{
  size_t tot_len = data_size + dest->length;

  if (dest->max_length >= tot_len)
    {
      memcpy(&dest->data[dest->length], data, data_size);
      dest->length = tot_len;

      return tot_len;
    }
  else
    {
      size_t new_len=
        MAX (data_size, MIN_CHUNK) + MAX (dest->max_length, MIN_CHUNK);

      dest->data = dest->realloc_func(dest->data, new_len);
      if (dest->data == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
      dest->max_length = new_len;

      memcpy(&dest->data[dest->length], data, data_size);
      dest->length = tot_len;

      return tot_len;
    }
}

int _gnutls_string_append_printf(gnutls_string * dest,
                                 const char *fmt,
                                 ...)
{
  va_list args;
  int len;
  char *str;

  va_start(args, fmt);
  len = vasprintf(&str, fmt, args);
  va_end(args);

  if (len < 0 || !str)
    return -1;

  len = _gnutls_string_append_str(dest, str);

  free(str);

  return len;
}

/* Converts the given string (old) to hex. A buffer must be provided
 * to hold the new hex string. The new string will be null terminated.
 * If the buffer does not have enough space to hold the string, a
 * truncated hex string is returned (always null terminated).
 */
char * _gnutls_bin2hex(const void *_old,
                       size_t oldlen,
                       char *buffer,
                       size_t buffer_size)
{
  unsigned int i, j;
  const opaque *old = _old;

  for (i = j = 0; i < oldlen && j + 2 < buffer_size; j += 2)
    {
      sprintf(&buffer[j], "%.2x", old[i]);
      i++;
    }
  buffer[j] = '\0';

  return buffer;
}

/* just a hex2bin function.
 */
int _gnutls_hex2bin(const opaque * hex_data,
                    int hex_size,
                    opaque * bin_data,
                    size_t * bin_size)
{
  int i, j;
  opaque hex2_data[3];
  unsigned long val;

  /* FIXME: we don't handle whitespace.
   */
  hex_size /= 2;

  if (*bin_size < (size_t) hex_size)
    {
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  for (i = j = 0; j < hex_size; i += 2, j++)
    {
      hex2_data[0] = hex_data[i];
      hex2_data[1] = hex_data[i + 1];
      hex2_data[2] = 0;
      val = strtoul((char *) hex2_data, NULL, 16);
      if (val == ULONG_MAX)
        {
          gnutls_assert ();
          return GNUTLS_E_SRP_PWD_PARSING_ERROR;
        }
      bin_data[j] = val;
    }

  return 0;
}
