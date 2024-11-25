/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file src/mhd2/mhd_read_file.c
 * @brief  The implementation of mhd_read_file() function
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "mhd_read_file.h"

#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#if ! defined(mhd_W32_NATIVE)
#  include "mhd_limits.h"
#else
/* Native W32 */
#  include <windows.h>
#  include <string.h> /* for memset() */
#endif
/**
 * Read data from the file to the provided buffer
 *
 * @param file_fd the FD of file to read
 * @param buf_size the size of the @a buf buffer
 * @param[out] buf the buffer to fill with the read data
 * @param[out] size_filled the pointer to variable to get the size of the data
 *                         actually put to the @a buffer
 * @return #mhd_FILE_READ_OK if succeed (the @a size_filled gets the actual
 *         read size),
 *         error otherwise
 */
MHD_INTERNAL MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_SIZE_ (4, 3) MHD_FN_PAR_OUT_ (5) enum mhd_FileReadResult
mhd_read_file (int file_fd,
               uint_fast64_t offset,
               size_t buf_size,
               char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
               size_t *restrict size_filled)
{
#if (defined(HAVE_PREAD64) || defined(HAVE_PREAD)) && ! defined(mhd_W32_NATIVE)
#  ifdef HAVE_PREAD64
  const off64_t pos_off = (off64_t) offset;
#  else  /* HAVE_PREAD */
  const off_t pos_off = (off_t) offset;
#  endif /* HAVE_PREAD */
  ssize_t res;

  *size_filled = 0;

  if ((0 > pos_off) ||
      (offset != (uint_fast64_t) pos_off))
    return mhd_FILE_READ_OFFSET_TOO_LARGE;

  if (0 > (ssize_t) buf_size)
    buf_size = SSIZE_MAX; /* Larger sizes may result in undefined behaviour */

#  ifdef HAVE_PREAD64
  res = pread64 (file_fd,
                 buf,
                 buf_size,
                 pos_off);
#  else  /* HAVE_PREAD */
  res = pread (file_fd,
               buf,
               buf_size,
               pos_off);
#  endif /* HAVE_PREAD */

  if (0 > res)
    return mhd_FILE_READ_ERROR;

  if (0 == res)
    return mhd_FILE_READ_EOF;

  *size_filled = (size_t) res;
  return mhd_FILE_READ_OK;
#elif ! defined(mhd_W32_NATIVE)
  /* Multithread-unsafe emulation */
#  ifdef HAVE_LSEEK64
  const off64_t pos_off = (off64_t) offset;
#  else
  const off_t pos_off = (off_t) offset;
#  endif
  ssize_t res;

  *size_filled = 0;

  if ((0 > pos_off) ||
      (offset != (uint_fast64_t) pos_off))
    return mhd_FILE_READ_OFFSET_TOO_LARGE;

  if (0 > (ssize_t) buf_size)
    buf_size = SSIZE_MAX; /* Larger sizes may result in undefined behaviour */

#  ifdef HAVE_LSEEK64
  if (pos_off != lseek64 (file_fd,
                          pos_off,
                          SEEK_SET))
    return mhd_FILE_READ_ERROR;
#  else
  if (pos_off != lseek (file_fd,
                        pos_off,
                        SEEK_SET))
    return mhd_FILE_READ_ERROR;
#  endif

  res = read (file_fd,
              buf,
              buf_size);

  if (0 > res)
    return mhd_FILE_READ_ERROR;

  if (0 == res)
    return mhd_FILE_READ_EOF;

  *size_filled = (size_t) res;
  return mhd_FILE_READ_OK;

#else  /* Native W32 */
  const intptr_t sys_fd = _get_osfhandle (file_fd);
  const HANDLE w_hndl = (HANDLE) sys_fd;
  OVERLAPPED ovrlp;
  DWORD reqReadSize;
  DWORD resReadSize;

  *size_filled = 0;
  if (INVALID_HANDLE_VALUE == w_hndl)
    return mhd_FILE_READ_ERROR;

  memset (&ovrlp, 0, sizeof(ovrlp));
  reqReadSize = (DWORD) buf_size;
  if (reqReadSize != buf_size)
    reqReadSize = (DWORD) (~((DWORD) 0));
  ovrlp.Offset = (DWORD) offset;
  offset >>= 32;
  ovrlp.OffsetHigh = (DWORD) offset;
  if (0 != (offset >> 32))
    return mhd_FILE_READ_OFFSET_TOO_LARGE;

  if (! ReadFile (w_hndl,
                  buf,
                  reqReadSize,
                  &resReadSize,
                  &ovrlp))
    return mhd_FILE_READ_ERROR;

  if (0 == resReadSize)
    return mhd_FILE_READ_EOF;

  *size_filled = resReadSize;
  return mhd_FILE_READ_OK;
#endif /* Native W32 */
}
