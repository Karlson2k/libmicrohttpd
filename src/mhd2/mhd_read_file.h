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
 * @file src/mhd2/mhd_read_file.h
 * @brief  The declaration of mhd_read_file() function
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_READ_FILE_H
#define MHD_READ_FILE_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"

/**
 * Results of file reading
 */
enum mhd_FileReadResult
{
  /**
   * File read succeed
   */
  mhd_FILE_READ_OK = 0
  ,
  /**
   * File read failed
   */
  mhd_FILE_READ_ERROR
  ,
  /**
   * The requested offset is too large
   */
  mhd_FILE_READ_OFFSET_TOO_LARGE
  ,
  /**
   * Got "end of file"
   */
  mhd_FILE_READ_EOF
};


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
MHD_INTERNAL enum mhd_FileReadResult
mhd_read_file (int file_fd,
               uint_fast64_t offset,
               size_t buf_size,
               char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
               size_t *restrict size_filled)
MHD_FN_MUST_CHECK_RESULT_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_SIZE_(4, 3) MHD_FN_PAR_OUT_ (5);


#endif /* ! MHD_READ_FILE_H */
