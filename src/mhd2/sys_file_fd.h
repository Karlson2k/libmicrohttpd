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
 * @file src/mhd2/sys_file_fd.h
 * @brief  The system headers for file FD close, read, write functions.
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef SYS_FILE_FD_H
#define SYS_FILE_FD_H 1

#include "mhd_sys_options.h"

#if defined(_WIN32) && ! defined(__CYGWIN__)
#  include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#else
#  ifdef HAVE_STDLIB_H
#    include <stdlib.h>
#  endif
#  include <stdio.h>
#endif


#endif /* ! SYS_FILE_FD_H */
