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
 * @file src/mhd2/mhd_str_macros.h
 * @brief  The definition of the MHD_String helper macros
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_STR_MACROS_H
#define MHD_STR_MACROS_H 1

#include "mhd_sys_options.h"

/**
 * The length of static string, not including terminating zero.
 * Can be used with char[] arrays.
 */
#define mhd_SSTR_LEN(sstr) (sizeof(sstr) / sizeof(char) - 1)

/**
 * The initialiser for the struct MHD_String
 */
#define mhd_MSTR_INIT(sstr) { mhd_SSTR_LEN (sstr), (sstr)}


#endif /* ! MHD_STR_MACROS_H */
