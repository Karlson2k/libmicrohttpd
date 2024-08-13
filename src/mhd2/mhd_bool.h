/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Christian Grothoff
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
 * @file src/mhd2/mhd_bool.h
 * @brief  The definition of the enum MHD_Bool, which is used in public API
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_BOOL_H
#define MHD_BOOL_H 1

#include "mhd_sys_options.h"

#ifndef MHD_BOOL_DEFINED

enum MHD_Bool
{
  /**
   * MHD-internal return code for "NO".
   */
  MHD_NO = 0
  ,
  /**
   * MHD-internal return code for "YES".  All non-zero values
   * will be interpreted as "YES", but MHD will only ever
   * return #MHD_YES or #MHD_NO.
   */
  MHD_YES = 1
};


#define MHD_BOOL_DEFINED 1
#endif /* ! MHD_BOOL_DEFINED */

#endif /* ! MHD_BOOL_H */
