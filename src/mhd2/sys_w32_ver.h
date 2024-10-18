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
 * @file src/mhd2/sys_w32_ver.h
 * @brief  Define _WIN32_WINNT macro, include minimal required system header if
 *         necessary
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SYS_W32_VER_H
#define MHD_SYS_W32_VER_H 1

#include "mhd_sys_options.h"

#ifndef _WIN32
#error This file must not be used on non-W32 systems
#endif

#ifndef _WIN32_WINNT
#  ifdef HAVE_SDKDDKVER_H
#    include <sdkddkver.h>
#  else
#    include <windows.h>
#endif

#endif /* ! MHD_SYS_W32_VER_H */
