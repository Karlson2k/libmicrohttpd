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
 * @file src/mhd2/mhd_lib_init.h
 * @brief  Declarations for the library global initialiser
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_LIB_INIT_H
#define MHD_LIB_INIT_H 1
#include "mhd_sys_options.h"

#include "sys_bool_type.h"

/**
 * Check whether the library was initialised and initialise if needed.
 * Increment number of active users of library global resources.
 * @return 'true' if succeed,
 *         'false' if failed
 */
MHD_INTERNAL bool
mhd_lib_init_global_if_needed (void);

/**
 * Decrement number of the library active users of global global resources and
 * deinitialise the library if no active users left.
 */
MHD_INTERNAL void
mhd_lib_deinit_global_if_needed (void);


#endif /* ! MHD_LIB_INIT_H */
