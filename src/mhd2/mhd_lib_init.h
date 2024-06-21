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
#include "autoinit_funcs.h"

/**
 * Initialise library global resources
 */
void
mhd_lib_global_init (void);

/**
 * Deinitialise and free library global resources
 */
void
mhd_lib_global_deinit (void);

#ifdef _AUTOINIT_FUNCS_ARE_SUPPORTED
#  define MHD_GLOBAL_INIT_CHECK() ((void) 0)
#else /* ! _AUTOINIT_FUNCS_ARE_SUPPORTED */
/* The functions are exported, but not declared in public header */

/**
 * Check whether the library was initialised and initialise if needed
 */
MHD_EXTERN_ void
MHD_lib_global_check_init (void);

/**
 * Check whether the library has been de-initialised and de-initialise if needed
 */
MHD_EXTERN_ void
MHD_lib_global_check_deinit (void)

#  define MHD_GLOBAL_INIT_CHECK() MHD_lib_global_check_init ()

#endif /* ! _AUTOINIT_FUNCS_ARE_SUPPORTED */


#endif /* ! MHD_LIB_INIT_H */
