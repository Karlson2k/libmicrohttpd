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
 * @file src/mhd2/mhd_lib_init_auto.h
 * @brief  Declarations for the library global initialiser and deinitialiser
 *         that called automatically at startup and shutdown of the application
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_LIB_INIT_AUTO_H
#define MHD_LIB_INIT_AUTO_H 1
#include "mhd_sys_options.h"

#define AUTOINIT_FUNCS_NO_WARNINGS_SUNPRO_C 1 /* The compiler is supported directly */
#include "autoinit_funcs.h"

#ifdef AIF_AUTOINIT_FUNCS_ARE_SUPPORTED
/* Use automatically called initialisation functions */
#  define mhd_AUTOINIT_FUNCS_USE        1
#elif defined(AIF_PRAGMA_INIT_SUPPORTED) && defined(AIF_PRAGMA_FINI_SUPPORTED)
/* Use automatically called initialisation functions */
#  define mhd_AUTOINIT_FUNCS_USE        1
/* Use "#pragma" to set initialisation functions */
#  define mhd_AUTOINIT_FUNCS_PRAGMA     1
#endif


#ifdef mhd_AUTOINIT_FUNCS_USE
/**
 * Perform the minimal initialisation of the library
 */
void
mhd_lib_global_init_auto (void);

/**
 * Deinitialise resources previously initialised by #mhd_lib_global_lazy_init()
 */
void
mhd_lib_global_deinit_auto (void);

#endif /* mhd_AUTOINIT_FUNCS_USE */


#endif /* ! MHD_LIB_INIT_AUTO_H */
