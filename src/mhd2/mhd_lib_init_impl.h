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
 * @file src/mhd2/mhd_lib_init_impl.h
 * @brief  Library global initialisers and de-initialisers
 * @author Karlson2k (Evgeny Grin)
 *
 * This file should be a .c file, but used as .h file to workaround
 * a GCC/binutils bug.
 */

#ifdef MHD_LIB_INIT_IMPL_H
#error This file must not be included more the one time only
#endif
#define MHD_LIB_INIT_IMPL_H 1

/* Due to the bug in GCC/binutils, on some platforms (at least on W32)
 * the automatic initialisation functions are not called when library is used
 * as a static library and no function is used/referred from the same
 * object/module/c-file.
 */
#ifndef MHD_LIB_INIT_IMPL_H_IN_DAEMON_CREATE_C
#error This file must in included only in 'daemon_create.c' file
#else  /* MHD_LIB_INIT_IMPL_H_IN_DAEMON_CREATE_C */

#include "mhd_sys_options.h"
#include "mhd_lib_init.h"

/* Forward declarations */
void
mhd_lib_global_init_wrap (void);

void
mhd_lib_global_deinit_wrap (void);


void
mhd_lib_global_init_wrap (void)
{
  mhd_lib_global_init ();
}


void
mhd_lib_global_deinit_wrap (void)
{
  mhd_lib_global_deinit ();
}


#ifdef _AUTOINIT_FUNCS_ARE_SUPPORTED

_SET_INIT_AND_DEINIT_FUNCS (mhd_lib_global_init_wrap, \
                            mhd_lib_global_deinit_wrap);

#endif /* _AUTOINIT_FUNCS_ARE_SUPPORTED */

#endif /* MHD_LIB_INIT_IMPL_H_IN_DAEMON_CREATE_C */
