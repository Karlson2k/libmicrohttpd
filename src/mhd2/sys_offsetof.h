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
 * @file src/mhd2/sys_offsetof.h
 * @brief  The definition of system's 'offsetof' macro or suitable replacement.
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SYS_OFFSETOF_H
#define MHD_SYS_OFFSETOF_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"

#if defined(HAVE_STDDEF_H)
#  include <stddef.h> /* it should be already included, actually */
#endif /* HAVE_STDDEF_H */

#ifndef offsetof
#  define offsetof(strct, membr) \
        ((size_t) (((char*) &(((strct*) 0)->membr)) - ((char*) ((strct*) 0))))
#endif /* ! offsetof */

#endif /* ! MHD_SYS_OFFSETOF_H */
