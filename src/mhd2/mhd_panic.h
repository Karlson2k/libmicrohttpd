/*
  This file is part of libmicrohttpd
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
 * @file src/mhd2/mhd_panic.h
 * @brief  MHD_PANIC() macro and declarations of the related functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_PANIC_H
#define MHD_PANIC_H 1

#include "mhd_sys_options.h"

#ifndef BUILDING_MHD_LIB
/* Simplified implementation, utilised by unit tests that use some parts of
   the library code directly. */
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#elif defined(HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#define MHD_PANIC(msg) \
        do { fprintf (stderr,"Unrecoverable error: %s\n", msg); abort (); } \
        while (0)

#else  /* BUILDING_MHD_LIB */
/* Fully functional implementation for the library */

/**
 * Internal panic handler
 * @param file the name of the file where the panic was triggered
 * @param func the name of the function where the panic was triggered
 * @param line the number of the line where the panic was triggered
 * @param message the message with the description of the panic
 */
MHD_NORETURN_ MHD_INTERNAL void
mhd_panic (const char *file,
           const char *func,
           unsigned int line,
           const char *message);


#ifdef MHD_PANIC
#error MHD_PANIC macro is already defined. Check other headers.
#endif /* MHD_PANIC */

#ifdef HAVE_LOG_FUNCTIONALITY
#  ifdef MHD_HAVE_MHD_FUNC_
/**
 * Panic processing for unrecoverable errors.
 *
 * @param msg the error message string
 */
#    define MHD_PANIC(msg) \
        mhd_panic (__FILE__, MHD_FUNC_, __LINE__, msg)
#  else
#    include "sys_null_macro.h"
/**
 * Panic processing for unrecoverable errors.
 *
 * @param msg the error message string
 */
#    define MHD_PANIC(msg) \
        mhd_panic (__FILE__, NULL, __LINE__, msg)
#  endif
#else
#  include "sys_null_macro.h"
/**
 * Panic processing for unrecoverable errors.
 *
 * @param msg the error message string
 */
#    define MHD_PANIC(msg) \
        mhd_panic (NULL, NULL, __LINE__, NULL)
#endif

/**
 * Initialise panic handler to default value
 */
MHD_INTERNAL void
mhd_panic_init_default (void);

#endif /* BUILDING_MHD_LIB */

#endif /* ! MHD_PANIC_H */
