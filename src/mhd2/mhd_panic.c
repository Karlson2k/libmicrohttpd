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
 * @brief  mhd_panic() and MHD_lib_set_panic_func() implementations
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#elif defined(HAVE_UNISTD_H)
#  include <unistd.h>
#endif
#include "sys_null_macro.h"
#include "mhd_public_api.h"
#include "mhd_panic.h"

/**
 * The user handler for panic
 */
static MHD_PanicCallback user_panic_handler = (MHD_PanicCallback) NULL;

/**
 * The closure argument for the #user_panic_handler
 */
static void *user_panic_handler_cls = NULL;

MHD_INTERNAL void
mhd_panic_init_default (void)
{
  user_panic_handler = (MHD_PanicCallback) NULL;
}


MHD_EXTERN_ void
MHD_lib_set_panic_func (MHD_PanicCallback cb,
                        void *cls)
{
  user_panic_handler = cb;
  user_panic_handler_cls = cls;
}


MHD_NORETURN_ MHD_INTERNAL void
mhd_panic (const char *file,
           const char *func,
           unsigned int line,
           const char *message)
{
  static const char empty_str[1] = "";
  if (NULL == file)
    file = empty_str;
  if (NULL == func)
    func = empty_str;
  if (NULL == message)
    message = empty_str;
  if (NULL != user_panic_handler)
    user_panic_handler (user_panic_handler_cls,
                        file, func, line, message);
#ifdef HAVE_LOG_FUNCTIONALITY
  if (0 == file[0])
    fprintf (stderr,
             "Unrecoverable error detected in GNU libmicrohttpd%s%s\n",
             (0 == message[0]) ? "" : ": ",
             message);
  else
  {
    if (0 != func[0])
    {
      fprintf (stderr,
               "Unrecoverable error detected in GNU libmicrohttpd, " \
               "file '%s' at %s:%u%s%s\n",
               file, func, line,
               (0 == message[0]) ? "" : ": ",
               message);
    }
    else
    {
      fprintf (stderr,
               "Unrecoverable error detected in GNU libmicrohttpd, " \
               "file '%s' at line %u%s%s\n",
               file, line,
               (0 == message[0]) ? "" : ": ",
               message);
    }
  }
#endif /* HAVE_LOG_FUNCTIONALITY */
  abort ();
}
