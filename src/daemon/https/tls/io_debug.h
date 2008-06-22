/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* This debug file was contributed by 
 * Paul Sheer <psheer@icon.co.za>. Some changes were made by nmav.
 * Its purpose is to debug non blocking behaviour of gnutls. The included
 * send() and recv() functions return EAGAIN errors in random.
 *
 */

#ifdef IO_DEBUG

#include <gnutls_int.h>

#define EDUNNO EAGAIN		/* EAGAIN */

extern int errno;
static int initialized_rand = 0;

#define INITIALIZE_RAND if (initialized_rand==0) {\
		srand(time(0)); \
		initialized_rand = 1; \
		}
static int
recv_debug (int fd, char *buf, int len, int flags)
{
  INITIALIZE_RAND;

  if (!(rand () % IO_DEBUG))
    {
      errno = EDUNNO;
      return -1;
    }
  if (len > 1)
    len = 1;
  return recv (fd, buf, len, flags);
}

#define recv recv_debug

static int
send_debug (int fd, const char *buf, int len, int flags)
{
  INITIALIZE_RAND;

  if (!(rand () % IO_DEBUG))
    {
      errno = EDUNNO;
      return -1;
    }
  if (len > 10)
    len = 10;
  return send (fd, buf, len, flags);
}

#define send send_debug

#endif
