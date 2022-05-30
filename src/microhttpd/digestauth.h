/*
     This file is part of libmicrohttpd
     Copyright (C) 2010, 2011, 2012, 2015, 2018 Daniel Pittman and Christian Grothoff
     Copyright (C) 2014-2022 Evgeny Grin (Karlson2k)

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
/**
 * @file digestauth.c
 * @brief Implements HTTP digest authentication
 * @author Amr Ali
 * @author Matthieu Speder
 * @author Christian Grothoff (RFC 7616 support)
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_DIGESTAUTH_H
#define MHD_DIGESTAUTH_H 1

#include "mhd_options.h"
#include "mhd_str.h"
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif /* HAVE_STDBOOL_H */


/**
 * The maximum supported size for Digest Auth parameters, like "real",
 * "username" etc. This limitation is used only for quoted parameters.
 * Parameters without quoted backslash character will be processed as long
 * as they fit connection pool (buffer) size.
 */
#define _MHD_AUTH_DIGEST_MAX_PARAM_SIZE (65535)

/**
 * Beginning string for any valid Digest Authentication header.
 */
#define _MHD_AUTH_DIGEST_BASE   "Digest"

struct MHD_RqDAuthParam
{
  struct _MHD_cstr_w_len value;
  bool quoted;
};

struct MHD_RqDAuth
{
  struct MHD_RqDAuthParam nonce;
  struct MHD_RqDAuthParam opaque;
  struct MHD_RqDAuthParam algorithm;
  struct MHD_RqDAuthParam response;
  struct MHD_RqDAuthParam username;
  struct MHD_RqDAuthParam username_ext;
  struct MHD_RqDAuthParam realm;
  struct MHD_RqDAuthParam uri;
  struct MHD_RqDAuthParam qop;
  struct MHD_RqDAuthParam cnonce;
  struct MHD_RqDAuthParam nc;
  bool userhash;
};

#endif /* ! MHD_DIGESTAUTH_H */

/* end of digestauth.h */
