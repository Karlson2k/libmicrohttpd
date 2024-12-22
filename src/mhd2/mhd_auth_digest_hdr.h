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
 * @file src/mhd2/mhd_auth_digest_hdr.h
 * @brief  The definition of the Digest Auth response header structure
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_AUTH_DIGEST_HDR_H
#define MHD_AUTH_DIGEST_HDR_H 1

#include "mhd_sys_options.h"

#ifndef MHD_SUPPORT_AUTH_DIGEST
#error This header should be used only if Digest Auth is build
#endif

#include "mhd_str_types.h"
#include "mhd_dlinked_list.h"

struct MHD_Response;                    /* forward declaration */
struct mhd_RespAuthDigestHeader;        /* forward declaration */

mhd_DLINKEDL_STRUCTS_DEFS (mhd_RespAuthDigestHeader);

/**
 * The Digest Auth response header (the challenge)
 */
struct mhd_RespAuthDigestHeader
{
  /**
   * The complete header string, including the name, the colon, the value and
   * CRLF terminating chars
   */
  struct MHD_String hdr;

  /**
   * The position of the nonce placeholder in the @a hdr
   */
  size_t nonce_pos;

  /**
   * The links to the other headers for the same response
   */
  mhd_DLNKDL_LINKS_TYPE (mhd_RespAuthDigestHeader) auth_d_hdrs;
};

#endif /* ! MHD_AUTH_DIGEST_HDR_H */
