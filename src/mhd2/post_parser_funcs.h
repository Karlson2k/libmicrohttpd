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
 * @file src/mhd2/post_parser_funcs.h
 * @brief  The declarations of internal POST parser functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_POST_PARSER_FUNCS_H
#define MHD_POST_PARSER_FUNCS_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

struct MHD_Connection; /* forward declaration */

/**
 * Make preparation necessary for parsing POST data.
 * @param c the stream to use
 * @return 'true' if succeed,
 *         'false' if failed and error result is set in the stream
 */
MHD_INTERNAL bool
mhd_stream_prepare_for_post_parse (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ (1);

/**
 * Parse POST data.
 * @param c the stream to use
 * @return // FIXME
 */
MHD_INTERNAL bool
mhd_stream_post_parse (struct MHD_Connection *restrict c,
                       size_t *restrict pdata_size,
                       char *restrict buf)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_PAR_INOUT_ (3);

// TODO: describe
MHD_INTERNAL bool
mhd_stream_process_post_finish (struct MHD_Connection *restrict c)
MHD_FN_PAR_NONNULL_ALL_;


#endif /* ! MHD_POST_PARSER_FUNCS_H */
