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
 * @file src/mhd2/conn_data_recv.h
 * @brief  The definition of data receiving functions for connection
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_CONN_DATA_RECV_H
#define MHD_CONN_DATA_RECV_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

struct MHD_Connection; /* forward declarations */

/**
 * Perform data receiving for the connection and try to detect the socket error
 * type.
 *
 * @param c the connection to use
 * @param has_err if 'true' then just check for the network error
 *        type is performed
 */
MHD_INTERNAL void
mhd_conn_data_recv (struct MHD_Connection *restrict c,
                    bool has_err)
MHD_FN_PAR_NONNULL_ALL_;


#endif /* ! MHD_CONN_DATA_RECV_H */
