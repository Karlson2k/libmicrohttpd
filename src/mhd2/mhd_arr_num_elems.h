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
 * @file src/mhd2/mhd_arr_num_elements.h
 * @brief  The definition of mhd_ARR_NUM_ELEMS macro
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_ARR_NUM_ELEMS_H
#define MHD_ARR_NUM_ELEMS_H 1

#include "mhd_sys_options.h"

/**
 * Get the number of elements in the array
 */
#define mhd_ARR_NUM_ELEMS(arr) (sizeof(arr) / sizeof(arr[0]))

#endif /* ! MHD_ARR_NUM_ELEMS_H */
