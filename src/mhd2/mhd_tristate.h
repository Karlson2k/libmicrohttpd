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
 * @file src/mhd2/mhd_tristate.h
 * @brief  The definition of the tristate type and helper macros
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TRISTATE_H
#define MHD_TRISTATE_H 1

#include "mhd_sys_options.h"

/**
 * Enum with three values / states
 */
enum MHD_FIXED_ENUM_ mhd_Tristate
{
  /**
   * Definitely no / negative / false
   */
  mhd_T_NO = 0
  ,
  /**
   * Definitely yes / positive / true
   */
  mhd_T_YES = 1
  ,
  /**
   * Undetermined / not known / maybe yes-maybe no
   */
  mhd_T_MAYBE = -1
};

/**
 * Check whether tristate value is mhd_T_YES
 */
#define mhd_T_IS_YES(v) (mhd_T_NO < (v))

/**
 * Check whether tristate value is mhd_T_NO
 */
#define mhd_T_IS_NO(v) (mhd_T_NO == (v))

/**
 * Check whether tristate value is mhd_T_MAYBE
 */
#define mhd_T_IS_MAYBE(v) (mhd_T_NO > (v))

/**
 * Check whether tristate value is NOT mhd_T_YES
 */
#define mhd_T_IS_NOT_YES(v) (mhd_T_NO >= (v))

/**
 * Check whether tristate value is NOT mhd_T_NO
 */
#define mhd_T_IS_NOT_NO(v) (mhd_T_NO != (v))

/**
 * Check whether tristate value is NOT mhd_T_MAYBE
 */
#define mhd_T_IS_NOT_MAYBE(v) (mhd_T_NO <= (v))

#endif /* ! MHD_TRISTATE_H */
