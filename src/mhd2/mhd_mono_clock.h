/*
  This file is part of libmicrohttpd
  Copyright (C) 2015-2024 Karlson2k (Evgeny Grin)

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
 * @file src/mhd2/mhd_mono_clock.h
 * @brief  internal monotonic clock functions declarations
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_MONO_CLOCK_H
#define MHD_MONO_CLOCK_H 1
#include "mhd_sys_options.h"

#include "sys_base_types.h"

/**
 * Initialise milliseconds counters.
 */
void
MHD_monotonic_msec_counter_init (void);


/**
 * Deinitialise milliseconds counters by freeing any allocated resources
 */
void
MHD_monotonic_msec_counter_finish (void);


/**
 * Monotonic milliseconds counter, useful for timeout calculation.
 * Tries to be not affected by manually setting the system real time
 * clock or adjustments by NTP synchronization.
 *
 * @return number of microseconds from some fixed moment
 */
uint_fast64_t
MHD_monotonic_msec_counter (void);

#endif /* MHD_MONO_CLOCK_H */
