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
 * @file src/mhd2/mhd_atomic_counter.c
 * @brief  The definition of the atomic counter functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "mhd_atomic_counter.h"

#if defined(mhd_ATOMIC_BY_LOCKS)

#include "mhd_assert.h"

MHD_INTERNAL mhd_ATOMIC_COUNTER_TYPE
mhd_atomic_counter_inc_get (struct mhd_AtomicCounter *pcnt)
{
  mhd_ATOMIC_COUNTER_TYPE ret;

  mhd_mutex_lock_chk (&(pcnt->lock));
  ret = ++(pcnt->count);
  mhd_mutex_unlock_chk (&(pcnt->lock));

  mhd_assert (0 != ret); /* check for overflow */

  return ret;
}


MHD_INTERNAL mhd_ATOMIC_COUNTER_TYPE
mhd_atomic_counter_dec_get (struct mhd_AtomicCounter *pcnt)
{
  mhd_ATOMIC_COUNTER_TYPE ret;

  mhd_mutex_lock_chk (&(pcnt->lock));
  ret = --(pcnt->count);
  mhd_mutex_unlock_chk (&(pcnt->lock));

  mhd_assert (mhd_ATOMIC_COUNTER_MAX != ret); /* check for underflow */

  return ret;
}


MHD_INTERNAL mhd_ATOMIC_COUNTER_TYPE
mhd_atomic_counter_get (struct mhd_AtomicCounter *pcnt)
{
  mhd_ATOMIC_COUNTER_TYPE ret;

  mhd_mutex_lock_chk (&(pcnt->lock));
  ret = pcnt->count;
  mhd_mutex_unlock_chk (&(pcnt->lock));

  return ret;
}


#endif /* mhd_ATOMIC_BY_LOCKS */
