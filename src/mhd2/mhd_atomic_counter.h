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
 * @file src/mhd2/mhd_atomic_counter.h
 * @brief  The definition of the atomic counter type and related functions
 *         declarations
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_ATOMIC_COUNTER_H
#define MHD_ATOMIC_COUNTER_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h" /* for size_t */

/* Use 'size_t' to make sure it would never overflow when used for
 * MHD needs. */

/**
 * The type used to contain the counter value.
 * Always unsigned.
 */
#define mhd_ATOMIC_COUNTER_TYPE size_t
/**
 * The maximum counter value
 */
#define mhd_ATOMIC_COUNTER_MAX \
        ((mhd_ATOMIC_COUNTER_TYPE) (~((mhd_ATOMIC_COUNTER_TYPE) 0)))

#ifdef MHD_USE_THREADS

/**
 * Atomic operations are based on locks
 */
#  define mhd_ATOMIC_BY_LOCKS 1

#else  /* ! MHD_USE_THREADS */

/**
 * Atomic because single thread environment is used
 */
#  define mhd_ATOMIC_SINGLE_THREAD 1
#endif /* ! MHD_USE_THREADS */


#if defined(mhd_ATOMIC_BY_LOCKS)
#  include "mhd_locks.h"
#  include "sys_bool_type.h"

/**
 * The atomic counter
 */
struct mhd_AtomicCounter
{
  /**
   * Counter value.
   * Must be read or written only with @a lock held.
   */
  volatile mhd_ATOMIC_COUNTER_TYPE count;
  /**
   * The mutex.
   */
  mhd_mutex lock;
};

#elif defined(mhd_ATOMIC_SINGLE_THREAD)

/**
 * The atomic counter
 */
struct mhd_AtomicCounter
{
  /**
   * Counter value.
   */
  volatile mhd_ATOMIC_COUNTER_TYPE count;
};

#endif /* mhd_ATOMIC_SINGLE_THREAD */


#if defined(mhd_ATOMIC_BY_LOCKS)

/**
 * Initialise the counter to specified value.
 * @param pcnt the pointer to the counter to initialise
 * @param initial_value the initial value for the counter
 * @return 'true' if succeed, "false' if failed
 * @warning Must not be called for the counters that has been initialised
 *          already.
 */
#  define mhd_atomic_counter_init(pcnt,initial_value) \
        ((pcnt)->count = (initial_value), \
         mhd_mutex_init_short (&((pcnt)->lock)))

/**
 * Deinitialise the counter.
 * @param pcnt the pointer to the counter to deinitialise
 * @warning Must be called only for the counters that has been initialised.
 */
#  define mhd_atomic_counter_deinit(pcnt) \
        mhd_mutex_destroy_chk (&((pcnt)->lock))

/**
 * Atomically increment the value of the counter
 * @param pcnt the pointer to the counter to increment
 */
#  define mhd_atomic_counter_inc(pcnt)  do { \
          mhd_mutex_lock_chk (&((pcnt)->lock));     \
          ++(pcnt->count);                       \
          mhd_mutex_unlock_chk (&((pcnt)->lock)); } while (0)

/**
 * Atomically increment the value of the counter and return the result
 * @param pcnt the pointer to the counter to increment
 * @return the final/resulting counter value
 */
MHD_INTERNAL mhd_ATOMIC_COUNTER_TYPE
mhd_atomic_counter_inc_get (struct mhd_AtomicCounter *pcnt);

/**
 * Atomically decrement the value of the counter and return the result
 * @param pcnt the pointer to the counter to decrement
 * @return the final/resulting counter value
 */
MHD_INTERNAL mhd_ATOMIC_COUNTER_TYPE
mhd_atomic_counter_dec_get (struct mhd_AtomicCounter *pcnt);

/**
 * Atomically get the value of the counter
 * @param pcnt the pointer to the counter to get
 * @return the counter value
 */
MHD_INTERNAL mhd_ATOMIC_COUNTER_TYPE
mhd_atomic_counter_get (struct mhd_AtomicCounter *pcnt);

#elif defined(mhd_ATOMIC_SINGLE_THREAD)

/**
 * Initialise the counter to specified value.
 * @param pcnt the pointer to the counter to initialise
 * @param initial_value the initial value for the counter
 * @return 'true' if succeed, "false' if failed
 * @warning Must not be called for the counters that has been initialised
 *          already.
 */
#  define mhd_atomic_counter_init(pcnt,initial_value) \
        ((pcnt)->count = (initial_value), (! 0))

/**
 * Deinitialise the counter.
 * @param pcnt the pointer to the counter to deinitialise
 * @warning Must be called only for the counters that has been initialised.
 */
#  define mhd_atomic_counter_deinit(pcnt) ((void) 0)

/**
 * Atomically increment the value of the counter
 * @param pcnt the pointer to the counter to increment
 */
#  define mhd_atomic_counter_inc(pcnt)  do { ++(pcnt->count); } while (0)

/**
 * Atomically increment the value of the counter and return the result
 * @param pcnt the pointer to the counter to increment
 * @return the final/resulting counter value
 */
#  define mhd_atomic_counter_inc_get(pcnt) (++((pcnt)->count))

/**
 * Atomically decrement the value of the counter and return the result
 * @param pcnt the pointer to the counter to decrement
 * @return the final/resulting counter value
 */
#  define mhd_atomic_counter_dec_get(pcnt) (--((pcnt)->count))

/**
 * Atomically get the value of the counter
 * @param pcnt the pointer to the counter to get
 * @return the counter value
 */
#  define mhd_atomic_counter_get(pcnt) ((pcnt)->count)

#endif /* mhd_ATOMIC_SINGLE_THREAD */

#endif /* ! MHD_ATOMIC_COUNTER_H */
