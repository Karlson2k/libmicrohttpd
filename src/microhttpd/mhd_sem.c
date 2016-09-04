/*
  This file is part of libmicrohttpd
  Copyright (C) 2016 Christian Grothoff

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
 * @file microhttpd/mhd_sem.c
 * @brief  implementation of semaphores
 * @author Christian Grothoff
 */
#include "internal.h"
#include "mhd_locks.h"

/**
 * A semaphore.
 */
struct MHD_Semaphore
{
  /**
   * Mutex we use internally.
   */
  pthread_mutex_t mutex;

  /**
   * Condition variable used to implement the semaphore.
   */
  pthread_cond_t cv;

  /**
   * Current value of the semaphore.
   */
  unsigned int counter;
};


/**
 * Create a semaphore with an initial counter of @a init
 *
 * @param init initial counter
 * @return the semaphore, NULL on error
 */
struct MHD_Semaphore *
MHD_semaphore_create (unsigned int init)
{
  struct MHD_Semaphore *sem;

  sem = malloc (sizeof (struct MHD_Semaphore));
  if (NULL == sem)
    return NULL;
  sem->counter = init;
  if (0 != pthread_mutex_init (&sem->mutex,
                               NULL))
    {
      free (sem);
      return NULL;
    }
  if (0 != pthread_cond_init (&sem->cv,
                              NULL))
    {
      (void) pthread_mutex_destroy (&sem->mutex);
      free (sem);
      return NULL;
    }
  return sem;
}


/**
 * Count down the semaphore, block if necessary.
 *
 * @param sem semaphore to count down.
 */
void
MHD_semaphore_down (struct MHD_Semaphore *sem)
{
  if (0 != pthread_mutex_lock (&sem->mutex))
    MHD_PANIC ("pthread_mutex_lock for semaphore failed\n");
  while (0 == sem->counter)
    {
      if (0 != pthread_cond_wait (&sem->cv,
                                  &sem->mutex))
        MHD_PANIC ("pthread_cond_wait failed\n");
    }
  sem->counter--;
  if (0 != pthread_mutex_unlock (&sem->mutex))
    MHD_PANIC ("pthread_mutex_unlock for semaphore failed\n");
}


/**
 * Increment the semaphore.
 *
 * @param sem semaphore to increment.
 */
void
MHD_semaphore_up (struct MHD_Semaphore *sem)
{
  if (0 != pthread_mutex_lock (&sem->mutex))
    MHD_PANIC ("pthread_mutex_lock for semaphore failed\n");
  sem->counter++;
  pthread_cond_signal (&sem->cv);
  if (0 != pthread_mutex_unlock (&sem->mutex))
    MHD_PANIC ("pthread_mutex_unlock for semaphore failed\n");
}


/**
 * Destroys the semaphore.
 *
 * @param sem semaphore to destroy.
 */
void
MHD_semaphore_destroy (struct MHD_Semaphore *sem)
{
  if (0 != pthread_cond_destroy (&sem->cv))
    MHD_PANIC ("pthread_cond_destroy failed\n");
  if (0 != pthread_mutex_destroy (&sem->mutex))
    MHD_PANIC ("pthread_mutex_destroy failed\n");
  free (sem);
}


/* end of mhd_sem.c */
