/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2016-2024 Evgeny Grin (Karlson2k), Christian Grothoff

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
 * @file src/mhd2/mhd_itc.h
 * @brief  Header for platform-independent inter-thread communication
 * @author Karlson2k (Evgeny Grin)
 * @author Christian Grothoff
 *
 * Provides basic abstraction for inter-thread communication.
 * Any functions can be implemented as macro on some platforms
 * unless explicitly marked otherwise.
 * Any "function" argument can be unused in macro, so avoid
 * variable modification in function parameters.
 */
#ifndef MHD_ITC_H
#define MHD_ITC_H 1
#include "mhd_itc_types.h"

#include "mhd_panic.h"

#if defined(MHD_ITC_EVENTFD_)

/* **************** Optimised ITC implementation by eventfd ********** */
#  include <sys/eventfd.h>
#  include <stdint.h>      /* for uint_fast64_t */
#  ifdef HAVE_UNISTD_H
#    include <unistd.h>      /* for read(), write() */
#  else
#    include <stdlib.h>
#  endif /* HAVE_UNISTD_H */
#  include "sys_errno.h"

/**
 * Number of FDs used by every ITC.
 */
#  define mhd_ITC_NUM_FDS (1)

/**
 * Set @a itc to the invalid value.
 * @param pitc the pointer to the itc to set
 */
#define mhd_itc_set_invalid(pitc) ((pitc)->fd = -1)

/**
 * Check whether ITC has valid value.
 *
 * Macro check whether @a itc value is valid (allowed),
 * macro does not check whether @a itc was really initialised.
 * @param itc the itc to check
 * @return boolean true if @a itc has valid value,
 *         boolean false otherwise.
 */
#define mhd_ITC_IS_VALID(itc)  (0 <= ((itc).fd))

/**
 * Initialise ITC by generating eventFD
 * @param pitc the pointer to the ITC to initialise
 * @return non-zero if succeeded, zero otherwise
 */
#  define mhd_itc_init(pitc) \
        (-1 != ((pitc)->fd = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK)))

/**
 * Helper for mhd_itc_activate()
 */
#  ifdef HAVE_COMPOUND_LITERALS_LVALUES
#    define mhd_ITC_WR_DATA ((uint_fast64_t){1})
#  else
/**
 * Internal static const helper for mhd_itc_activate()
 */
static const uint_fast64_t mhd_ITC_WR_DATA = 1;
#  endif

/**
 * Activate signal on the @a itc
 * @param itc the itc to use
 * @return non-zero if succeeded, zero otherwise
 */
#define mhd_itc_activate(itc)                                \
        ((write ((itc).fd, (const void*) &mhd_ITC_WR_DATA, 8) > 0) \
         || (EAGAIN == errno))

/**
 * Return read FD of @a itc which can be used for poll(), select() etc.
 * @param itc the itc to get FD
 * @return FD of read side
 */
#define mhd_itc_r_fd(itc) ((itc).fd)

/**
 * Clear signalled state on @a itc
 * @param itc the itc to clear
 */
#define mhd_itc_clear(itc)                      \
        do { uint_fast64_t __b;                       \
             (void) read ((itc).fd, (void*) &__b, 8);  \
        } while (0)

/**
 * Destroy previously initialised ITC.  Note that close()
 * on some platforms returns odd errors, so we ONLY fail
 * if the errno is EBADF.
 * @param itc the itc to destroy
 * @return non-zero if succeeded, zero otherwise
 */
#define mhd_itc_destroy(itc) \
        ((0 == close ((itc).fd)) || (EBADF != errno))

#elif defined(MHD_ITC_PIPE_)

/* **************** Standard UNIX ITC implementation by pipe ********** */

#  if defined(HAVE_PIPE2_FUNC)
#    include <fcntl.h>     /* for O_CLOEXEC, O_NONBLOCK */
#  endif /* HAVE_PIPE2_FUNC && HAVE_FCNTL_H */
#  ifdef HAVE_UNISTD_H
#    include <unistd.h>      /* for read(), write() */
#  else
#    include <stdlib.h>
#  endif /* HAVE_UNISTD_H */
#  include "sys_errno.h"
#  if defined(HAVE_PIPE2_FUNC) && defined(O_CLOEXEC) && defined(O_NONBLOCK)
#    define MHD_USE_PIPE2 1
#  else
#    include "sys_bool_type.h"
#  endif


/**
 * Number of FDs used by every ITC.
 */
#  define mhd_ITC_NUM_FDS (2)

/**
 * Set @a itc to the invalid value.
 * @param pitc the pointer to the itc to set
 */
#  define mhd_itc_set_invalid(pitc) ((pitc)->fd[0] = (pitc)->fd[1] = -1)

/**
 * Check whether ITC has valid value.
 *
 * Macro check whether @a itc value is valid (allowed),
 * macro does not check whether @a itc was really initialised.
 * @param itc the itc to check
 * @return boolean true if @a itc has valid value,
 *         boolean false otherwise.
 */
#  define mhd_ITC_IS_VALID(itc)  (0 <= (itc).fd[0])

/**
 * Initialise ITC by generating pipe
 * @param pitc the pointer to the ITC to initialise
 * @return non-zero if succeeded, zero otherwise
 */
#  if defined(MHD_USE_PIPE2)
#    define mhd_itc_init(pitc) (! pipe2 ((pitc)->fd, O_CLOEXEC | O_NONBLOCK))
#  else  /* ! MHD_USE_PIPE2 */
#    define mhd_itc_init(pitc)         \
        ( (! pipe ((pitc)->fd)) ?           \
          (mhd_itc_nonblocking ((pitc)) ?   \
           (! 0) :                          \
           (mhd_itc_destroy (*(pitc)), 0) ) \
    : (0) )

#    define MHD_HAVE_MHD_ITC_NONBLOCKING 1
/**
 * Change itc FD options to be non-blocking.
 *
 * @param pitc the pointer to ITC to manipulate
 * @return true if succeeded, false otherwise
 */
MHD_INTERNAL bool
mhd_itc_nonblocking (struct mhd_itc *pitc);

#  endif /* ! MHD_USE_PIPE2 */

/**
 * Activate signal on @a itc
 * @param itc the itc to use
 * @return non-zero if succeeded, zero otherwise
 */
#  define mhd_itc_activate(itc) \
        ((write ((itc).fd[1], (const void*) "", 1) > 0) || (EAGAIN == errno))

/**
 * Return read FD of @a itc which can be used for poll(), select() etc.
 * @param itc the itc to get FD
 * @return FD of read side
 */
#  define mhd_itc_r_fd(itc) ((itc).fd[0])

/**
 * Clear signaled state on @a itc
 * @param itc the itc to clear
 */
#  define mhd_itc_clear(itc) do                                \
        { long __b;                                                  \
          while (0 < read ((itc).fd[0], (void*) &__b, sizeof(__b)))  \
          {(void) 0;} } while (0)

/**
 * Destroy previously initialised ITC
 * @param itc the itc to destroy
 * @return non-zero if succeeded, zero otherwise
 */
#  define mhd_itc_destroy(itc)     \
        (0 == (close ((itc).fd[0]) + close ((itc).fd[1])))

#elif defined(MHD_ITC_SOCKETPAIR_)

/* **************** ITC implementation by socket pair ********** */

#  include "mhd_sockets_macros.h"
#  if ! defined(mhd_socket_pair_nblk)
#    include "mhd_sockets_funcs.h"
#  endif

/**
 * Number of FDs used by every ITC.
 */
#  define mhd_ITC_NUM_FDS (2)

/**
 * Set @a itc to the invalid value.
 * @param pitc the pointer to the itc to set
 */
#  define mhd_itc_set_invalid(pitc) \
        ((pitc)->sk[0] = (pitc)->sk[1] = MHD_INVALID_SOCKET)

/**
 * Check whether ITC has valid value.
 *
 * Macro check whether @a itc value is valid (allowed),
 * macro does not check whether @a itc was really initialised.
 * @param itc the itc to check
 * @return boolean true if @a itc has valid value,
 *         boolean false otherwise.
 */
#  define mhd_ITC_IS_VALID(itc)  (MHD_INVALID_SOCKET != (itc).sk[0])

/**
 * Initialise ITC by generating socketpair
 * @param itc the itc to initialise
 * @return non-zero if succeeded, zero otherwise
 */
#  ifdef mhd_socket_pair_nblk
#    define mhd_itc_init(pitc) mhd_socket_pair_nblk ((pitc)->sk)
#  else  /* ! mhd_socket_pair_nblk */
#    define mhd_itc_init(pitc)                \
        ( (! mhd_socket_pair ((pitc)->sk)) ?        \
          (0) : ( (! mhd_itc_nonblocking ((pitc))) ? \
                  (mhd_itc_destroy (*(pitc)), 0) : (! 0) ) )

/**
 * Change itc FD options to be non-blocking.
 *
 * @param pitc the pointer to ITC to manipulate
 * @return true if succeeded, false otherwise
 */
#    define mhd_itc_nonblocking(pitc)         \
        (mhd_socket_nonblocking ((pitc)->sk[0]) &&  \
         mhd_socket_nonblocking ((pitc)->sk[1]))

#  endif /* ! mhd_socket_pair_nblk */

/**
 * Activate signal on @a itc
 * @param itc the itc to use
 * @return non-zero if succeeded, zero otherwise
 */
#  define mhd_itc_activate(itc) \
        ((0 < mhd_sys_send ((itc).sk[1], "", 1)) || mhd_SCKT_LERR_IS_EAGAIN ())

/**
 * Return read FD of @a itc which can be used for poll(), select() etc.
 * @param itc the itc to get FD
 * @return FD of read side
 */
#  define mhd_itc_r_fd(itc) ((itc).sk[0])

/**
 * Clear signaled state on @a itc
 * @param itc the itc to clear
 */
#  define mhd_itc_clear(itc) do                                   \
        { long __b;                                                     \
          while (0 < recv ((itc).sk[0], (void*) &__b, sizeof(__b), 0))  \
          {(void) 0;} } while (0)

/**
 * Destroy previously initialised ITC
 * @param itc the itc to destroy
 * @return non-zero if succeeded, zero otherwise
 */
#  define mhd_itc_destroy(itc)       \
        (mhd_socket_close ((itc).sk[1]) ?  \
         mhd_socket_close ((itc).sk[0]) :  \
         ((void) mhd_socket_close ((itc).sk[0]), ! ! 0) )

#endif /* MHD_ITC_SOCKETPAIR_ */

/**
 * Destroy previously initialised ITC and abort execution
 * if error is detected.
 * @param itc the itc to destroy
 */
#define mhd_itc_destroy_chk(itc) do {          \
          if (! mhd_itc_destroy (itc))               \
          MHD_PANIC ("Failed to destroy ITC.\n");  \
} while (0)

/**
 * Check whether ITC has invalid value.
 *
 * Macro check whether @a itc value is invalid,
 * macro does not check whether @a itc was destroyed.
 * @param itc the itc to check
 * @return boolean true if @a itc has invalid value,
 *         boolean false otherwise.
 */
#define mhd_ITC_IS_INVALID(itc)  (! mhd_ITC_IS_VALID (itc))

#endif /* ! MHD_ITC_H */
