/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2025 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/daemon_event_update.c
 * @brief  The implementation of MHD_daemon_event_update() function for external
 *         events updates
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

#include "mhd_assert.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"

#include "daemon_logger.h"

#ifdef mhd_DEBUG_POLLING_FDS
#  include "mhd_itc.h"
#  include <stdio.h>
#endif /* mhd_DEBUG_POLLING_FDS */

#include "mhd_public_api.h"

MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2) void
MHD_daemon_event_update (
  struct MHD_Daemon *MHD_RESTRICT daemon,
  struct MHD_EventUpdateContext *MHD_RESTRICT ecb_cntx,
  enum MHD_FdState fd_current_state)
{
  bool broken_app_data;
  bool unneeded_event;

  if (mhd_DAEMON_STATE_STARTED > daemon->state)
    return;
  if (! mhd_WM_INT_HAS_EXT_EVENTS (daemon->wmode_int))
    return;  /* FIXME: log error? */
  if (mhd_DAEMON_STATE_STARTED < daemon->state)
    return;

#ifdef mhd_DEBUG_POLLING_FDS
  if (1)
  {
    char state_str[] = "x:x:x";
    state_str[0] = MHD_FD_STATE_IS_SET_RECV (fd_current_state) ? 'R' : '-';
    state_str[2] = MHD_FD_STATE_IS_SET_SEND (fd_current_state) ? 'W' : '-';
    state_str[4] = MHD_FD_STATE_IS_SET_EXCEPT (fd_current_state) ? 'E' : '-';

    switch ((mhd_SockRelMarker) ecb_cntx)
    {
    case mhd_SOCKET_REL_MARKER_EMPTY:
      fprintf (stderr,
               "### MHD_daemon_event_update(daemon, [unknown],   %s)\n",
               state_str);
      break;
    case mhd_SOCKET_REL_MARKER_ITC:
      fprintf (stderr,
               "### MHD_daemon_event_update(daemon, [ITC:  %llu], %s)\n",
               (unsigned long long) mhd_itc_r_fd (daemon->threading.itc),
               state_str);
      break;
    case mhd_SOCKET_REL_MARKER_LISTEN:
      fprintf (stderr,
               "### MHD_daemon_event_update(daemon, [lstn: %llu], %s)\n",
               (unsigned long long) daemon->net.listen.fd,
               state_str);
      break;
    default:
      fprintf (stderr,
               "### MHD_daemon_event_update(daemon, [conn: %llu], %s)\n",
               (unsigned long long)
               (((struct MHD_Connection *) ecb_cntx)->sk.fd),
               state_str);
      break;
    }
  }
#endif /* mhd_DEBUG_POLLING_FDS */

  broken_app_data = false;
  unneeded_event = false;

  switch ((mhd_SockRelMarker) ecb_cntx)
  {
  case mhd_SOCKET_REL_MARKER_EMPTY:
    broken_app_data = true;
    break;
  case mhd_SOCKET_REL_MARKER_ITC:
#ifdef MHD_SUPPORT_THREADS
    if (MHD_FD_STATE_IS_SET_EXCEPT (fd_current_state))
      daemon->events.data.extr.itc_data.is_broken = true;
    else
    {
      daemon->events.data.extr.itc_data.is_active =
        MHD_FD_STATE_IS_SET_RECV (fd_current_state);
      unneeded_event = MHD_FD_STATE_IS_SET_SEND (fd_current_state);
    }
#else  /* ! MHD_SUPPORT_THREADS */
    broken_app_data = true;
#endif /* ! MHD_SUPPORT_THREADS */
    break;
  case mhd_SOCKET_REL_MARKER_LISTEN:
    if (MHD_INVALID_SOCKET == daemon->net.listen.fd)
      broken_app_data = true;
    else if (MHD_FD_STATE_IS_SET_EXCEPT (fd_current_state))
      daemon->net.listen.is_broken = true;
    else
    {
      daemon->events.accept_pending =
        MHD_FD_STATE_IS_SET_RECV (fd_current_state);
      unneeded_event = MHD_FD_STATE_IS_SET_SEND (fd_current_state);
    }
    break;
  default:
    if (((struct MHD_Connection *) ecb_cntx)->daemon != daemon)
      broken_app_data = true;
    else
    {
      struct MHD_Connection *const c = ((struct MHD_Connection *) ecb_cntx);
      unsigned int err_flag;

      mhd_assert (MHD_FD_STATE_NONE != c->extr_event.reg_for);

      unneeded_event = (0 != ((~((unsigned int) c->extr_event.reg_for))
                              & ((unsigned int) fd_current_state)));

      /* Preserve connection's "error flag" */
      err_flag = (((unsigned int) c->sk.ready)
                  & (unsigned int) mhd_SOCKET_NET_STATE_ERROR_READY);

      c->sk.ready =
        (enum mhd_SocketNetState)
        (err_flag | (((unsigned int) fd_current_state)
                     & ((unsigned int) c->extr_event.reg_for)));
    }
    break;
  }

  if (broken_app_data)
  {
    mhd_LOG_MSG (daemon, \
                 MHD_SC_EXTR_EVENT_BROKEN_DATA, \
                 "MHD_daemon_event_update() is called with broken content " \
                 "data");
  }
  else if (unneeded_event)
  {
    mhd_LOG_MSG (daemon, \
                 MHD_SC_EXTR_EVENT_BROKEN_DATA, \
                 "MHD_daemon_event_update() is called with status that has " \
                 "not been requested");
  }
}
