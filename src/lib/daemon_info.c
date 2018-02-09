/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2018 Daniel Pittman and Christian Grothoff

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
 * @file lib/daemon_info.c
 * @brief implementation of MHD_daemon_get_information_sz()
 * @author Christian Grothoff
 */
#include "internal.h"


/**
 * Obtain information about the given daemon.
 * Use wrapper macro #MHD_daemon_get_information() instead of direct use
 * of this function.
 *
 * @param daemon what daemon to get information about
 * @param info_type what information is desired?
 * @param[out] return_value pointer to union where requested information will
 *                          be stored
 * @param return_value_size size of union MHD_DaemonInformation at compile
 *                          time
 * @return #MHD_YES on success, #MHD_NO on error
 *         (@a info_type is unknown, NULL pointer etc.)
 * @ingroup specialized
 */
enum MHD_Bool
MHD_daemon_get_information_sz (struct MHD_Daemon *daemon,
			       enum MHD_DaemonInformationType info_type,
			       union MHD_DaemonInformation *return_value,
			       size_t return_value_size)
{
#if OLD
  if (NULL == daemon)
    return NULL;
  switch (info_type)
    {
    case MHD_DAEMON_INFO_KEY_SIZE:
      return NULL; /* no longer supported */
    case MHD_DAEMON_INFO_MAC_KEY_SIZE:
      return NULL; /* no longer supported */
    case MHD_DAEMON_INFO_LISTEN_FD:
      return (const union MHD_DaemonInfo *) &daemon->listen_fd;
#ifdef EPOLL_SUPPORT
    case MHD_DAEMON_INFO_EPOLL_FD:
      return (const union MHD_DaemonInfo *) &daemon->epoll_fd;
#endif
    case MHD_DAEMON_INFO_CURRENT_CONNECTIONS:
      if (0 == (daemon->options & MHD_USE_INTERNAL_POLLING_THREAD))
        {
          /* Assume that MHD_run() in not called in other thread
           * at the same time. */
          MHD_cleanup_connections (daemon);
        }
      else if (daemon->worker_pool)
        {
          unsigned int i;
          /* Collect the connection information stored in the workers. */
          daemon->connections = 0;
          for (i = 0; i < daemon->worker_pool_size; i++)
            {
              /* FIXME: next line is thread-safe only if read is atomic. */
              daemon->connections += daemon->worker_pool[i].connections;
            }
        }
      return (const union MHD_DaemonInfo *) &daemon->connections;
    case MHD_DAEMON_INFO_FLAGS:
      return (const union MHD_DaemonInfo *) &daemon->options;
    case MHD_DAEMON_INFO_BIND_PORT:
      return (const union MHD_DaemonInfo *) &daemon->port;
    default:
      return NULL;
    }
#else
  return MHD_NO;
#endif
}

/* end of daemon_info.c */
