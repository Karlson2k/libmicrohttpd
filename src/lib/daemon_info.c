
/**
 * Obtain information about the given daemon
 * (not fully implemented!).
 *
 * @param daemon what daemon to get information about
 * @param info_type what information is desired?
 * @param ... depends on @a info_type
 * @return NULL if this information is not available
 *         (or if the @a info_type is unknown)
 * @ingroup specialized
 */
const union MHD_DaemonInfo *
MHD_get_daemon_info (struct MHD_Daemon *daemon,
		     enum MHD_DaemonInfoType info_type,
		     ...)
{
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
}


