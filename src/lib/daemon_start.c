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
 * @file lib/daemon.c
 * @brief functions to start a daemon
 * @author Christian Grothoff
 */
#include "internal.h"

/* ************************* event loops ********************** */



/* TODO: migrate! */


/* ************* Functions for MHD_daemon_start() ************ */


/**
 * Set listen socket options to allow port rebinding (or not)
 * depending on how MHD was configured.
 *
 * @param daemon[in,out] the daemon with the listen socket to configure
 * @return #MHD_SC_OK on success (or non-fatal errors)
 */
static enum MHD_StatusCode
configure_listen_reuse (struct MHD_Daemon *daemon)
{
  const MHD_SCKT_OPT_BOOL_ on = 1;

  /* Apply the socket options according to
     listening_address_reuse. */
  /* FIXME: used to be -1/0/1, now defined as a bool! 
     MISMATCH! */
  if (0 == daemon->listening_address_reuse)
    {
#ifndef MHD_WINSOCK_SOCKETS
      /* No user requirement, use "traditional" default SO_REUSEADDR
       * on non-W32 platforms, and do not fail if it doesn't work.
       * Don't use it on W32, because on W32 it will allow multiple
       * bind to the same address:port, like SO_REUSEPORT on others. */
      if (0 > setsockopt (listen_fd,
			  SOL_SOCKET,
			  SO_REUSEADDR,
			  (void*) &on, sizeof (on)))
	{
#ifdef HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED,
		    _("setsockopt failed: %s\n"),
		    MHD_socket_last_strerr_ ());
#endif
	}
#endif /* ! MHD_WINSOCK_SOCKETS */
      return MHD_SC_OK;
    }
  if (daemon->listening_address_reuse > 0)
    {
      /* User requested to allow reusing listening address:port. */
#ifndef MHD_WINSOCK_SOCKETS
      /* Use SO_REUSEADDR on non-W32 platforms, and do not fail if
       * it doesn't work. */
      if (0 > setsockopt (listen_fd,
			  SOL_SOCKET,
			  SO_REUSEADDR,
			  (void*)&on, sizeof (on)))
	{
#ifdef HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED,
		    _("setsockopt failed: %s\n"),
		    MHD_socket_last_strerr_ ());
#endif
	  return MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED;
	}
#endif /* ! MHD_WINSOCK_SOCKETS */
      /* Use SO_REUSEADDR on Windows and SO_REUSEPORT on most platforms.
       * Fail if SO_REUSEPORT is not defined or setsockopt fails.
       */
      /* SO_REUSEADDR on W32 has the same semantics
	 as SO_REUSEPORT on BSD/Linux */
#if defined(MHD_WINSOCK_SOCKETS) || defined(SO_REUSEPORT)
      if (0 > setsockopt (listen_fd,
			  SOL_SOCKET,
#ifndef MHD_WINSOCK_SOCKETS
			  SO_REUSEPORT,
#else  /* MHD_WINSOCK_SOCKETS */
			  SO_REUSEADDR,
#endif /* MHD_WINSOCK_SOCKETS */
			  (void *) &on,
			  sizeof (on)))
	{
#ifdef HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED,
		    _("setsockopt failed: %s\n"),
		    MHD_socket_last_strerr_ ());
#endif
	  return MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_FAILED;
	}
#else  /* !MHD_WINSOCK_SOCKETS && !SO_REUSEPORT */
      /* we're supposed to allow address:port re-use, but
	 on this platform we cannot; fail hard */
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_NOT_SUPPORTED,
		_("Cannot allow listening address reuse: SO_REUSEPORT not defined\n"));
#endif
      return MHD_SC_LISTEN_ADDRESS_REUSE_ENABLE_NOT_SUPPORTED;
#endif /* !MHD_WINSOCK_SOCKETS && !SO_REUSEPORT */
    }

  /* if (daemon->listening_address_reuse < 0) */
  /* User requested to disallow reusing listening address:port.
   * Do nothing except for Windows where SO_EXCLUSIVEADDRUSE
   * is used and Solaris with SO_EXCLBIND.
   * Fail if MHD was compiled for W32 without SO_EXCLUSIVEADDRUSE
   * or setsockopt fails.
   */
#if (defined(MHD_WINSOCK_SOCKETS) && defined(SO_EXCLUSIVEADDRUSE)) ||	\
  (defined(__sun) && defined(SO_EXCLBIND))
  if (0 > setsockopt (listen_fd,
		      SOL_SOCKET,
#ifdef SO_EXCLUSIVEADDRUSE
		      SO_EXCLUSIVEADDRUSE,
#else  /* SO_EXCLBIND */
		      SO_EXCLBIND,
#endif /* SO_EXCLBIND */
		      (void *) &on,
		      sizeof (on)))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_LISTEN_ADDRESS_REUSE_DISABLE_FAILED,
		_("setsockopt failed: %s\n"),
		MHD_socket_last_strerr_ ());
#endif
      return MHD_SC_LISTEN_ADDRESS_REUSE_DISABLE_FAILED;
    }
#elif defined(MHD_WINSOCK_SOCKETS) /* SO_EXCLUSIVEADDRUSE not defined on W32? */
#ifdef HAVE_MESSAGES
  MHD_DLOG (daemon,
	    MHD_SC_LISTEN_ADDRESS_REUSE_DISABLE_NOT_SUPPORTED,
	    _("Cannot disallow listening address reuse: SO_EXCLUSIVEADDRUSE not defined\n"));
#endif
  return MHD_SC_LISTEN_ADDRESS_REUSE_DISABLE_NOT_SUPPORTED;
#endif /* MHD_WINSOCK_SOCKETS */
  return MHD_SC_OK;
}


/**
 * Open, configure and bind the listen socket (if required).
 *
 * @param daemon[in,out] daemon to open the socket for
 * @return #MHD_SC_OK on success
 */
static enum MHD_StatusCode
open_listen_socket (struct MHD_Daemon *daemon)
{
  enum MHD_StatusCode sc;
  socklen_t addrlen;
  struct sockaddr_storage ss;
  const struct sockaddr *sa;
  int pf;
  bool use_v6;
      
  if (MHD_INVALID_SOCKET != daemon->listen_fd)
    return MHD_SC_OK; /* application opened it for us! */

  /* Determine address family */
  if (MHD_AF_NONE != daemon->address_family)
    {
      switch (daemon->address_family)
	{
	case MHD_AF_NONE:
	  abort ();
	case MHD_AF_AUTO:
#if HAVE_INET6
	  pf = PF_INET6;
	  use_v6 = true;
#else
	  pf = PF_INET;
	  use_v6 = false;
#endif
	  break;
	case MHD_AF_INET:
	  use_v6 = false;
	  pf = PF_INET;
	  break;
	case MHD_AF_INET6:
	case MHD_AF_DUAL:
#if HAVE_INET6
	  pf = PF_INET6;
	  use_v6 = true;
	  break;
#else
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
		    MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD,
                    _("IPv6 not supported by this build\n"));
#endif
	  return MHD_SC_IPV6_NOT_SUPPORTED_BY_BUILD;
#endif
	}
    }
  else if (0 != daemon->listen_sa_len)
    {
      
      /* we have a listen address, get AF from there! */
      switch (daemon->listen_sa.ss_family)
      {
      case AF_INET:
	pf = PF_INET;
	use_v6 = false;
	break;
#ifdef AF_INET6
      case AF_INET6:
	pf = PF_INET6;
	use_v6 = true;
	break;
#endif
#ifdef AF_UNIX
      case AF_UNIX:
	pf = PF_UNIX;
	use_v6 = false;
#endif
      default:
	return MHD_SC_AF_NOT_SUPPORTED_BY_BUILD;
      }
    }
  else
    {
      /* no listening desired, that's OK */
      return MHD_SC_OK;
    }
  
  /* try to open listen socket */
 try_open_listen_socket:
  daemon->listen_socket = MHD_socket_create_listen_(pf);
  if ( (MHD_INVALID_SOCKET == daemon->listen_socket) &&
       (MHD_AF_AUTO == daemon->address_family) &&
       (use_v6) )
    {
      use_v6 = false;
      pf = PF_INET;
      goto try_open_listen_socket;
    }
  if (MHD_INVALID_SOCKET == daemon->listen_socket) 
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_FAILED_TO_OPEN_LISTEN_SOCKET,
		_("Failed to create socket for listening: %s\n"),
		MHD_socket_last_strerr_ ());
#endif
      return MHD_SC_FAILED_TO_OPEN_LISTEN_SOCKET;
    }

  if (MHD_SC_OK !=
      (sc = configure_listen_reuse (daemon)))
    return sc;

  /* configure for dual stack (or not) */
  if (use_v6)
    {
#if defined IPPROTO_IPV6 && defined IPV6_V6ONLY
      /* Note: "IPV6_V6ONLY" is declared by Windows Vista ff., see "IPPROTO_IPV6 Socket Options"
	 (http://msdn.microsoft.com/en-us/library/ms738574%28v=VS.85%29.aspx);
	 and may also be missing on older POSIX systems; good luck if you have any of those,
	 your IPv6 socket may then also bind against IPv4 anyway... */
      const MHD_SCKT_OPT_BOOL_ v6_only =
	(MHD_AF_INET6 == daemon->address_family);
      if (0 > setsockopt (listen_fd,
			  IPPROTO_IPV6,
			  IPV6_V6ONLY,
			  (const void *) &v6_only,
			  sizeof (v6_only)))
	{
#ifdef HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_FAILED,
		    _("setsockopt failed: %s\n"),
		    MHD_socket_last_strerr_ ());
#endif
	}
#else
#ifdef HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    MHD_SC_LISTEN_DUAL_STACK_CONFIGURATION_NOT_SUPPORTED,
		    _("Cannot explicitly setup dual stack behavior on this platform\n"));
#endif
#endif
    }
  
  /* Determine address to bind to */
  if (0 != daemon->listen_sa_len)
    {
      /* Bind address explicitly given */
      sa = daemon->listen_sa;
      addrlen = daemon->listen_sa_len;
    }
  else
    {
      /* Compute bind address based on port and AF */
#if HAVE_INET6
      if (use_v6)
	{
#ifdef IN6ADDR_ANY_INIT
	  static const struct in6_addr static_in6any = IN6ADDR_ANY_INIT;
#endif
	  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;

	  addrlen = sizeof (struct sockaddr_in6);
	  memset (sin6,
		  0,
		  sizeof (struct sockaddr_in6));
	  sin6->sin6_family = AF_INET6;
	  sin6->sin6_port = htons (daemon->listen_port);
#ifdef IN6ADDR_ANY_INIT
	  sin6->sin6_addr = static_in6any;
#endif
#if HAVE_SOCKADDR_IN_SIN_LEN
	  sin6->sin6_len = sizeof (struct sockaddr_in6);
#endif
	}
      else
#endif
	{
	  struct sockaddr_in *sin4 = (struct sockaddr_in *) &ss;

	  addrlen = sizeof (struct sockaddr_in);
	  memset (sin4,
		  0,
		  sizeof (struct sockaddr_in));
	  sin4->sin_family = AF_INET;
	  sin4->sin_port = htons (daemon->listen_port);
	  if (0 != INADDR_ANY)
	    sin4->sin_addr.s_addr = htonl (INADDR_ANY);
#if HAVE_SOCKADDR_IN_SIN_LEN
	  sin4->sin_len = sizeof (struct sockaddr_in);
#endif
	}
      sa = (const struct sockaddr *) ss;
    }
      
  /* actually do the bind() */    
  if (-1 == bind (daemon->listen_socket,
		  sa,
		  addrlen))
    {
#ifdef HAVE_MESSAGES
      unsigned int port = 0;

      switch (sa->sa_family)
	{
	case AF_INET:
	  if (addrlen == sizeof (struct sockaddr_in))
	    port = ntohs (((const struct sockaddr_in*)sa)->sin_port);
	  else
	    port = UINT16_MAX + 1; /* indicate size error */
	  break;
	case AF_INET6:
	  if (addrlen == sizeof (struct sockaddr_in6))
	    port = ntohs (((const struct sockaddr_in6*)sa)->sin_port);
	  else
	    port = UINT16_MAX + 1; /* indicate size error */
	  break;
	default:
	  port = UINT_MAX; /* AF_UNIX? */
	  break;
	}
      MHD_DLOG (daemon,
		MHD_SC_LISTEN_SOCKET_BIND_FAILED,
		_("Failed to bind to port %u: %s\n"),
		port,
		MHD_socket_last_strerr_ ());
#endif
      return MHD_SC_LISTEN_SOCKET_BIND_FAILED;
    }

  /* setup TCP_FASTOPEN */
#ifdef TCP_FASTOPEN
  if (MHD_FOM_DISABLE != daemon->fast_open_method)
    {
      if (0 != setsockopt (daemon->listen_socket,
			   IPPROTO_TCP,
			   TCP_FASTOPEN,
			   &daemon->fastopen_queue_size,
			   sizeof (daemon->fastopen_queue_size)))
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
		    MHD_SC_FAST_OPEN_FAILURE,
                    _("setsockopt failed: %s\n"),
                    MHD_socket_last_strerr_ ());
#endif
	  if (MHD_FOM_REQUIRE == daemon->fast_open_method)
	    return MHD_SC_FAST_OPEN_FAILURE;
        }
      }
#endif

  /* setup listening */
  if (0 > listen (daemon->listen_socket,
                  daemon->listen_backlog_size))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_LISTEN_FAILURE,
		_("Failed to listen for connections: %s\n"),
		MHD_socket_last_strerr_ ());
#endif
      return MHD_SC_LISTEN_FAILURE;
    }
  return MHD_SC_OK;
}


/** 
 * Obtain the listen port number from the socket (if it
 * was not explicitly set by us, i.e. if we were given
 * a listen socket or if the port was 0 and the OS picked
 * a free one).
 *
 * @param daemon[in,out] daemon to obtain the port number for
 */
static void
get_listen_port_number (struct MHD_Daemon *daemon)
{
  struct sockaddr_storage servaddr;
  socklen_t addrlen;
  
  if ( (0 != daemon->port) ||
       (MHD_INVALID_SOCKET == daemon->listen_socket) )
    return; /* nothing to be done */

  memset (&servaddr,
	  0,
	  sizeof (struct sockaddr_storage));
  addrlen = sizeof (servaddr);
  if (0 != getsockname (daemon->listen_socket,
			(struct sockaddr *) &servaddr,
			&addrlen))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_LISTEN_PORT_INTROSPECTION_FAILURE,
		_("Failed to get listen port number: %s\n"),
		MHD_socket_last_strerr_ ());
#endif /* HAVE_MESSAGES */
      return;
    }
#ifdef MHD_POSIX_SOCKETS
  if (sizeof (servaddr) < addrlen)
    {
      /* should be impossible with `struct sockaddr_storage` */
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_LISTEN_PORT_INTROSPECTION_FAILURE,
		_("Failed to get listen port number (`struct sockaddr_storage` too small!?)\n"));
#endif /* HAVE_MESSAGES */
      return;
    }
#endif /* MHD_POSIX_SOCKETS */
  switch (servaddr.ss_family)
    {
    case AF_INET:
      {
	struct sockaddr_in *s4 = (struct sockaddr_in *) &servaddr;
	
	daemon->port = ntohs (s4->sin_port);
	break;
      }
#ifdef HAVE_INET6
    case AF_INET6:
      {
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) &servaddr;
	
	daemon->port = ntohs(s6->sin6_port);
	break;
      }
#endif /* HAVE_INET6 */
#ifdef AF_UNIX
    case AF_UNIX:
      daemon->port = 0; /* special value for UNIX domain sockets */
      break;
#endif
    default:
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_LISTEN_PORT_INTROSPECTION_UNKNOWN_AF,
		_("Unknown address family!\n"));
#endif
      daemon->port = 0; /* ugh */
      break;
    }
}


/**
 * Setup epoll() FD for the daemon and initialize it to listen
 * on the listen FD.
 * @remark To be called only from thread that process
 * daemon's select()/poll()/etc.
 *
 * @param daemon daemon to initialize for epoll()
 * @return #MHD_SC_OK on success
 */
static enum MHD_StatusCode
setup_epoll_to_listen (struct MHD_Daemon *daemon)
{
  struct epoll_event event;
  MHD_socket ls;

  /* FIXME: update function! */
  daemon->epoll_fd = setup_epoll_fd (daemon);
  if (-1 == daemon->epoll_fd)
    return MHD_NO;
#if defined(HTTPS_SUPPORT) && defined(UPGRADE_SUPPORT)
  if (0 != (MHD_ALLOW_UPGRADE & daemon->options))
    {
       daemon->epoll_upgrade_fd = setup_epoll_fd (daemon);
       if (MHD_INVALID_SOCKET == daemon->epoll_upgrade_fd)
         return MHD_NO;
    }
#endif /* HTTPS_SUPPORT && UPGRADE_SUPPORT */
  if ( (MHD_INVALID_SOCKET == (ls = daemon->listen_fd)) ||
       (daemon->was_quiesced) )
    return MHD_YES; /* non-listening daemon */
  event.events = EPOLLIN;
  event.data.ptr = daemon;
  if (0 != epoll_ctl (daemon->epoll_fd,
		      EPOLL_CTL_ADD,
		      ls,
		      &event))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("Call to epoll_ctl failed: %s\n"),
                MHD_socket_last_strerr_ ());
#endif
      return MHD_NO;
    }
  daemon->listen_socket_in_epoll = true;
  if (MHD_ITC_IS_VALID_(daemon->itc))
    {
      event.events = EPOLLIN;
      event.data.ptr = (void *) epoll_itc_marker;
      if (0 != epoll_ctl (daemon->epoll_fd,
                          EPOLL_CTL_ADD,
                          MHD_itc_r_fd_ (daemon->itc),
                          &event))
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
                    _("Call to epoll_ctl failed: %s\n"),
                    MHD_socket_last_strerr_ ());
#endif
          return MHD_NO;
        }
    }
  return MHD_SC_OK;
}
#endif


/**
 * Thread that runs the polling loop until the daemon
 * is explicitly shut down.
 *
 * @param cls `struct MHD_Deamon` to run select loop in a thread for
 * @return always 0 (on shutdown)
 */
static MHD_THRD_RTRN_TYPE_ MHD_THRD_CALL_SPEC_
MHD_polling_thread (void *cls)
{
  struct MHD_Daemon *daemon = cls;

  MHD_thread_init_ (&daemon->pid);
  while (! daemon->shutdown)
    {
      switch (daemon->event_loop_syscall)
      {
      case MHD_ELS_AUTO:
	MHD_PANIC ("MHD_ELS_AUTO should have been mapped to preferred style");
	break;
      case MHD_ELS_SELECT:
	MHD_select (daemon,
		    MHD_YES);
	break;
      case MHD_ELS_POLL:
	MHD_poll (daemon,
		  MHD_YES);
	break;
      case MHD_ELS_EPOLL:
#ifdef EPOLL_SUPPORT	
	MHD_epoll (daemon,
		   MHD_YES);
#else
	MHD_PANIC ("MHD_ELS_EPOLL not supported, should have failed earlier");
#endif
	break;
      }
      MHD_cleanup_connections (daemon);
    }
  /* Resume any pending for resume connections, join
   * all connection's threads (if any) and finally cleanup
   * everything. */
  close_all_connections (daemon);

  return (MHD_THRD_RTRN_TYPE_)0;
}


/**
 * Setup the thread pool (if needed).
 *
 * @param daemon[in,out] daemon to setup thread pool for
 * @return #MHD_SC_OK on success
 */
static enum MHD_StatusCode
setup_thread_pool (struct MHD_Daemon *daemon)
{
  /* Coarse-grained count of connections per thread (note error
   * due to integer division). Also keep track of how many
   * connections are leftover after an equal split. */
  unsigned int conns_per_thread = daemon->global_connection_limit
    / daemon->threading_model;
  unsigned int leftover_conns = daemon->global_connection_limit
    % daemon->threading_model;
  unsigned int i;
  enum MHD_StatusCode sc;

  /* Allocate memory for pooled objects */
  daemon->worker_pool = MHD_calloc_ (daemon->threading_model,
				     sizeof (struct MHD_Daemon));
  if (NULL == daemon->worker_pool)
    return MHD_SC_THREAD_POOL_MALLOC_FAILURE;
  
  /* Start the workers in the pool */
  for (i = 0; i < daemon->threading_model; i++)
    {
      /* Create copy of the Daemon object for each worker */
      struct MHD_Daemon *d = &daemon->worker_pool[i];
      
      memcpy (d,
	      daemon,
	      sizeof (struct MHD_Daemon));
      /* Adjust pooling params for worker daemons; note that memcpy()
	 has already copied MHD_USE_INTERNAL_POLLING_THREAD thread model into
	 the worker threads. */
      d->master = daemon;
      d->worker_pool_size = 0;
      d->worker_pool = NULL;
      /* Divide available connections evenly amongst the threads.
       * Thread indexes in [0, leftover_conns) each get one of the
       * leftover connections. */
      d->global_connection_limit = conns_per_thread;
      if (i < leftover_conns)
	++d->global_connection_limit;
	  
      if (! daemon->disable_itc)	
	{
	  if (! MHD_itc_init_ (d->itc))
	    {
#ifdef HAVE_MESSAGES
	      MHD_DLOG (daemon,
			MHD_SC_ITC_INITIALIZATION_FAILED,
			_("Failed to create worker inter-thread communication channel: %s\n"),
			MHD_itc_last_strerror_() );
#endif
	      sc = MHD_SC_ITC_INITIALIZATION_FAILED;
	      goto thread_failed;
	    }
	  if ( (MHD_ELS_SELECT == daemon->event_loop_syscall) &&
	       (! MHD_SCKT_FD_FITS_FDSET_(MHD_itc_r_fd_ (d->itc),
					  NULL)) )
	    {
#ifdef HAVE_MESSAGES
	      MHD_DLOG (daemon,
			MHD_SC_ITC_DESCRIPTOR_TOO_LARGE,
			_("File descriptor for inter-thread communication channel exceeds maximum value\n"));
#endif
	      MHD_itc_destroy_chk_ (d->itc);
	      sc = MHD_SC_ITC_DESCRIPTOR_TOO_LARGE;
	      goto thread_failed;
	    }
	}
      else
	{
	  MHD_itc_set_invalid_ (d->itc);
	}
      
#ifdef EPOLL_SUPPORT
      if ( (MHD_ELS_EPOLL == daemon->event_loop_syscall) &&
	   (MHD_SC_OK != (sc = setup_epoll_to_listen (d))) )
	goto thread_failed;
#endif
      
      /* Must init cleanup connection mutex for each worker */
      if (! MHD_mutex_init_ (&d->cleanup_connection_mutex))
	{
#ifdef HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    MHD_SC_THREAD_POOL_CREATE_MUTEX_FAILURE,
		    _("MHD failed to initialize cleanup connection mutex\n"));
#endif
	  if (! daemon->disable_itc)
	    MHD_itc_destroy_chk_ (d->itc);
	  sc = MHD_SC_THREAD_POOL_CREATE_MUTEX_FAILURE;
	  goto thread_failed;
	}
      
      /* Spawn the worker thread */
      if (! MHD_create_named_thread_ (&d->pid,
				      "MHD-worker",
				      daemon->thread_stack_size,
				      &MHD_polling_thread,
				      d))
	{
#ifdef HAVE_MESSAGES
	  MHD_DLOG (daemon,
		    MHD_SC_THREAD_POOL_LAUNCH_FAILURE,
		    _("Failed to create pool thread: %s\n"),
		    MHD_strerror_ (errno));
#endif
	  sc = MHD_SC_THREAD_POOL_LAUNCH_FAILURE;
	  /* Free memory for this worker; cleanup below handles
	   * all previously-created workers. */
	  if (! daemon->disable_itc)
	    MHD_itc_destroy_chk_ (d->itc);
	  MHD_mutex_destroy_chk_ (&d->cleanup_connection_mutex);
	  goto thread_failed;
	}
    } /* end for() */
  return MHD_SC_OK;

thread_failed:
  /* If no worker threads created, then shut down normally. Calling
     MHD_stop_daemon (as we do below) doesn't work here since it
     assumes a 0-sized thread pool means we had been in the default
     MHD_USE_INTERNAL_POLLING_THREAD mode. */
  if (0 == i)
    {
      if (NULL != daemon->worker_pool)
	{
	  free (daemon->worker_pool);
	  daemon->worker_pool = NULL;
	}
      return MHD_SC_THREAD_LAUNCH_FAILURE;
    }
  /* Shutdown worker threads we've already created. Pretend
     as though we had fully initialized our daemon, but
     with a smaller number of threads than had been
     requested. */
  daemon->worker_pool_size = i;
  daemon->listen_socket = MHD_daemon_quiesce (daemon);
  return MHD_SC_THREAD_LAUNCH_FAILURE;
}


/**
 * Start a webserver.
 *
 * @param daemon daemon to start; you can no longer set
 *        options on this daemon after this call!
 * @return #MHD_SC_OK on success
 * @ingroup event
 */
enum MHD_StatusCode
MHD_daemon_start (struct MHD_Daemon *daemon)
{
  enum MHD_StatusCode sc;

  if (MHD_ELS_AUTO == daemon->event_loop_syscall)
    {
#if EPOLL_SUPPORT
      /* We do not support thread-per-connection in combination
	 with epoll, so use poll in this case, otherwise prefer
	 epoll. */
      if (MHD_TM_THREAD_PER_CONNECTION == daemon->threading_model)
	daemon->event_loop_syscall = MHD_ELS_POLL;
      else
	daemon->event_loop_syscall = MHD_ELS_EPOLL;
#elif HAVE_POLL
      daemon->event_loop_syscall = MHD_ELS_POLL;
#else
      daemon->event_loop_syscall = MHD_ELS_SELECT;
#endif
    }

#ifdef EPOLL_SUPPORT
  if ( (MHD_ELS_EPOLL == daemon->event_loop_syscall) &&
       (0 == daemon->worker_pool_size) &&
       (MHD_INVALID_SOCKET != daemon->listen_socket) &&
       (MHD_TM_THREAD_PER_CONNECTION == daemon->threading_model) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_SYSCALL_THREAD_COMBINATION_INVALID,
		_("Combining MHD_USE_THREAD_PER_CONNECTION and MHD_USE_EPOLL is not supported.\n"));
#endif
      return MHD_SC_SYSCALL_THREAD_COMBINATION_INVALID;
    }
#endif

  /* Setup ITC */
  if ( (! daemon->disable_itc) &&
       (0 == daemon->worker_pool_size) )
    {
      if (! MHD_itc_init_ (daemon->itc))
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
		    MHD_SC_ITC_INITIALIZATION_FAILED,
                    _("Failed to create inter-thread communication channel: %s\n"),
                    MHD_itc_last_strerror_ ());
#endif
          return MHD_SC_ITC_INITIALIZATION_FAILED;
        }
      if ( (MHD_ELS_SELECT == daemon->event_loop_syscall) &&
           (! MHD_SCKT_FD_FITS_FDSET_(MHD_itc_r_fd_ (daemon->itc),
                                      NULL)) )
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
		    MHD_SC_ITC_DESCRIPTOR_TOO_LARGE,
		    _("File descriptor for inter-thread communication channel exceeds maximum value\n"));
#endif
	  return MHD_SC_ITC_DESCRIPTOR_TOO_LARGE;
	}
    }
  
  if (MHD_SC_OK != (sc = open_listen_socket (daemon)))
    return sc;
  
  /* Check listen socket is in range (if we are limited) */
  if ( (MHD_INVALID_SOCKET != daemon->listen_socket) &&
       (MHD_ELS_SELECT == daemon->event_loop_syscall) &&
       (! MHD_SCKT_FD_FITS_FDSET_(daemon->listen_socket,
				  NULL)) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_LISTEN_SOCKET_TOO_LARGE,
		_("Socket descriptor larger than FD_SETSIZE: %d > %d\n"),
		daemon->listen_socket,
		FD_SETSIZE);
#endif
      return MHD_SC_LISTEN_SOCKET_TOO_LARGE;
    }
  
  /* set listen socket to non-blocking */
  if ( (MHD_INVALID_SOCKET != daemon->listen_socket) &&
       (! MHD_socket_nonblocking_ (daemon->listen_socket)) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_LISTEN_SOCKET_NONBLOCKING_FAILURE,
		_("Failed to set nonblocking mode on listening socket: %s\n"),
		MHD_socket_last_strerr_());
#endif
      if ( (MHD_ELS_EPOLL == daemon->event_loop_syscall) ||
	   (daemon->worker_pool_size > 0) )
	{
	  /* Accept must be non-blocking. Multiple children may wake
	   * up to handle a new connection, but only one will win the
	   * race.  The others must immediately return. As this is
	   * not possible, we must fail hard here. */
	  return MHD_SC_LISTEN_SOCKET_NONBLOCKING_FAILURE;
	}
    }
  
#ifdef EPOLL_SUPPORT
  /* Setup epoll */
  if ( (MHD_ELS_EPOLL == daemon->event_loop_syscall) &&
       (0 == daemon->worker_pool_size) &&
       (MHD_INVALID_SOCKET != daemon->listen_socket) &&
       (MHD_SC_OK != (sc = setup_epoll_to_listen (daemon))) )
    return sc;
#endif
     
  /* Setup main listen thread (only if we have no thread pool or
     external event loop and do have a listen socket) */
  /* FIXME: why no worker thread if we have no listen socket? */
  if ( ( (MHD_TM_THREAD_PER_CONNECTION == daemon->threading_model) ||
	 (1 == daemon->threading_model) ) &&
       (MHD_INVALID_SOCKET != daemon->listen_socket) &&
       (! MHD_create_named_thread_ (&daemon->pid,
				    (MHD_TM_THREAD_PER_CONNECTION == daemon->threading_model)
				    ? "MHD-listen"
				    : "MHD-single",
				    daemon->thread_stack_size,
				    &MHD_polling_thread,
				    daemon) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		MHD_SC_THREAD_MAIN_LAUNCH_FAILURE,
		_("Failed to create listen thread: %s\n"),
		MHD_strerror_ (errno));
#endif
      return MHD_SC_THREAD_MAIN_LAUNCH_FAILURE;
    }

  /* Setup worker threads */
  /* FIXME: why no thread pool if we have no listen socket? */
  if ( (1 < daemon->threading_model) &&
	(MHD_INVALID_SOCKET != daemon->listen_socket) &&
	(MHD_SC_OK != (sc = setup_thread_pool (daemon))) )
    return sc;
       
  return MHD_SC_OK;
}



/* end of daemon.c */
