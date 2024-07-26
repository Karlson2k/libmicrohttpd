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
 * @file src/mhd2/mhd_daemon.h
 * @brief  The header for declaration of struct MHD_Daemon
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_DAEMON_H
#define MHD_DAEMON_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

#include "mhd_socket_type.h"

#include "mhd_public_api.h"

#ifdef MHD_USE_THREADS
#  include "mhd_threads.h"
#  include "mhd_itc_types.h"
#  include "mhd_locks.h"
#endif

#include "sys_select.h"
#include "sys_poll.h"
#ifdef MHD_USE_EPOLL
#  include <sys/epoll.h>
#endif

#include "mhd_dlinked_list.h"

struct DaemonOptions; /* Forward declaration */
struct MHD_Connection; /* Forward declaration */

/**
 * The helper struct for the connections list
 */
mhd_DLINKEDL_LIST_DEF (MHD_Connection);

/**
 * The current phase of the daemon life
 */
enum MHD_FIXED_ENUM_ mhd_DaemonState
{
  /**
   * The daemon has been created, but not yet started.
   * Setting configuration options is possible.
   */
  mhd_DAEMON_STATE_NOT_STARTED = 0
  ,
  /**
   * The daemon is being started.
   */
  mhd_DAEMON_STATE_STARTING
  ,
  /**
   * The daemon has been started.
   * Normal operations.
   */
  mhd_DAEMON_STATE_STARTED
  ,
  /**
   * The daemon has failed to start
   */
  mhd_DAEMON_STATE_FAILED
  ,
  /**
   * The daemon is being stopped.
   */
  mhd_DAEMON_STATE_STOPPING
  ,
  /**
   * The daemon is stopped.
   * The state should rarely visible as daemon should be destroyed when stopped.
   */
  mhd_DAEMON_STATE_STOPPED
};


/**
 * Internal version of the daemon work mode type
 */
enum MHD_FIXED_ENUM_ mhd_WorkModeIntType
{
  /**
   * Network edge-triggered events are monitored and provided by application.
   * Receiving, sending and processing of the network data if performed when
   * special MHD function is called by application.
   * No threads managed by the daemon.
   */
  mhd_WM_INT_EXTERNAL_EVENTS_EDGE
  ,
  /**
   * Network level-triggered events are monitored and provided by application.
   * Receiving, sending and processing of the network data if performed when
   * special MHD function is called by application.
   * No threads managed by the daemon.
   */
  mhd_WM_INT_EXTERNAL_EVENTS_LEVEL
  ,
  /**
   * The daemon checks for the network events, receives, sends and process
   * the network data when special MHD function is called by application.
   * No threads managed by the daemon.
   */
  mhd_WM_INT_INTERNAL_EVENTS_NO_THREADS
  ,
  /**
   * The daemon runs its own single thread, where the daemon monitors
   * all network events, receives, sends and process the network data.
   */
  mhd_WM_INT_INTERNAL_EVENTS_ONE_THREAD
  ,
  /**
   * The daemon runs its own single thread, where the daemon monitors
   * the new incoming connections, and runs individual thread for each
   * established connection, where the daemon monitors connection, receives,
   * sends and process the network data.
   */
  mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION
  ,
  /**
   * The daemon runs its fixed number of threads, all threads monitors the
   * new incoming connections and each thread handles own subset of the network
   * connections (monitors connections network events, receives, sends and
   * process the network data).
   */
  mhd_WM_INT_INTERNAL_EVENTS_THREAD_POOL
};

/**
 * Check whether given mhd_WorkModeIntType value should have internal threads,
 * either directly controlled or indirectly, via additional workers daemons.
 */
#define mhd_WM_INT_HAS_THREADS(wm_i) \
        (mhd_WM_INT_INTERNAL_EVENTS_ONE_THREAD <= wm_i)

/**
 * Check whether given mhd_WorkModeIntType value has external events
 */
#define mhd_WM_INT_HAS_EXT_EVENTS(wm_i) \
        (mhd_WM_INT_EXTERNAL_EVENTS_LEVEL >= wm_i)


/**
 * Sockets polling internal syscalls used by MHD.
 *
 * The same value used as by #MHD_SockPollSyscall, however instead of "auto"
 * method this enum uses "not yet set" and enum is extended with an additional
 * "external" value.
 */
enum MHD_FIXED_ENUM_ mhd_IntPollType
{
  /**
   * External sockets polling is used.
   */
  mhd_POLL_TYPE_EXT = -1
  ,
  /**
   * Internal sockets polling syscall has not been selected yet.
   */
  mhd_POLL_TYPE_NOT_SET_YET = MHD_SPS_AUTO
  ,
  /**
   * Use select().
   */
  mhd_POLL_TYPE_SELECT = MHD_SPS_SELECT
  ,
  /**
   * Use poll().
   */
  mhd_POLL_TYPE_POLL = MHD_SPS_POLL
  ,
  /**
   * Use epoll.
   */
  mhd_POLL_TYPE_EPOLL = MHD_SPS_EPOLL
};

#if defined(HAVE_UINTPTR_T)
typedef uintptr_t mhd_SockRelMarker;
#else
typedef unsigned char *mhd_SockRelMarker;
#endif


#define mhd_SOCKET_REL_MARKER_EMPTY    ((mhd_SockRelMarker) 0)

#define mhd_SOCKET_REL_MARKER_ITC      ((mhd_SockRelMarker) - 1)

#define mhd_SOCKET_REL_MARKER_LISTEN   (mhd_SOCKET_REL_MARKER_ITC - 1)
/**
 * Identifier of the FD related to event
 */
union mhd_SocketRelation
{
  /**
   * Identifier of the FD.
   * Only valid when it is equal to #mhd_SOCKET_REL_MARKER_EMPTY,
   * #mhd_SOCKET_REL_MARKER_ITC or #mhd_SOCKET_REL_MARKER_LISTEN.
   */
  mhd_SockRelMarker fd_id;
  /**
   * This is a connection's FD.
   * This is valid only when @a fd_id is not valid.
   */
  struct MHD_Connection *connection;
};

#ifdef MHD_USE_SELECT

/**
 * Daemon's pointers to the preallocated arrays for running sockets monitoring
 * by poll().
 */
struct mhd_DaemonEventsSelectData
{
  /**
   * Set of sockets monitored for read (receive) readiness.
   */
  fd_set *rfds;
  /**
   * Set of sockets monitored for write (send) readiness.
   */
  fd_set *wfds;
  /**
   * Set of sockets monitored for exception (error) readiness.
   */
  fd_set *efds;
};

#endif /* MHD_USE_SELECT */

#ifdef MHD_USE_POLL

/**
 * Daemon's pointers to the preallocated arrays for running sockets monitoring
 * by poll().
 */
struct mhd_DaemonEventsPollData
{
  /**
   * Array of sockets monitored for read (receive) readiness.
   * The size of the array is maximum number of connections per this daemon plus
   * two (one for the listen socket and one for ITC).
   * ITC FDs and the listening are always the first (and the second), if used.
   * The number of elements is always two plus maximum number of connections
   * allowed for the daemon.
   */
  struct pollfd *fds;
  /**
   * Array of the @a fds identifications.
   * Each slot matches the slot with the same number in @a fds.
   * Up to two first positions reserved for the ITC and the listening.
   * The number of elements is always two plus maximum number of connections
   * allowed for the daemon.
   */
  union mhd_SocketRelation *rel;
};

#endif /* MHD_USE_POLL */

#ifdef MHD_USE_EPOLL
/**
 * Daemon's parameters and pointers to the preallocated memory for running
 * sockets monitoring by epoll.
 */
struct mhd_DaemonEventsEPollData
{
  /**
   * The epoll control FD.
   */
  int e_fd;
  /**
   * The array of events reported by epoll.
   */
  struct epoll_event *events;

  /**
   * The number of elements in the allocated @a events arrays.
   */
  size_t num_elements;
};

#endif

/**
 * Daemon's data for external events for sockets monitoring.
 * Internal version of struct MHD_WorkModeExternalEventLoopCBParam.
 */
struct mhd_DaemonEventsExternal
{
  /**
   * Socket registration callback
   */
  MHD_SocketRegistrationUpdateCallback cb;
  /**
   * Closure for the @a cb
   */
  void *cls;
};

/**
 * Type-specific events monitoring data
 */
union mhd_DaemonEventMonitoringTypeSpecificData
{
#ifdef MHD_USE_SELECT
  /**
   * Daemon's pointers to the preallocated arrays for running sockets monitoring
   * by poll().
   */
  struct mhd_DaemonEventsSelectData select;
#endif /* MHD_USE_SELECT */

#ifdef MHD_USE_POLL
  /**
   * Daemon's pointers to the preallocated arrays for running sockets monitoring
   * by poll().
   */
  struct mhd_DaemonEventsPollData poll;
#endif /* MHD_USE_POLL */

#ifdef MHD_USE_EPOLL
  /**
   * Daemon's parameters and pointers to the preallocated memory for running
   * sockets monitoring by epoll.
   */
  struct mhd_DaemonEventsEPollData epoll;
#endif

  /**
   * Daemon's data for external events for sockets monitoring.
   * Internal version of struct MHD_WorkModeExternalEventLoopCBParam.
   */
  struct mhd_DaemonEventsExternal ext;
};


/**
 * The required actions for the daemon
 */
struct mhd_DaemonEventActionRequired
{
  /**
   * If 'true' then connection is waiting to be accepted
   */
  bool accept;
};


/**
 * The data for events monitoring
 */
struct mhd_DaemonEventMonitoringData
{
  /**
   * Sockets polling type used by the daemon.
   */
  enum mhd_IntPollType poll_type;

  /**
   * Type-specific events monitoring data
   */
  union mhd_DaemonEventMonitoringTypeSpecificData data;

  /**
   * The required actions for the daemon.
   * If daemon has internal thread, this should be changed only inside
   * the daemon's thread.
   */
  struct mhd_DaemonEventActionRequired act_req;

  /**
   * Indicate that daemon already has some data to be processed on the next
   * cycle
   */
  bool zero_wait;

  /**
   * The list of the daemon's connections that need processing
   */
  mhd_DLNKDL_LIST (MHD_Connection,proc_ready);

};


/**
 * The type of the socket
 */
enum MHD_FIXED_ENUM_ mhd_SocketType
{
  /**
   * The socket type is some non-IP type.
   */
  mhd_SOCKET_TYPE_NON_IP = -2
  ,
  /**
   * The socket type is UNIX (LOCAL)
   */
  mhd_SOCKET_TYPE_UNIX = -1
  ,
  /**
   * The socket is unknown yet. It can be IP or non-IP.
   */
  mhd_SOCKET_TYPE_UNKNOWN = 0
  ,
  /**
   * The socket is definitely IP.
   */
  mhd_SOCKET_TYPE_IP = 1
};

/**
 * Listen socket data
 */
struct mhd_ListenSocket
{
  /**
   * The listening socket
   */
  MHD_Socket fd;
  /**
   * The type of the listening socket @a fd
   */
  enum mhd_SocketType type;
  /**
   * 'true' if @a fd is non-blocking
   */
  bool non_block;
  /**
   * The port number for @a fd
   *
   * Zero if unknown and for non-IP socket.
   */
  uint_least16_t port;
};

/**
 * Configured settings for the daemon's network data
 */
struct mhd_DaemonNetworkSettings
{
#ifdef MHD_POSIX_SOCKETS
  /**
   * The maximum number for the network FDs.
   * The valid FD number must be less then @a max_fd_num.
   */
  MHD_Socket max_fd_num;
#else
  int dummy; /* mute compiler warning */
#endif
};

/**
 * The daemon network/sockets data
 */
struct mhd_DaemonNetwork
{
  /**
   * The listening socket
   */
  struct mhd_ListenSocket listen;

#ifdef MHD_USE_EPOLL
  /**
   * The epoll FD.
   * Set to '-1' when epoll is not used.
   */
  int epoll_fd;
#endif
  /**
   * Configured settings for the daemon's network data
   */
  struct mhd_DaemonNetworkSettings cfg;
};

#ifdef MHD_USE_THREADS

/**
 * The type of the daemon
 */
enum MHD_FIXED_ENUM_ mhd_DaemonType
{
  /**
   * A single daemon, performing all the work.
   *
   * This daemon may have a optional single thread, managed by MHD.
   */
  mhd_DAEMON_TYPE_SINGLE
#ifndef NDEBUG
    = 1
#endif
  ,
  /**
   * A master daemon, only controlling worker daemons.
   *
   * This daemon never handle any network activity directly.
   */
  mhd_DAEMON_TYPE_MASTER_CONTROL_ONLY
  ,
  /**
   * A daemon with single internal thread for listening and multiple threads
   * handling connections with the clients, one thread per connection.
   */
  mhd_DAEMON_TYPE_LISTEN_ONLY
  ,
  /**
   * A worker daemon, performing the same work as a single daemon, but
   * controlled by master daemon.
   *
   * This type of daemon always have single internal tread and never exposed
   * to application directly.
   */
  mhd_DAEMON_TYPE_WORKER
};

/**
 * Check whether the daemon type is allowed to have internal thread with
 * direct control
 */
#define mhd_D_TYPE_IS_VALID(t) \
        ((mhd_DAEMON_TYPE_SINGLE <= (t)) && (mhd_DAEMON_TYPE_WORKER >= (t)))

/**
 * Check whether the daemon type must not be exposed to the application
 */
#define mhd_D_TYPE_IS_INTERNAL_ONLY(t) \
        (mhd_DAEMON_TYPE_WORKER == (t))

/**
 * Check whether the daemon type is allowed to process the network data
 */
#define mhd_D_TYPE_HAS_EVENTS_PROCESSING(t) \
        (mhd_DAEMON_TYPE_MASTER_CONTROL_ONLY != (t))

/**
 * Check whether the daemon type must not be exposed to the application
 */
#define mhd_D_TYPE_HAS_WORKERS(t) \
        (mhd_DAEMON_TYPE_MASTER_CONTROL_ONLY == (t))

/**
 * Check whether the daemon type has master (controlling) daemon
 */
#define mhd_D_TYPE_HAS_MASTER_DAEMON(t) \
        (mhd_DAEMON_TYPE_WORKER == (t))

#else  /* ! MHD_USE_THREADS */

/**
 * Check whether the daemon type is allowed to have internal thread with
 * direct control
 */
#define mhd_D_TYPE_IS_VALID(t) (! 0)

/**
 * Check whether the daemon type must not be exposed to the application
 */
#define mhd_D_TYPE_IS_INTERNAL_ONLY(t) (0)

/**
 * Check whether the daemon type is allowed to process the network data
 */
#define mhd_D_TYPE_HAS_EVENTS_PROCESSING(t) (! 0)

/**
 * Check whether the daemon type must not be exposed to the application
 */
#define mhd_D_TYPE_HAS_WORKERS(t) (0)

/**
 * Check whether the daemon type has master (controlling) daemon
 */
#define mhd_D_TYPE_HAS_MASTER_DAEMON(t)  (0)

#endif /* ! MHD_USE_THREADS */

#ifdef MHD_USE_THREADS

/**
 * Workers pool data
 */
struct mhd_DaemonWorkerPoolData
{
  /**
   * Array of worker daemons
   */
  struct MHD_Daemon *workers;

  /**
   * The number of workers in the @a workers array
   */
  unsigned int num;
};

/**
 * Hierarchy data for the daemon
 */
union mhd_DeamonHierarchyData
{
  /**
   * The pointer to the master daemon
   * Only for #mhd_DAEMON_TYPE_WORKER daemons.
   */
  struct MHD_Daemon *master;

  /**
   * Workers pool data.
   * Only for #mhd_DAEMON_TYPE_MASTER_CONTROL_ONLY daemons.
   */
  struct mhd_DaemonWorkerPoolData pool;
};

/**
 * Configured settings for threading
 */
struct mhd_DaemonThreadingDataSettings
{
  /**
   * The size of the stack.
   * Zero to use system's defaults.
   */
  size_t stack_size;
};

/**
 * Threading and Inter-Thread Communication data
 */
struct mhd_DaemonThreadingData
{
  /**
   * The type of this daemon
   */
  enum mhd_DaemonType d_type;

  /**
   * Inter-Thread Communication channel.
   * Used to trigger processing of the command or the data provided or updated
   * by the application.
   */
  struct mhd_itc itc;

  /**
   * 'True' if stop has been requested.
   * The daemon thread should stop all connections and then close.
   */
  volatile bool stop_requested;

  /**
   * 'True' if resuming of any connection has been requested.
   */
  volatile bool resume_requested;

  /**
   * The handle of the daemon's thread (if managed by the daemon)
   */
  mhd_thread_handle_ID tid;

  /**
   * The hierarchy data for the daemon.
   * Used only when @a d_type is #mhd_DAEMON_TYPE_MASTER_CONTROL_ONLY or
   * #mhd_DAEMON_TYPE_WORKER.
   */
  union mhd_DeamonHierarchyData hier;

  /**
   * Configured settings for threading
   */
  struct mhd_DaemonThreadingDataSettings cfg;
};

#endif /* MHD_USE_THREADS */

/**
 * Configured settings for the daemon's connections
 */
struct mhd_DaemonConnectionsSettings
{
  /**
   * The maximum number of connections handled by the daemon
   */
  unsigned int count_limit;

  /**
   * Connection's default timeout value (in seconds)
   */
  unsigned int timeout;

  /**
   * Connection's memory pool size
   */
  size_t mem_pool_size;
};

/**
 * Connections handling data
 */
struct mhd_DaemonConnections
{

  /**
   * The list of all daemon's connections.
   * All connection are listed here, expect connection in @a to_clean list.
   */
  mhd_DLNKDL_LIST (MHD_Connection,all_conn);

  /**
   * The list of connections sorted by last activity
   */
  mhd_DLNKDL_LIST (MHD_Connection,def_timeout);

  /**
   * The list of connections with custom timeouts
   */
  mhd_DLNKDL_LIST (MHD_Connection,cust_timeout);

  /**
   * The list of all daemon's connections
   */
  mhd_DLNKDL_LIST (MHD_Connection,to_clean);

  /**
   * The current number of connections handled by the daemon
   */
  unsigned int count;

  /**
   * If set to 'true' then no new connection is allowed.
   * New connection may be blocked because of various system limits, when
   * additional connection would fail anyway. This flag should be cleared
   * when any already processing connection closed.
   * Can be checked from other threads
   */
  volatile bool block_new;

  /**
   * Configured settings for the daemon's connections
   */
  struct mhd_DaemonConnectionsSettings cfg;
};

/**
 * Early URI callback
 */
struct mhd_DaemonRequestUriCB
{
  /**
   * The callback
   */
  MHD_EarlyUriLogCallback cb;
  /**
   * The callback closure
   */
  void *cls;
};

/**
 * Shared large buffer data
 */
struct mhd_DeamonLargeBuffer
{
  /**
   * The amount of memory left allowed to be allocated for the large buffer
   */
  size_t space_left;

#ifdef MHD_USE_THREADS
  /**
   * The mutex to change or check the @a space_left value
   */
  mhd_mutex lock;
#endif
};

/**
 * Settings for requests processing
 */
struct mhd_DaemonRequestProcessingSettings
{
  /**
   * Request callback.
   * The main request processing callback.
   */
  MHD_RequestCallback cb;

  /**
   * The closure for @a req_cb
   */
  void *cb_cls;

  /**
   * Protocol strictness enforced by MHD on clients.
   */
  enum MHD_ProtocolStrictLevel strictnees;

  /**
   * Early URI callback
   */
  struct mhd_DaemonRequestUriCB uri_cb; // TODO: set from settings

  /**
   * Shared large buffer data
   */
  struct mhd_DeamonLargeBuffer large_buf; // TODO: set from settings

  /**
   * Suppress "Date:" header in responses
   */
  bool suppress_date; // TODO: set from settings
};


#ifndef NDEBUG
/**
 * Various debugging data
 */
struct mhd_daemon_debug
{
  bool net_inited;
  bool net_deinited;
  bool events_allocated;
  unsigned int num_events_elements;
  bool events_fully_inited;
  bool thread_pool_inited;
  bool threading_inited;
  bool connections_inited;
  bool avoid_accept4;
};
#endif /* NDEBUG */


struct MHD_Daemon
{
  /* General data */

  /**
   * The daemon state
   */
  enum mhd_DaemonState state;

  /**
   * The daemon work mode (private version)
   */
  enum mhd_WorkModeIntType wmode_int;

  /* Events/sockets monitoring/polling data */

  /**
   * The data for events monitoring
   */
  struct mhd_DaemonEventMonitoringData events;

  /* Network/sockets data */

  /**
   * The daemon network/sockets data
   */
  struct mhd_DaemonNetwork net;

#ifdef MHD_USE_THREADS
  /* Threading data */

  /**
   * The daemon threading and Inter-Thread Communication data
   */
  struct mhd_DaemonThreadingData threading;
#endif

  /* Connections handling */

  /**
   * The connections handling data
   */
  struct mhd_DaemonConnections conns;

  /* Request processing data */

  /**
   * Settings for requests processing
   */
  struct mhd_DaemonRequestProcessingSettings req_cfg;

  /* Other data */

  /**
   * Daemon logging parameters
   */
  struct MHD_DaemonOptionValueLog log_params;


  /* Temporal data */

  /**
   * User settings, before applied to the daemon itself
   */
  struct DaemonOptions *settings;

#ifndef NDEBUG
  /* Debug data */

  struct mhd_daemon_debug dbg;
#endif
};


#ifdef MHD_POSIX_SOCKETS
/**
 * Checks whether @a fd socket number fits limitations for the @a d_ptr daemon
 */
#  define mhd_FD_FITS_DAEMON(d_ptr,fd) \
        ((MHD_INVALID_SOCKET == d_ptr->net.cfg.max_fd_num) || \
         (d_ptr->net.cfg.max_fd_num > fd))
#else
#  define mhd_FD_FITS_DAEMON(d_ptr,fd) (! 0)
#endif
#endif /* ! MHD_DAEMON_H */

#ifdef MHD_USE_EPOLL
#  define mhd_D_IS_USING_EPOLL(d) \
        (mhd_POLL_TYPE_EPOLL == ((d)->events.poll_type))
#else
#  define mhd_D_IS_USING_EPOLL(d) (0)
#endif

#ifdef MHD_USE_THREADS
#  define mhd_D_HAS_THREADS(d) mhd_WM_INT_HAS_THREADS ((d)->wmode_int)
#else
#  define mhd_D_HAS_THREADS(d) (0)
#endif

#ifdef MHD_USE_THREADS
#  define mhd_D_HAS_THR_PER_CONN(d) \
        (mhd_WM_INT_INTERNAL_EVENTS_THREAD_PER_CONNECTION == \
         ((d)->wmode_int))
#else
#  define mhd_D_HAS_THR_PER_CONN(d) (0)
#endif

#define mhd_D_HAS_WORKERS(d) mhd_D_TYPE_HAS_WORKERS ((d)->threading.d_type)

#define mhd_D_HAS_MASTER(d) mhd_D_TYPE_HAS_MASTER_DAEMON ((d)->threading.d_type)

#define mhd_D_IS_INTERNAL_ONLY(d) \
        mhd_D_TYPE_IS_INTERNAL_ONLY ((d)->threading.d_type)

#define mhd_D_IS_USING_EDGE_TRIG(d) \
        (mhd_D_IS_USING_EPOLL (d) || \
         (mhd_WM_INT_EXTERNAL_EVENTS_EDGE ==((d)->wmode_int)))
