/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2017 Daniel Pittman and Christian Grothoff

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
 * @file microhttpd/internal.h
 * @brief  internal shared structures
 * @author Daniel Pittman
 * @author Christian Grothoff
 */

#ifndef INTERNAL_H
#define INTERNAL_H

#include "mhd_options.h"
#include "platform.h"
#include "microhttpd2.h"
#include "microhttpd_tls.h"
#include "mhd_assert.h"

#ifdef HTTPS_SUPPORT
#include <gnutls/gnutls.h>
#if GNUTLS_VERSION_MAJOR >= 3
#include <gnutls/abstract.h>
#endif
#endif /* HTTPS_SUPPORT */

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
#ifdef MHD_PANIC
/* Override any defined MHD_PANIC macro with proper one */
#undef MHD_PANIC
#endif /* MHD_PANIC */

#ifdef HAVE_MESSAGES
/**
 * Trigger 'panic' action based on fatal errors.
 *
 * @param msg error message (const char *)
 */
#define MHD_PANIC(msg) do { mhd_panic (mhd_panic_cls, __FILE__, __LINE__, msg); BUILTIN_NOT_REACHED; } while (0)
#else
/**
 * Trigger 'panic' action based on fatal errors.
 *
 * @param msg error message (const char *)
 */
#define MHD_PANIC(msg) do { mhd_panic (mhd_panic_cls, __FILE__, __LINE__, NULL); BUILTIN_NOT_REACHED; } while (0)
#endif

#include "mhd_threads.h"
#include "mhd_locks.h"
#include "mhd_sockets.h"
#include "mhd_itc_types.h"


/**
 * Close FD and abort execution if error is detected.
 * @param fd the FD to close
 */
#define MHD_fd_close_chk_(fd) do {             \
    if (0 == close ((fd)) && (EBADF == errno)) \
      MHD_PANIC(_("Failed to close FD.\n"));   \
  } while(0)

/**
 * Should we perform additional sanity checks at runtime (on our internal
 * invariants)?  This may lead to aborts, but can be useful for debugging.
 */
#define EXTRA_CHECKS MHD_NO

#define MHD_MAX(a,b) (((a)<(b)) ? (b) : (a))
#define MHD_MIN(a,b) (((a)<(b)) ? (a) : (b))


/**
 * Minimum size by which MHD tries to increment read/write buffers.
 * We usually begin with half the available pool space for the
 * IO-buffer, but if absolutely needed we additively grow by the
 * number of bytes given here (up to -- theoretically -- the full pool
 * space).
 */
#define MHD_BUF_INC_SIZE 1024


/**
 * Handler for fatal errors.
 */
extern MHD_PanicCallback mhd_panic;

/**
 * Closure argument for "mhd_panic".
 */
extern void *mhd_panic_cls;

/* If we have Clang or gcc >= 4.5, use __buildin_unreachable() */
#if defined(__clang__) || (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
#define BUILTIN_NOT_REACHED __builtin_unreachable()
#elif defined(_MSC_FULL_VER)
#define BUILTIN_NOT_REACHED __assume(0)
#else
#define BUILTIN_NOT_REACHED
#endif

#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro)/sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */


/**
 * State kept for each MHD daemon.  All connections are kept in two
 * doubly-linked lists.  The first one reflects the state of the
 * connection in terms of what operations we are waiting for (read,
 * write, locally blocked, cleanup) whereas the second is about its
 * timeout state (default or custom).
 */
struct MHD_Daemon
{
  /**
   * Function to call to handle incoming requests.
   */
  MHD_RequestCallback rc;

  /**
   * Closure for @e rc.
   */
  void *rc_cls;

  /** 
   * Function to call for logging.
   */
  MHD_LoggingCallback logger;

  /**
   * Closure for @e logger.
   */
  void *logger_cls;  

  /**
   * Function to call to accept/reject connections based on
   * the client's IP address.
   */
  MHD_AcceptPolicyCallback accept_policy_cb;

  /**
   * Closure for @e accept_policy_cb.
   */
  void *accept_policy_cb_cls;

  /**
   * Function to call on the full URL early for logging.
   */
  MHD_EarlyUriLogCallback early_uri_logger_cb;

  /**
   * Closure for @e early_uri_logger_cb.
   */
  void *early_uri_logger_cls;

  /**
   * Function to call whenever a connection is started or
   * closed.
   */
  MHD_NotifyConnectionCallback notify_connection_cb;

  /**
   * Closure for @e notify_connection_cb.
   */
  void *notify_connection_cb_cls;

  /**
   * Function to call to unescape sequences in URIs and URI arguments.
   * See #MHD_daemon_unescape_cb().
   */
  MHD_UnescapeCallback unescape_cb;

  /**
   * Closure for @e unescape_cb.
   */
  void *unescape_cb_cls;
  
#if HTTPS_SUPPORT
  /**
   * Which TLS backend should be used. NULL for no TLS.
   * This is merely the handle to the dlsym() object, not
   * the API.
   */ 
  void *tls_backend_lib;

  /**
   * Callback functions to use for TLS operations.
   */
  struct MHD_TLS_Plugin *tls_api;
#endif
#if ENABLE_DAUTH

  /**
   * Random values to be used by digest authentication module.
   * Size given in @e digest_auth_random_buf_size.
   */
  const void *digest_auth_random_buf;
#endif
  
  /** 
   * Socket address to bind to for the listen socket.
   */
  struct sockaddr_storage listen_sa;

  /** 
   * Number of (valid) bytes in @e listen_sa.  Zero
   * if @e listen_sa is not initialized.
   */
  size_t listen_sa_len;

  /**
   * Buffer size to use for each connection. Default
   * is #MHD_POOL_SIZE_DEFAULT.
   */
  size_t connection_memory_limit_b;

/**
 * Default minimum size by which MHD tries to increment read/write
 * buffers.  We usually begin with half the available pool space for
 * the IO-buffer, but if absolutely needed we additively grow by the
 * number of bytes given here (up to -- theoretically -- the full pool
 * space).
 */
#define BUF_INC_SIZE_DEFAULT 1024
  
  /**
   * Increment to use when growing the read buffer. Smaller
   * than @e connection_memory_limit_b.
   */
  size_t connection_memory_increment_b;

  /**
   * Desired size of the stack for threads created by MHD,
   * 0 for system default.
   */
  size_t thread_stack_limit_b;

#if ENABLE_DAUTH
  
  /**
   * Size of @e digest_auth_random_buf.
   */
  size_t digest_auth_random_buf_size;

  /**
   * Default value for @e digest_nc_length.
   */
#define DIGEST_NC_LENGTH_DEFAULT 4
  
  /**
   * Desired length of the internal array with the nonce and
   * nonce counters for digest authentication.
   */
  size_t digest_nc_length;
#endif
  
  /**
   * Default value we use for the listen backlog.
   */
#ifdef SOMAXCONN
#define LISTEN_BACKLOG_DEFAULT SOMAXCONN
#else  /* !SOMAXCONN */
#define LISTEN_BACKLOG_DEFAULT 511
#endif
  
  /**
   * Backlog argument to use for listen.  See 
   * #MHD_daemon_listen_backlog().
   */
  int listen_backlog;
  
  /**
   * Default queue length to use with fast open.
   */
#define FO_QUEUE_LENGTH_DEFAULT 50

  /**
   * Queue length to use with fast open.
   */
  unsigned int fo_queue_length;

  /**
   * Maximum number of connections MHD accepts. 0 for unlimited.
   */
  unsigned int global_connection_limit;

  /**
   * Maximum number of connections we accept per IP, 0 for unlimited.
   */
  unsigned int ip_connection_limit;

  /**
   * Default timeout in seconds for idle connections.
   */
  unsigned int connection_default_timeout_s;
  
  /** 
   * Listen socket we should use, MHD_INVALID_SOCKET means
   * we are to initialize the socket from the other options given.
   */
  MHD_socket listen_socket;

  /**
   * Which threading model do we use? Postive
   * numbers indicate the number of worker threads to be used.
   */
  enum MHD_ThreadingModel threading_model;
  
  /**
   * When should we use TCP_FASTOPEN? 
   * See #MHD_daemon_tcp_fastopen().
   */ 
  enum MHD_FastOpenMethod fast_open_method;

  /**
   * Address family to use when listening.
   * Default is #MHD_AF_AUTO.
   */
  enum MHD_AddressFamily listen_af;

  /**
   * Sets active/desired style of the event loop.
   * (Auto only possible during initialization, later set to
   * the actual style we use.)
   */
  enum MHD_EventLoopSyscall event_loop_syscall;

  /**
   * How strictly do we enforce the HTTP protocol?
   * See #MHD_daemon_protocol_strict_level().
   */
  enum MHD_ProtocolStrictLevel protocol_strict_level;

  /** 
   * On which port should we listen on? Only effective if we were not
   * given a listen socket or a full address via
   * #MHD_daemon_bind_sa().  0 means not set, which means to default
   * to 80 (http) or 443 (https) respectively.
   */
  uint16_t listen_port;
  
  /**
   * Suppress generating the "Date:" header, this system
   * lacks an RTC (or developer is hyper-optimizing).  See
   * #MHD_daemon_suppress_date_no_clock().
   */ 
  bool suppress_date;

  /**
   * The use of the inter-thread communication channel is disabled.
   * See #MHD_daemon_disable_itc().
   */ 
  bool disable_itc;

  /**
   * Disable #MHD_action_suspend() functionality.  See
   * #MHD_daemon_disallow_suspend_resume().
   */ 
  bool disallow_suspend_resume;

  /**
   * Disable #MHD_action_upgrade() functionality.  See
   * #MHD_daemon_disallow_upgrade().
   */ 
  bool disallow_upgrade;

  /**
   * Disables optional calls to `shutdown()` and enables aggressive
   * non-blocking optimistic reads and other potentially unsafe
   * optimizations.  See #MHD_daemon_enable_turbo().
   */
  bool enable_turbo;

  /**
   * Allow reusing the address:port combination when binding.
   * See #MHD_daemon_listen_allow_address_reuse().
   */
  bool allow_address_reuse;

  
  
};






#endif
