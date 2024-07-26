/* This is generated code, it is still under LGPLv2.1+.
   Do not edit directly! */
/* *INDENT-OFF* */
/**
 * @file daemon_options.h
 * @author daemon-options-generator.c
 */

#ifndef MHD_DAEMON_OPTIONS_H
#define MHD_DAEMON_OPTIONS_H 1

#include "mhd_sys_options.h"
#include "mhd_public_api.h"

struct DaemonOptions {
  /**
   * Value for #MHD_D_O_WORK_MODE.
   * the object created by one of the next functions/macros: #MHD_WM_OPTION_EXTERNAL_PERIODIC(), #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL(), #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE(), #MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH(), #MHD_WM_OPTION_WORKER_THREADS(), #MHD_WM_OPTION_THREAD_PER_CONNECTION()
   */
  struct MHD_WorkModeWithParam work_mode;


  /**
   * Value for #MHD_D_O_POLL_SYSCALL.
   * FIXME
   */
  enum MHD_SockPollSyscall poll_syscall;


  /**
   * Value for #MHD_D_O_LOG_CALLBACK.
   * the callback to use for logging,
   * NULL to disable logging
   */
  struct MHD_DaemonOptionValueLog log_callback;


  /**
   * Value for #MHD_D_O_BIND_PORT.
   * the address family to use,
   * the #MHD_AF_NONE to disable listen socket (the same effect as if this option is not used)
   */
  struct MHD_DaemonOptionValueBind bind_port;


  /**
   * Value for #MHD_D_O_BIND_SA.
   * the size of the socket address pointed by @a sa.
   */
  struct MHD_DaemonOptionValueSA bind_sa;


  /**
   * Value for #MHD_D_O_LISTEN_SOCKET.
   * the listen socket to use, ignored if set to #MHD_INVALID_SOCKET
   */
  MHD_Socket listen_socket;


  /**
   * Value for #MHD_D_O_LISTEN_ADDR_REUSE.
   * FIXME
   */
  enum MHD_DaemonOptionBindType listen_addr_reuse;


  /**
   * Value for #MHD_D_O_TCP_FASTOPEN.
   * the type use of of TCP FastOpen
   */
  struct MHD_DaemonOptionValueTFO tcp_fastopen;


  /**
   * Value for #MHD_D_O_LISTEN_BACKLOG.
   * FIXME
   */
  unsigned int listen_backlog;


  /**
   * Value for #MHD_D_O_SIGPIPE_SUPPRESSED.
   */
  enum MHD_Bool sigpipe_suppressed;


  /**
   * Value for #MHD_D_O_TLS.
   * the TLS backend to use,
   * #MHD_TLS_BACKEND_NONE for non-TLS (plain TCP) connections
   */
  enum MHD_TlsBackend tls;


  /**
   * Value for #MHD_D_O_TLS_KEY_CERT.
   * the private key loaded into memory (not a filename)
   */
  struct MHD_DaemonOptionValueTlsCert tls_key_cert;


  /**
   * Value for #MHD_D_O_TLS_CLIENT_CA.
   * the CA certificate in memory (not a filename)
   */
  const char *tls_client_ca;


  /**
   * Value for #MHD_D_O_TLS_PSK_CALLBACK.
   * the function to call to obtain pre-shared key
   */
  struct MHD_DaemonOptionValueTlsPskCB tls_psk_callback;


  /**
   * Value for #MHD_D_O_NO_ALPN.
   */
  enum MHD_Bool no_alpn;


  /**
   * Value for #MHD_D_O_DEFAULT_TIMEOUT.
   * the in seconds, zero for no timeout
   */
  unsigned int default_timeout;


  /**
   * Value for #MHD_D_O_GLOBAL_CONNECTION_LIMIT.
   * FIXME
   */
  unsigned int global_connection_limit;


  /**
   * Value for #MHD_D_O_PER_IP_LIMIT.
   * FIXME
   */
  unsigned int per_ip_limit;


  /**
   * Value for #MHD_D_O_ACCEPT_POLICY.
   * the accept policy callback
   */
  struct MHD_DaemonOptionValueAcceptPol accept_policy;


  /**
   * Value for #MHD_D_O_PROTOCOL_STRICT_LEVEL.
   * the level of strictness
   */
  struct MHD_DaemonOptionValueStrctLvl protocol_strict_level;


  /**
   * Value for #MHD_D_O_EARLY_URI_LOGGER.
   * the early URI callback
   */
  struct MHD_DaemonOptionValueUriCB early_uri_logger;


  /**
   * Value for #MHD_D_O_DISABLE_URI_QUERY_PLUS_AS_SPACE.
   */
  enum MHD_Bool disable_uri_query_plus_as_space;


  /**
   * Value for #MHD_D_O_SUPPRESS_DATE_HEADER.
   */
  enum MHD_Bool suppress_date_header;


  /**
   * Value for #MHD_D_O_ENABLE_SHOUTCAST.
   */
  enum MHD_Bool enable_shoutcast;


  /**
   * Value for #MHD_D_O_CONN_MEMORY_LIMIT.
   */
  size_t conn_memory_limit;


  /**
   * Value for #MHD_D_O_LARGE_POOL_SIZE.
   */
  size_t large_pool_size;


  /**
   * Value for #MHD_D_O_STACK_SIZE.
   */
  size_t stack_size;


  /**
   * Value for #MHD_D_O_FD_NUMBER_LIMIT.
   * FIXME
   */
  MHD_Socket fd_number_limit;


  /**
   * Value for #MHD_D_O_TURBO.
   */
  enum MHD_Bool turbo;


  /**
   * Value for #MHD_D_O_DISABLE_THREAD_SAFETY.
   */
  enum MHD_Bool disable_thread_safety;


  /**
   * Value for #MHD_D_O_DISALLOW_UPGRADE.
   */
  enum MHD_Bool disallow_upgrade;


  /**
   * Value for #MHD_D_O_DISALLOW_SUSPEND_RESUME.
   */
  enum MHD_Bool disallow_suspend_resume;


  /**
   * Value for #MHD_D_O_DAEMON_READY_CALLBACK.
   * the pre-start callback
   */
  struct MHD_DaemonOptionValueReadyCB daemon_ready_callback;


  /**
   * Value for #MHD_D_O_NOTIFY_CONNECTION.
   * the callback for notifications
   */
  struct MHD_DaemonOptionValueNotifConnCB notify_connection;


  /**
   * Value for #MHD_D_O_NOTIFY_STREAM.
   * the callback for notifications
   */
  struct MHD_DaemonOptionValueNotifStreamCB notify_stream;


  /**
   * Value for #MHD_D_O_RANDOM_ENTROPY.
   * the size of the buffer
   */
  struct MHD_DaemonOptionEntropySeed random_entropy;


  /**
   * Value for #MHD_D_O_DAUTH_MAP_SIZE.
   * the size of the map array
   */
  size_t dauth_map_size;


  /**
   * Value for #MHD_D_O_DAUTH_NONCE_BIND_TYPE.
   * FIXME
   */
  enum MHD_DaemonOptionValueDAuthBindNonce dauth_nonce_bind_type;


  /**
   * Value for #MHD_D_O_DAUTH_DEF_NONCE_TIMEOUT.
   * FIXME
   */
  unsigned int dauth_def_nonce_timeout;


  /**
   * Value for #MHD_D_O_DAUTH_DEF_MAX_NC.
   * FIXME
   */
  uint_fast32_t dauth_def_max_nc;


};

#endif /* ! MHD_DAEMON_OPTIONS_H */
