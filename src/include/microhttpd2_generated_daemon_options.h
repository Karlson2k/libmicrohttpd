/**
 * The options (parameters) for MHD daemon
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_DaemonOption
{  /**
   * Not a real option.
   * Should not be used directly.
   * This value indicates the end of the list of the options.
   */
  MHD_D_O_END = 0
  ,

  /**
   * Set MHD work (threading and polling) mode.
   * Consider use of #MHD_D_OPTION_WM_EXTERNAL_PERIODIC(), #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL(), #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_EDGE(), #MHD_D_OPTION_WM_EXTERNAL_SINGLE_FD_WATCH(), #MHD_D_OPTION_WM_WORKER_THREADS() or #MHD_D_OPTION_WM_THREAD_PER_CONNECTION() instead of direct use of this parameter.
   */
  MHD_D_O_WORK_MODE = 40
  ,

  /**
   * Select a sockets watch system call used for internal polling.
   */
  MHD_D_O_POLL_SYSCALL = 41
  ,

  /**
   * Set a callback to use for logging
   */
  MHD_D_O_LOG_CALLBACK = 60
  ,

  /**
   * Bind to the given TCP port and address family.
   *
Does not work with #MHD_D_OPTION_BIND_SA() or #MHD_D_OPTION_LISTEN_SOCKET().
   *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
   */
  MHD_D_O_BIND_PORT = 80
  ,

  /**
   * Bind to the given socket address.
   *
Does not work with #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_LISTEN_SOCKET().
   *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
   */
  MHD_D_O_BIND_SA = 81
  ,

  /**
   * Accept connections from the given socket.  Socket
   * must be a TCP or UNIX domain (SOCK_STREAM) socket.
   *
Does not work with #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA().
   *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
   */
  MHD_D_O_LISTEN_SOCKET = 82
  ,

  /**
   * Select mode of reusing address:port listen address.
   *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
   */
  MHD_D_O_LISTEN_ADDR_REUSE = 100
  ,

  /**
   * Configure TCP_FASTOPEN option, including setting a
   * custom @a queue_length.
   *
Note that having a larger queue size can cause resource exhaustion
   * attack as the TCP stack has to now allocate resources for the SYN
   * packet along with its DATA.
   *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
   */
  MHD_D_O_TCP_FASTOPEN = 101
  ,

  /**
   * Use the given backlog for the listen() call.
   *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
   * Zero parameter treated as MHD/system default.
   */
  MHD_D_O_LISTEN_BACKLOG = 102
  ,

  /**
   * Inform that SIGPIPE is suppressed or handled by application.
   * If suppressed/handled, MHD uses network functions that could generate SIGPIPE, like `sendfile()`.
   * Silently ignored when MHD creates internal threads as for them SIGPIPE is suppressed automatically.
   */
  MHD_D_O_SIGPIPE_SUPPRESSED = 103
  ,

  /**
   * Enable TLS (HTTPS) and select TLS backend
   */
  MHD_D_O_TLS = 120
  ,

  /**
   * Provide TLS key and certificate data in-memory.
   * Works only if TLS mode is enabled.
   */
  MHD_D_O_TLS_CERT_KEY = 121
  ,

  /**
   * Provide the certificate of the certificate authority (CA) to be used by the MHD daemon for client authentication.
   * Works only if TLS mode is enabled.
   */
  MHD_D_O_TLS_CLIENT_CA = 122
  ,

  /**
   * Configure PSK to use for the TLS key exchange.
   */
  MHD_D_O_TLS_PSK_CALLBACK = 130
  ,

  /**
   * Control ALPN for TLS connection.
   * Silently ignored for non-TLS.
   * By default ALPN is automatically used for TLS connections.
   */
  MHD_D_O_NO_ALPN = 140
  ,

  /**
   * Specify inactivity timeout for connection.
   * When no activity for specified time on connection, it is closed automatically.
   * Use zero for no timeout, which is also the (unsafe!) default.
   */
  MHD_D_O_DEFAULT_TIMEOUT = 160
  ,

  /**
   * Maximum number of (concurrent) network connections served by daemon.
   * @note The real maximum number of network connections could be smaller
   *       than requested due to the system limitations, like FD_SETSIZE when
   *       polling by select() is used.
   */
  MHD_D_O_GLOBAL_CONNECTION_LIMIT = 161
  ,

  /**
   * Limit on the number of (concurrent) network connections made to the server from the same IP address.
   * Can be used to prevent one IP from taking over all of the allowed connections. If the same IP tries to establish more than the specified number of connections, they will be immediately rejected.
   */
  MHD_D_O_PER_IP_LIMIT = 162
  ,

  /**
   * Set a policy callback that accepts/rejects connections based on the client's IP address.  The callbeck function will be called before servicing any new incoming connection.
   */
  MHD_D_O_ACCEPT_POLICY = 163
  ,

  /**
   * Set how strictly MHD will enforce the HTTP protocol.
   */
  MHD_D_O_PROTOCOL_STRICT_LEVEL = 200
  ,

  /**
   * Set a callback to be called first for every request when the request line is received (before any parsing of the header).
   * This callback is the only way to get raw (unmodified) request URI as URI is parsed and modified by MHD in-place.
   * Mandatory URI modification may apply before this call, like binary zero replacement, as required by RFCs.
   */
  MHD_D_O_EARLY_URI_LOGGER = 201
  ,

  /**
   * Disable converting plus ('+') character to space in GET parameters (URI part after '?').
   * Plus conversion is not required by HTTP RFCs, however it required by HTML specifications, see https://url.spec.whatwg.org/#application/x-www-form-urlencoded for details.
   * By default plus is converted to space in the query part of URI.
   */
  MHD_D_O_DISABLE_URI_QUERY_PLUS_AS_SPACE = 202
  ,

  /**
   * Suppresse use of 'Date:' header.
   * According to RFC should be suppressed only if the system has no RTC.
   * The 'Date:' is not suppressed (the header is enabled) by default.
   */
  MHD_D_O_SUPPRESS_DATE_HEADER = 240
  ,

  /**
   * Use SHOUTcast for responses.
   * This will cause *all* responses to begin with the SHOUTcast 'ICY' line instead of 'HTTP'.
   */
  MHD_D_O_ENABLE_SHOUTCAST = 241
  ,

  /**
   * Maximum memory size per connection.
   * Default is 32kb.
   * Values above 128kb are unlikely to result in much performance benefit, as half of the memory will be typically used for IO, and TCP buffers are unlikely to support window sizes above 64k on most systems.
   * The size should be large enough to fit all request headers (together with internal parsing information).
   */
  MHD_D_O_CONN_MEMORY_LIMIT = 280
  ,

  /**
   * The size of the shared memory pool for accamulated upload processing.
   * The same large pool is shared for all connections server by MHD and used when application requests avoiding of incremental upload processing to accamulate complete content upload before giving it to the application.
   * Default is 8Mb.
   * Can be set to zero to disable share pool.
   */
  MHD_D_O_LARGE_POOL_SIZE = 281
  ,

  /**
   * Desired size of the stack for the threads started by MHD.
   * Use 0 for system default, which is also MHD default.
   * Works only with #MHD_D_OPTION_WM_WORKER_THREADS() or #MHD_D_OPTION_WM_THREAD_PER_CONNECTION().
   */
  MHD_D_O_STACK_SIZE = 282
  ,

  /**
   * The the maximum FD value.
   * The limit is applied to all sockets used by MHD.
   * If listen socket FD is equal or higher that specified value, the daemon fail to start.
   * If new connection FD is equal or higher that specified value, the connection is rejected.
   * Useful if application uses select() for polling the sockets, system FD_SETSIZE is good value for this option in such case.
   * Silently ignored on W32 (WinSock sockets).
   */
  MHD_D_O_FD_NUMBER_LIMIT = 283
  ,

  /**
   * Enable `turbo`.
   * Disables certain calls to `shutdown()`, enables aggressive non-blocking optimistic reads and other potentially unsafe optimisations.
   * Most effects only happen with internal threads with epoll.
   * The 'turbo' mode is not enabled (mode is disabled) by default.
   */
  MHD_D_O_TURBO = 320
  ,

  /**
   * Disable some internal thread safety.
   * Indicates that MHD daemon will be used by application in single-threaded mode only.  When this flag is set then application must call any MHD function only within a single thread.
   * This flag turns off some internal thread-safety and allows MHD making some of the internal optimisations suitable only for single-threaded environment.
   * Not compatible with any internal threads modes.
   * If MHD is compiled with custom configuration for embedded projects without threads support, this option is mandatory.
   * Thread safety is not disabled (safety is enabled) by default.
   */
  MHD_D_O_DISABLE_THREAD_SAFETY = 321
  ,

  /**
   * You need to set this option if you want to disable use of HTTP Upgrade.
   * Upgrade may require usage of additional internal resources, which we can avoid providing if they will not be used.
   * You should only use this option if you do not use upgrade functionality and need a generally minor boost in performance and resources saving.
   * The upgrade is not disallowed (upgrade is allowed) by default.
   */
  MHD_D_O_DISALLOW_UPGRADE = 322
  ,

  /**
   * Disable #MHD_action_suspend() functionality.
   *
You should only use this function if you do not use suspend functionality and need a generally minor boost in performance.
   * The suspend is not disallowed (suspend is allowed) by default.
   */
  MHD_D_O_DISALLOW_SUSPEND_RESUME = 323
  ,

  /**
   * Set a callback to be called for pre-start finalisation.
   *
The specified callback will be called one time, after network initialisation, TLS pre-initialisation, but before the start of the internal threads (if allowed)
   */
  MHD_D_O_DAEMON_READY_CALLBACK = 360
  ,

  /**
   * Set a function that should be called whenever a connection is started or closed.
   */
  MHD_D_O_NOTIFY_CONNECTION = 361
  ,

  /**
   * Register a function that should be called whenever a stream is started or closed.
   * For HTTP/1.1 this callback is called one time for every connection.
   */
  MHD_D_O_NOTIFY_STREAM = 362
  ,

  /**
   * Set strong random data to be used by MHD.
   * Currently the data is only needed for Digest Auth module.
   * Daemon support for Digest Auth is enabled automatically if this option is used.
   * The recommended size is between 8 and 32 bytes. Security can be lower for sizes less or equal four.
   * Sizes larger then 32 (or, probably, larger than 16 - debatable) will not increase the security.
   */
  MHD_D_O_RANDOM_ENTROPY = 400
  ,

  /**
   * Specify the size of the internal hash map array that tracks generated digest nonces usage.
   * When the size of the map is too small then need to handle concurrent DAuth requests, a lot of stale nonce results will be produced.
   * By default the size is 1000 entries.
   */
  MHD_D_O_AUTH_DIGEST_MAP_SIZE = 401
  ,

  /**
   * Nonce validity time (in seconds) used for Digest Auth.
   * If followed by zero value the value is silently ignored.
   * @see #MHD_digest_auth_check(), MHD_digest_auth_check_digest()
   */
  MHD_D_O_AUTH_DIGEST_NONCE_TIMEOUT = 403
  ,

  /**
   * Default maximum nc (nonce count) value used for Digest Auth.
   * If followed by zero value the value is silently ignored.
   * @see #MHD_digest_auth_check(), MHD_digest_auth_check_digest()
   */
  MHD_D_O_AUTH_DIGEST_DEF_MAX_NC = 404
  ,

  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_D_O_SENTINEL = 65535

};

/**
 * Data for #MHD_D_O_LOG_CALLBACK
 */
struct MHD_DaemonOptionValueLog
{
  /**
   * the callback to use for logging,
   * NULL to disable logging
   */
  MHD_LoggingCallback v_log_cb;

  /**
   * the closure for the logging callback
   */
  void *v_log_cb_cls;

};

/**
 * Data for #MHD_D_O_BIND_PORT
 */
struct MHD_DaemonOptionValueBind
{
  /**
   * the address family to use,
   * the #MHD_AF_NONE to disable listen socket (the same effect as if this option is not used)
   */
  enum MHD_AddressFamily v_af;

  /**
   * port to use, 0 to let system assign any free port,
   * ignored if @a af is #MHD_AF_NONE
   */
  uint_least16_t v_port;

};

/**
 * Data for #MHD_D_O_BIND_SA
 */
struct MHD_DaemonOptionValueSA
{
  /**
   * the size of the socket address pointed by @a sa.
   */
  size_t v_sa_len;

  /**
   * the address to bind to; can be IPv4 (AF_INET), IPv6 (AF_INET6) or even a UNIX domain socket (AF_UNIX)
   */
  /* const */ struct sockaddr *v_sa;

  /**
   * When a previous version of the protocol exist (like IPv4 when @a v_sa is IPv6) bind to both protocols (IPv6 and IPv4).
   */
  enum MHD_Bool v_dual;

};

/**
 * Data for #MHD_D_O_TCP_FASTOPEN
 */
struct MHD_DaemonOptionValueTFO
{
  /**
   * the type use of of TCP FastOpen
   */
  enum MHD_TCPFastOpenType v_option;

  /**
   * the length of the queue, zero to use system or MHD default,
   * silently ignored on platforms without support for custom queue size
   */
  unsigned int v_queue_length;

};

/**
 * Data for #MHD_D_O_TLS_CERT_KEY
 */
struct MHD_DaemonOptionValueTlsCert
{
  /**
   * The X.509 certificates chain in PEM format loaded into memory (not a filename).
   * The first certificate must be the server certificate, following by the chain of signing
   * certificates up to (but not including) CA root certificate.
   */
  /* const */ char *v_mem_cert;

  /**
   * the private key in PEM format loaded into memory (not a filename)
   */
  const char *v_mem_key;

  /**
   * the option passphrase phrase to decrypt the private key,
   * could be NULL if private key does not need a password
   */
  const char *v_mem_pass;

};

/**
 * Data for #MHD_D_O_TLS_PSK_CALLBACK
 */
struct MHD_DaemonOptionValueTlsPskCB
{
  /**
   * the function to call to obtain pre-shared key
   */
  MHD_PskServerCredentialsCallback v_psk_cb;

  /**
   * the closure for @a psk_cb
   */
  void *v_psk_cb_cls;

};

/**
 * Data for #MHD_D_O_ACCEPT_POLICY
 */
struct MHD_DaemonOptionValueAcceptPol
{
  /**
   * the accept policy callback
   */
  MHD_AcceptPolicyCallback v_apc;

  /**
   * the closure for the callback
   */
  void *v_apc_cls;

};

/**
 * Data for #MHD_D_O_PROTOCOL_STRICT_LEVEL
 */
struct MHD_DaemonOptionValueStrctLvl
{
  /**
   * the level of strictness
   */
  enum MHD_ProtocolStrictLevel v_sl;

  /**
   * the way how to use the requested level
   */
  enum MHD_UseStictLevel v_how;

};

/**
 * Data for #MHD_D_O_EARLY_URI_LOGGER
 */
struct MHD_DaemonOptionValueUriCB
{
  /**
   * the early URI callback
   */
  MHD_EarlyUriLogCallback v_cb;

  /**
   * the closure for the callback
   */
  void *v_cls;

};

/**
 * Data for #MHD_D_O_DAEMON_READY_CALLBACK
 */
struct MHD_DaemonOptionValueReadyCB
{
  /**
   * the pre-start callback
   */
  MHD_DaemonReadyCallback v_cb;

  /**
   * the closure for the callback
   */
  void *v_cb_cls;

};

/**
 * Data for #MHD_D_O_NOTIFY_CONNECTION
 */
struct MHD_DaemonOptionValueNotifConnCB
{
  /**
   * the callback for notifications
   */
  MHD_NotifyConnectionCallback v_ncc;

  /**
   * the closure for the callback
   */
  void *v_cls;

};

/**
 * Data for #MHD_D_O_NOTIFY_STREAM
 */
struct MHD_DaemonOptionValueNotifStreamCB
{
  /**
   * the callback for notifications
   */
  MHD_NotifyStreamCallback v_nsc;

  /**
   * the closure for the callback
   */
  void *v_cls;

};

/**
 * Data for #MHD_D_O_RANDOM_ENTROPY
 */
struct MHD_DaemonOptionEntropySeed
{
  /**
   * the size of the buffer
   */
  size_t v_buf_size;

  /**
   * the buffer with strong random data, the content will be copied by MHD
   */
  /* const */ void *v_buf;

};

/**
 * Parameters for MHD daemon options
 */
union MHD_DaemonOptionValue
{
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
   * Value for #MHD_D_O_TLS_CERT_KEY.
   * The X.509 certificates chain in PEM format loaded into memory (not a filename).
   * The first certificate must be the server certificate, following by the chain of signing
   * certificates up to (but not including) CA root certificate.
   */
  struct MHD_DaemonOptionValueTlsCert tls_cert_key;

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
   * Value for #MHD_D_O_AUTH_DIGEST_MAP_SIZE.
   * the size of the map array
   */
  size_t auth_digest_map_size;

  /**
   * Value for #MHD_D_O_AUTH_DIGEST_NONCE_TIMEOUT.
   * FIXME
   */
  unsigned int auth_digest_nonce_timeout;

  /**
   * Value for #MHD_D_O_AUTH_DIGEST_DEF_MAX_NC.
   * FIXME
   */
  uint_fast32_t auth_digest_def_max_nc;

};


struct MHD_DaemonOptionAndValue
{
  /**
   * The daemon configuration option
   */
  enum MHD_DaemonOption opt;

  /**
   * The value for the @a opt option
   */
  union MHD_DaemonOptionValue val;
};

#if defined(MHD_USE_COMPOUND_LITERALS) && defined(MHD_USE_DESIG_NEST_INIT)
/**
 * Set MHD work (threading and polling) mode.
 * Consider use of #MHD_D_OPTION_WM_EXTERNAL_PERIODIC(), #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL(), #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_EDGE(), #MHD_D_OPTION_WM_EXTERNAL_SINGLE_FD_WATCH(), #MHD_D_OPTION_WM_WORKER_THREADS() or #MHD_D_OPTION_WM_THREAD_PER_CONNECTION() instead of direct use of this parameter.
 * @param wmp the object created by one of the next functions/macros: #MHD_WM_OPTION_EXTERNAL_PERIODIC(), #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL(), #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE(), #MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH(), #MHD_WM_OPTION_WORKER_THREADS(), #MHD_WM_OPTION_THREAD_PER_CONNECTION()
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_WORK_MODE(wmp) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_WORK_MODE,  \
          .val.work_mode = (wmp) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Select a sockets watch system call used for internal polling.
 * @param els FIXME
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_POLL_SYSCALL(els) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_POLL_SYSCALL,  \
          .val.poll_syscall = (els) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Set a callback to use for logging
 * @param log_cb the callback to use for logging,
 *   NULL to disable logging
 * @param log_cb_cls the closure for the logging callback
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_LOG_CALLBACK(log_cb,log_cb_cls) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_LOG_CALLBACK,  \
          .val.log_callback.v_log_cb = (log_cb), \
          .val.log_callback.v_log_cb_cls = (log_cb_cls) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Bind to the given TCP port and address family.
 *
Does not work with #MHD_D_OPTION_BIND_SA() or #MHD_D_OPTION_LISTEN_SOCKET().
 *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
 * @param af the address family to use,
 *   the #MHD_AF_NONE to disable listen socket (the same effect as if this option is not used)
 * @param port port to use, 0 to let system assign any free port,
 *   ignored if @a af is #MHD_AF_NONE
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_BIND_PORT(af,port) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_BIND_PORT,  \
          .val.bind_port.v_af = (af), \
          .val.bind_port.v_port = (port) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Bind to the given socket address.
 *
Does not work with #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_LISTEN_SOCKET().
 *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
 * @param sa_len the size of the socket address pointed by @a sa.
 * @param sa the address to bind to; can be IPv4 (AF_INET), IPv6 (AF_INET6) or even a UNIX domain socket (AF_UNIX)
 * @param dual When a previous version of the protocol exist (like IPv4 when @a v_sa is IPv6) bind to both protocols (IPv6 and IPv4).
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_BIND_SA(sa_len,sa,dual) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_BIND_SA,  \
          .val.bind_sa.v_sa_len = (sa_len), \
          .val.bind_sa.v_sa = (sa), \
          .val.bind_sa.v_dual = (dual) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Accept connections from the given socket.  Socket
 * must be a TCP or UNIX domain (SOCK_STREAM) socket.
 *
Does not work with #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA().
 *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
 * @param listen_fd the listen socket to use, ignored if set to #MHD_INVALID_SOCKET
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_LISTEN_SOCKET(listen_fd) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_LISTEN_SOCKET,  \
          .val.listen_socket = (listen_fd) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Select mode of reusing address:port listen address.
 *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
 * @param reuse_type FIXME
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_LISTEN_ADDR_REUSE(reuse_type) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_LISTEN_ADDR_REUSE,  \
          .val.listen_addr_reuse = (reuse_type) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Configure TCP_FASTOPEN option, including setting a
 * custom @a queue_length.
 *
Note that having a larger queue size can cause resource exhaustion
 * attack as the TCP stack has to now allocate resources for the SYN
 * packet along with its DATA.
 *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
 * @param option the type use of of TCP FastOpen
 * @param queue_length the length of the queue, zero to use system or MHD default,
 *   silently ignored on platforms without support for custom queue size
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_TCP_FASTOPEN(option,queue_length) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_TCP_FASTOPEN,  \
          .val.tcp_fastopen.v_option = (option), \
          .val.tcp_fastopen.v_queue_length = (queue_length) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Use the given backlog for the listen() call.
 *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
 * Zero parameter treated as MHD/system default.
 * @param backlog_size FIXME
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_LISTEN_BACKLOG(backlog_size) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_LISTEN_BACKLOG,  \
          .val.listen_backlog = (backlog_size) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Inform that SIGPIPE is suppressed or handled by application.
 * If suppressed/handled, MHD uses network functions that could generate SIGPIPE, like `sendfile()`.
 * Silently ignored when MHD creates internal threads as for them SIGPIPE is suppressed automatically.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_SIGPIPE_SUPPRESSED(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_SIGPIPE_SUPPRESSED,  \
          .val.sigpipe_suppressed = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Enable TLS (HTTPS) and select TLS backend
 * @param backend the TLS backend to use,
 *   #MHD_TLS_BACKEND_NONE for non-TLS (plain TCP) connections
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_TLS(backend) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_TLS,  \
          .val.tls = (backend) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Provide TLS key and certificate data in-memory.
 * Works only if TLS mode is enabled.
 * @param mem_cert The X.509 certificates chain in PEM format loaded into memory (not a filename).
 *   The first certificate must be the server certificate, following by the chain of signing
 *   certificates up to (but not including) CA root certificate.
 * @param mem_key the private key in PEM format loaded into memory (not a filename)
 * @param mem_pass the option passphrase phrase to decrypt the private key,
 *   could be NULL if private key does not need a password
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_TLS_CERT_KEY(mem_cert,mem_key,mem_pass) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_TLS_CERT_KEY,  \
          .val.tls_cert_key.v_mem_cert = (mem_cert), \
          .val.tls_cert_key.v_mem_key = (mem_key), \
          .val.tls_cert_key.v_mem_pass = (mem_pass) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Provide the certificate of the certificate authority (CA) to be used by the MHD daemon for client authentication.
 * Works only if TLS mode is enabled.
 * @param mem_client_ca the CA certificate in memory (not a filename)
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_TLS_CLIENT_CA(mem_client_ca) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_TLS_CLIENT_CA,  \
          .val.tls_client_ca = (mem_client_ca) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Configure PSK to use for the TLS key exchange.
 * @param psk_cb the function to call to obtain pre-shared key
 * @param psk_cb_cls the closure for @a psk_cb
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_TLS_PSK_CALLBACK(psk_cb,psk_cb_cls) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_TLS_PSK_CALLBACK,  \
          .val.tls_psk_callback.v_psk_cb = (psk_cb), \
          .val.tls_psk_callback.v_psk_cb_cls = (psk_cb_cls) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Control ALPN for TLS connection.
 * Silently ignored for non-TLS.
 * By default ALPN is automatically used for TLS connections.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_NO_ALPN(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_NO_ALPN,  \
          .val.no_alpn = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Specify inactivity timeout for connection.
 * When no activity for specified time on connection, it is closed automatically.
 * Use zero for no timeout, which is also the (unsafe!) default.
 * @param timeout the in seconds, zero for no timeout
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_DEFAULT_TIMEOUT(timeout) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_DEFAULT_TIMEOUT,  \
          .val.default_timeout = (timeout) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Maximum number of (concurrent) network connections served by daemon.
 * @note The real maximum number of network connections could be smaller
 *       than requested due to the system limitations, like FD_SETSIZE when
 *       polling by select() is used.
 * @param glob_limit FIXME
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_GLOBAL_CONNECTION_LIMIT(glob_limit) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_GLOBAL_CONNECTION_LIMIT,  \
          .val.global_connection_limit = (glob_limit) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Limit on the number of (concurrent) network connections made to the server from the same IP address.
 * Can be used to prevent one IP from taking over all of the allowed connections. If the same IP tries to establish more than the specified number of connections, they will be immediately rejected.
 * @param limit FIXME
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_PER_IP_LIMIT(limit) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_PER_IP_LIMIT,  \
          .val.per_ip_limit = (limit) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Set a policy callback that accepts/rejects connections based on the client's IP address.  The callbeck function will be called before servicing any new incoming connection.
 * @param apc the accept policy callback
 * @param apc_cls the closure for the callback
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_ACCEPT_POLICY(apc,apc_cls) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_ACCEPT_POLICY,  \
          .val.accept_policy.v_apc = (apc), \
          .val.accept_policy.v_apc_cls = (apc_cls) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Set how strictly MHD will enforce the HTTP protocol.
 * @param sl the level of strictness
 * @param how the way how to use the requested level
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_PROTOCOL_STRICT_LEVEL(sl,how) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_PROTOCOL_STRICT_LEVEL,  \
          .val.protocol_strict_level.v_sl = (sl), \
          .val.protocol_strict_level.v_how = (how) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Set a callback to be called first for every request when the request line is received (before any parsing of the header).
 * This callback is the only way to get raw (unmodified) request URI as URI is parsed and modified by MHD in-place.
 * Mandatory URI modification may apply before this call, like binary zero replacement, as required by RFCs.
 * @param cb the early URI callback
 * @param cls the closure for the callback
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_EARLY_URI_LOGGER(cb,cls) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_EARLY_URI_LOGGER,  \
          .val.early_uri_logger.v_cb = (cb), \
          .val.early_uri_logger.v_cls = (cls) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Disable converting plus ('+') character to space in GET parameters (URI part after '?').
 * Plus conversion is not required by HTTP RFCs, however it required by HTML specifications, see https://url.spec.whatwg.org/#application/x-www-form-urlencoded for details.
 * By default plus is converted to space in the query part of URI.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_DISABLE_URI_QUERY_PLUS_AS_SPACE(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_DISABLE_URI_QUERY_PLUS_AS_SPACE,  \
          .val.disable_uri_query_plus_as_space = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Suppresse use of 'Date:' header.
 * According to RFC should be suppressed only if the system has no RTC.
 * The 'Date:' is not suppressed (the header is enabled) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_SUPPRESS_DATE_HEADER(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_SUPPRESS_DATE_HEADER,  \
          .val.suppress_date_header = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Use SHOUTcast for responses.
 * This will cause *all* responses to begin with the SHOUTcast 'ICY' line instead of 'HTTP'.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_ENABLE_SHOUTCAST(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_ENABLE_SHOUTCAST,  \
          .val.enable_shoutcast = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Maximum memory size per connection.
 * Default is 32kb.
 * Values above 128kb are unlikely to result in much performance benefit, as half of the memory will be typically used for IO, and TCP buffers are unlikely to support window sizes above 64k on most systems.
 * The size should be large enough to fit all request headers (together with internal parsing information).
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_CONN_MEMORY_LIMIT(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_CONN_MEMORY_LIMIT,  \
          .val.conn_memory_limit = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * The size of the shared memory pool for accamulated upload processing.
 * The same large pool is shared for all connections server by MHD and used when application requests avoiding of incremental upload processing to accamulate complete content upload before giving it to the application.
 * Default is 8Mb.
 * Can be set to zero to disable share pool.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_LARGE_POOL_SIZE(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_LARGE_POOL_SIZE,  \
          .val.large_pool_size = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Desired size of the stack for the threads started by MHD.
 * Use 0 for system default, which is also MHD default.
 * Works only with #MHD_D_OPTION_WM_WORKER_THREADS() or #MHD_D_OPTION_WM_THREAD_PER_CONNECTION().
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_STACK_SIZE(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_STACK_SIZE,  \
          .val.stack_size = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * The the maximum FD value.
 * The limit is applied to all sockets used by MHD.
 * If listen socket FD is equal or higher that specified value, the daemon fail to start.
 * If new connection FD is equal or higher that specified value, the connection is rejected.
 * Useful if application uses select() for polling the sockets, system FD_SETSIZE is good value for this option in such case.
 * Silently ignored on W32 (WinSock sockets).
 * @param max_fd FIXME
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_FD_NUMBER_LIMIT(max_fd) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_FD_NUMBER_LIMIT,  \
          .val.fd_number_limit = (max_fd) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Enable `turbo`.
 * Disables certain calls to `shutdown()`, enables aggressive non-blocking optimistic reads and other potentially unsafe optimisations.
 * Most effects only happen with internal threads with epoll.
 * The 'turbo' mode is not enabled (mode is disabled) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_TURBO(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_TURBO,  \
          .val.turbo = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Disable some internal thread safety.
 * Indicates that MHD daemon will be used by application in single-threaded mode only.  When this flag is set then application must call any MHD function only within a single thread.
 * This flag turns off some internal thread-safety and allows MHD making some of the internal optimisations suitable only for single-threaded environment.
 * Not compatible with any internal threads modes.
 * If MHD is compiled with custom configuration for embedded projects without threads support, this option is mandatory.
 * Thread safety is not disabled (safety is enabled) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_DISABLE_THREAD_SAFETY(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_DISABLE_THREAD_SAFETY,  \
          .val.disable_thread_safety = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * You need to set this option if you want to disable use of HTTP Upgrade.
 * Upgrade may require usage of additional internal resources, which we can avoid providing if they will not be used.
 * You should only use this option if you do not use upgrade functionality and need a generally minor boost in performance and resources saving.
 * The upgrade is not disallowed (upgrade is allowed) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_DISALLOW_UPGRADE(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_DISALLOW_UPGRADE,  \
          .val.disallow_upgrade = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Disable #MHD_action_suspend() functionality.
 *
You should only use this function if you do not use suspend functionality and need a generally minor boost in performance.
 * The suspend is not disallowed (suspend is allowed) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
#  define MHD_D_OPTION_DISALLOW_SUSPEND_RESUME(value) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_DISALLOW_SUSPEND_RESUME,  \
          .val.disallow_suspend_resume = (value) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Set a callback to be called for pre-start finalisation.
 *
The specified callback will be called one time, after network initialisation, TLS pre-initialisation, but before the start of the internal threads (if allowed)
 * @param cb the pre-start callback
 * @param cb_cls the closure for the callback
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_DAEMON_READY_CALLBACK(cb,cb_cls) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_DAEMON_READY_CALLBACK,  \
          .val.daemon_ready_callback.v_cb = (cb), \
          .val.daemon_ready_callback.v_cb_cls = (cb_cls) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Set a function that should be called whenever a connection is started or closed.
 * @param ncc the callback for notifications
 * @param cls the closure for the callback
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_NOTIFY_CONNECTION(ncc,cls) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_NOTIFY_CONNECTION,  \
          .val.notify_connection.v_ncc = (ncc), \
          .val.notify_connection.v_cls = (cls) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Register a function that should be called whenever a stream is started or closed.
 * For HTTP/1.1 this callback is called one time for every connection.
 * @param nsc the callback for notifications
 * @param cls the closure for the callback
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_NOTIFY_STREAM(nsc,cls) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_NOTIFY_STREAM,  \
          .val.notify_stream.v_nsc = (nsc), \
          .val.notify_stream.v_cls = (cls) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Set strong random data to be used by MHD.
 * Currently the data is only needed for Digest Auth module.
 * Daemon support for Digest Auth is enabled automatically if this option is used.
 * The recommended size is between 8 and 32 bytes. Security can be lower for sizes less or equal four.
 * Sizes larger then 32 (or, probably, larger than 16 - debatable) will not increase the security.
 * @param buf_size the size of the buffer
 * @param buf the buffer with strong random data, the content will be copied by MHD
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_RANDOM_ENTROPY(buf_size,buf) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_RANDOM_ENTROPY,  \
          .val.random_entropy.v_buf_size = (buf_size), \
          .val.random_entropy.v_buf = (buf) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Specify the size of the internal hash map array that tracks generated digest nonces usage.
 * When the size of the map is too small then need to handle concurrent DAuth requests, a lot of stale nonce results will be produced.
 * By default the size is 1000 entries.
 * @param size the size of the map array
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_AUTH_DIGEST_MAP_SIZE(size) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_AUTH_DIGEST_MAP_SIZE,  \
          .val.auth_digest_map_size = (size) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Nonce validity time (in seconds) used for Digest Auth.
 * If followed by zero value the value is silently ignored.
 * @see #MHD_digest_auth_check(), MHD_digest_auth_check_digest()
 * @param timeout FIXME
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_AUTH_DIGEST_NONCE_TIMEOUT(timeout) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_AUTH_DIGEST_NONCE_TIMEOUT,  \
          .val.auth_digest_nonce_timeout = (timeout) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Default maximum nc (nonce count) value used for Digest Auth.
 * If followed by zero value the value is silently ignored.
 * @see #MHD_digest_auth_check(), MHD_digest_auth_check_digest()
 * @param max_nc FIXME
 * @return structure with the requested setting
 */
#  define MHD_D_OPTION_AUTH_DIGEST_DEF_MAX_NC(max_nc) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = MHD_D_O_AUTH_DIGEST_DEF_MAX_NC,  \
          .val.auth_digest_def_max_nc = (max_nc) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_DaemonOptionAndValue
 */
#  define MHD_D_OPTION_TERMINATE() \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_DaemonOptionAndValue) \
        { \
          .opt = (MHD_D_O_END) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

#else /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */
MHD_NOWARN_UNUSED_FUNC_
/**
 * Set MHD work (threading and polling) mode.
 * Consider use of #MHD_D_OPTION_WM_EXTERNAL_PERIODIC(), #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_LEVEL(), #MHD_D_OPTION_WM_EXTERNAL_EVENT_LOOP_CB_EDGE(), #MHD_D_OPTION_WM_EXTERNAL_SINGLE_FD_WATCH(), #MHD_D_OPTION_WM_WORKER_THREADS() or #MHD_D_OPTION_WM_THREAD_PER_CONNECTION() instead of direct use of this parameter.
 * @param wmp the object created by one of the next functions/macros: #MHD_WM_OPTION_EXTERNAL_PERIODIC(), #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_LEVEL(), #MHD_WM_OPTION_EXTERNAL_EVENT_LOOP_CB_EDGE(), #MHD_WM_OPTION_EXTERNAL_SINGLE_FD_WATCH(), #MHD_WM_OPTION_WORKER_THREADS(), #MHD_WM_OPTION_THREAD_PER_CONNECTION()
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_WORK_MODE (
  struct MHD_WorkModeWithParam wmp
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_WORK_MODE;
  opt_val.val.work_mode = wmp;

  return opt_val;
}


/**
 * Select a sockets watch system call used for internal polling.
 * @param els FIXME
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_POLL_SYSCALL (
  enum MHD_SockPollSyscall els
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_POLL_SYSCALL;
  opt_val.val.poll_syscall = els;

  return opt_val;
}


/**
 * Set a callback to use for logging
 * @param log_cb the callback to use for logging,
 *   NULL to disable logging
 * @param log_cb_cls the closure for the logging callback
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LOG_CALLBACK (
  MHD_LoggingCallback log_cb,
  void *log_cb_cls
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_LOG_CALLBACK;
  opt_val.val.log_callback.v_log_cb = log_cb;
  opt_val.val.log_callback.v_log_cb_cls = log_cb_cls;

  return opt_val;
}


/**
 * Bind to the given TCP port and address family.
 *
Does not work with #MHD_D_OPTION_BIND_SA() or #MHD_D_OPTION_LISTEN_SOCKET().
 *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
 * @param af the address family to use,
 *   the #MHD_AF_NONE to disable listen socket (the same effect as if this option is not used)
 * @param port port to use, 0 to let system assign any free port,
 *   ignored if @a af is #MHD_AF_NONE
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_BIND_PORT (
  enum MHD_AddressFamily af,
  uint_least16_t port
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_BIND_PORT;
  opt_val.val.bind_port.v_af = af;
  opt_val.val.bind_port.v_port = port;

  return opt_val;
}


/**
 * Bind to the given socket address.
 *
Does not work with #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_LISTEN_SOCKET().
 *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
 * @param sa_len the size of the socket address pointed by @a sa.
 * @param sa the address to bind to; can be IPv4 (AF_INET), IPv6 (AF_INET6) or even a UNIX domain socket (AF_UNIX)
 * @param dual When a previous version of the protocol exist (like IPv4 when @a v_sa is IPv6) bind to both protocols (IPv6 and IPv4).
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_BIND_SA (
  size_t sa_len,
  /* const */ struct sockaddr *sa,
  enum MHD_Bool dual
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_BIND_SA;
  opt_val.val.bind_sa.v_sa_len = sa_len;
  opt_val.val.bind_sa.v_sa = sa;
  opt_val.val.bind_sa.v_dual = dual;

  return opt_val;
}


/**
 * Accept connections from the given socket.  Socket
 * must be a TCP or UNIX domain (SOCK_STREAM) socket.
 *
Does not work with #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA().
 *
If no listen socket optins (#MHD_D_OPTION_BIND_PORT(), #MHD_D_OPTION_BIND_SA(), #MHD_D_OPTION_LISTEN_SOCKET()) are used, MHD does not listen for incoming connection.
 * @param listen_fd the listen socket to use, ignored if set to #MHD_INVALID_SOCKET
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LISTEN_SOCKET (
  MHD_Socket listen_fd
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_LISTEN_SOCKET;
  opt_val.val.listen_socket = listen_fd;

  return opt_val;
}


/**
 * Select mode of reusing address:port listen address.
 *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
 * @param reuse_type FIXME
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LISTEN_ADDR_REUSE (
  enum MHD_DaemonOptionBindType reuse_type
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_LISTEN_ADDR_REUSE;
  opt_val.val.listen_addr_reuse = reuse_type;

  return opt_val;
}


/**
 * Configure TCP_FASTOPEN option, including setting a
 * custom @a queue_length.
 *
Note that having a larger queue size can cause resource exhaustion
 * attack as the TCP stack has to now allocate resources for the SYN
 * packet along with its DATA.
 *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
 * @param option the type use of of TCP FastOpen
 * @param queue_length the length of the queue, zero to use system or MHD default,
 *   silently ignored on platforms without support for custom queue size
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TCP_FASTOPEN (
  enum MHD_TCPFastOpenType option,
  unsigned int queue_length
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_TCP_FASTOPEN;
  opt_val.val.tcp_fastopen.v_option = option;
  opt_val.val.tcp_fastopen.v_queue_length = queue_length;

  return opt_val;
}


/**
 * Use the given backlog for the listen() call.
 *
Works only when #MHD_D_OPTION_BIND_PORT() or #MHD_D_OPTION_BIND_SA() are used.
 * Zero parameter treated as MHD/system default.
 * @param backlog_size FIXME
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LISTEN_BACKLOG (
  unsigned int backlog_size
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_LISTEN_BACKLOG;
  opt_val.val.listen_backlog = backlog_size;

  return opt_val;
}


/**
 * Inform that SIGPIPE is suppressed or handled by application.
 * If suppressed/handled, MHD uses network functions that could generate SIGPIPE, like `sendfile()`.
 * Silently ignored when MHD creates internal threads as for them SIGPIPE is suppressed automatically.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_SIGPIPE_SUPPRESSED (
  enum MHD_Bool value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_SIGPIPE_SUPPRESSED;
  opt_val.val.sigpipe_suppressed = (value); \

  return opt_val;
}


/**
 * Enable TLS (HTTPS) and select TLS backend
 * @param backend the TLS backend to use,
 *   #MHD_TLS_BACKEND_NONE for non-TLS (plain TCP) connections
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TLS (
  enum MHD_TlsBackend backend
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_TLS;
  opt_val.val.tls = backend;

  return opt_val;
}


/**
 * Provide TLS key and certificate data in-memory.
 * Works only if TLS mode is enabled.
 * @param mem_cert The X.509 certificates chain in PEM format loaded into memory (not a filename).
 *   The first certificate must be the server certificate, following by the chain of signing
 *   certificates up to (but not including) CA root certificate.
 * @param mem_key the private key in PEM format loaded into memory (not a filename)
 * @param mem_pass the option passphrase phrase to decrypt the private key,
 *   could be NULL if private key does not need a password
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TLS_CERT_KEY (
  /* const */ char *mem_cert,
  const char *mem_key,
  const char *mem_pass
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_TLS_CERT_KEY;
  opt_val.val.tls_cert_key.v_mem_cert = mem_cert;
  opt_val.val.tls_cert_key.v_mem_key = mem_key;
  opt_val.val.tls_cert_key.v_mem_pass = mem_pass;

  return opt_val;
}


/**
 * Provide the certificate of the certificate authority (CA) to be used by the MHD daemon for client authentication.
 * Works only if TLS mode is enabled.
 * @param mem_client_ca the CA certificate in memory (not a filename)
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TLS_CLIENT_CA (
  const char *mem_client_ca
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_TLS_CLIENT_CA;
  opt_val.val.tls_client_ca = mem_client_ca;

  return opt_val;
}


/**
 * Configure PSK to use for the TLS key exchange.
 * @param psk_cb the function to call to obtain pre-shared key
 * @param psk_cb_cls the closure for @a psk_cb
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TLS_PSK_CALLBACK (
  MHD_PskServerCredentialsCallback psk_cb,
  void *psk_cb_cls
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_TLS_PSK_CALLBACK;
  opt_val.val.tls_psk_callback.v_psk_cb = psk_cb;
  opt_val.val.tls_psk_callback.v_psk_cb_cls = psk_cb_cls;

  return opt_val;
}


/**
 * Control ALPN for TLS connection.
 * Silently ignored for non-TLS.
 * By default ALPN is automatically used for TLS connections.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_NO_ALPN (
  enum MHD_Bool value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_NO_ALPN;
  opt_val.val.no_alpn = (value); \

  return opt_val;
}


/**
 * Specify inactivity timeout for connection.
 * When no activity for specified time on connection, it is closed automatically.
 * Use zero for no timeout, which is also the (unsafe!) default.
 * @param timeout the in seconds, zero for no timeout
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DEFAULT_TIMEOUT (
  unsigned int timeout
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_DEFAULT_TIMEOUT;
  opt_val.val.default_timeout = timeout;

  return opt_val;
}


/**
 * Maximum number of (concurrent) network connections served by daemon.
 * @note The real maximum number of network connections could be smaller
 *       than requested due to the system limitations, like FD_SETSIZE when
 *       polling by select() is used.
 * @param glob_limit FIXME
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_GLOBAL_CONNECTION_LIMIT (
  unsigned int glob_limit
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_GLOBAL_CONNECTION_LIMIT;
  opt_val.val.global_connection_limit = glob_limit;

  return opt_val;
}


/**
 * Limit on the number of (concurrent) network connections made to the server from the same IP address.
 * Can be used to prevent one IP from taking over all of the allowed connections. If the same IP tries to establish more than the specified number of connections, they will be immediately rejected.
 * @param limit FIXME
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_PER_IP_LIMIT (
  unsigned int limit
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_PER_IP_LIMIT;
  opt_val.val.per_ip_limit = limit;

  return opt_val;
}


/**
 * Set a policy callback that accepts/rejects connections based on the client's IP address.  The callbeck function will be called before servicing any new incoming connection.
 * @param apc the accept policy callback
 * @param apc_cls the closure for the callback
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_ACCEPT_POLICY (
  MHD_AcceptPolicyCallback apc,
  void *apc_cls
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_ACCEPT_POLICY;
  opt_val.val.accept_policy.v_apc = apc;
  opt_val.val.accept_policy.v_apc_cls = apc_cls;

  return opt_val;
}


/**
 * Set how strictly MHD will enforce the HTTP protocol.
 * @param sl the level of strictness
 * @param how the way how to use the requested level
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_PROTOCOL_STRICT_LEVEL (
  enum MHD_ProtocolStrictLevel sl,
  enum MHD_UseStictLevel how
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_PROTOCOL_STRICT_LEVEL;
  opt_val.val.protocol_strict_level.v_sl = sl;
  opt_val.val.protocol_strict_level.v_how = how;

  return opt_val;
}


/**
 * Set a callback to be called first for every request when the request line is received (before any parsing of the header).
 * This callback is the only way to get raw (unmodified) request URI as URI is parsed and modified by MHD in-place.
 * Mandatory URI modification may apply before this call, like binary zero replacement, as required by RFCs.
 * @param cb the early URI callback
 * @param cls the closure for the callback
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_EARLY_URI_LOGGER (
  MHD_EarlyUriLogCallback cb,
  void *cls
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_EARLY_URI_LOGGER;
  opt_val.val.early_uri_logger.v_cb = cb;
  opt_val.val.early_uri_logger.v_cls = cls;

  return opt_val;
}


/**
 * Disable converting plus ('+') character to space in GET parameters (URI part after '?').
 * Plus conversion is not required by HTTP RFCs, however it required by HTML specifications, see https://url.spec.whatwg.org/#application/x-www-form-urlencoded for details.
 * By default plus is converted to space in the query part of URI.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DISABLE_URI_QUERY_PLUS_AS_SPACE (
  enum MHD_Bool value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_DISABLE_URI_QUERY_PLUS_AS_SPACE;
  opt_val.val.disable_uri_query_plus_as_space = (value); \

  return opt_val;
}


/**
 * Suppresse use of 'Date:' header.
 * According to RFC should be suppressed only if the system has no RTC.
 * The 'Date:' is not suppressed (the header is enabled) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_SUPPRESS_DATE_HEADER (
  enum MHD_Bool value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_SUPPRESS_DATE_HEADER;
  opt_val.val.suppress_date_header = (value); \

  return opt_val;
}


/**
 * Use SHOUTcast for responses.
 * This will cause *all* responses to begin with the SHOUTcast 'ICY' line instead of 'HTTP'.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_ENABLE_SHOUTCAST (
  enum MHD_Bool value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_ENABLE_SHOUTCAST;
  opt_val.val.enable_shoutcast = (value); \

  return opt_val;
}


/**
 * Maximum memory size per connection.
 * Default is 32kb.
 * Values above 128kb are unlikely to result in much performance benefit, as half of the memory will be typically used for IO, and TCP buffers are unlikely to support window sizes above 64k on most systems.
 * The size should be large enough to fit all request headers (together with internal parsing information).
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_CONN_MEMORY_LIMIT (
  size_t value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_CONN_MEMORY_LIMIT;
  opt_val.val.conn_memory_limit = (value); \

  return opt_val;
}


/**
 * The size of the shared memory pool for accamulated upload processing.
 * The same large pool is shared for all connections server by MHD and used when application requests avoiding of incremental upload processing to accamulate complete content upload before giving it to the application.
 * Default is 8Mb.
 * Can be set to zero to disable share pool.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_LARGE_POOL_SIZE (
  size_t value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_LARGE_POOL_SIZE;
  opt_val.val.large_pool_size = (value); \

  return opt_val;
}


/**
 * Desired size of the stack for the threads started by MHD.
 * Use 0 for system default, which is also MHD default.
 * Works only with #MHD_D_OPTION_WM_WORKER_THREADS() or #MHD_D_OPTION_WM_THREAD_PER_CONNECTION().
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_STACK_SIZE (
  size_t value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_STACK_SIZE;
  opt_val.val.stack_size = (value); \

  return opt_val;
}


/**
 * The the maximum FD value.
 * The limit is applied to all sockets used by MHD.
 * If listen socket FD is equal or higher that specified value, the daemon fail to start.
 * If new connection FD is equal or higher that specified value, the connection is rejected.
 * Useful if application uses select() for polling the sockets, system FD_SETSIZE is good value for this option in such case.
 * Silently ignored on W32 (WinSock sockets).
 * @param max_fd FIXME
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_FD_NUMBER_LIMIT (
  MHD_Socket max_fd
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_FD_NUMBER_LIMIT;
  opt_val.val.fd_number_limit = max_fd;

  return opt_val;
}


/**
 * Enable `turbo`.
 * Disables certain calls to `shutdown()`, enables aggressive non-blocking optimistic reads and other potentially unsafe optimisations.
 * Most effects only happen with internal threads with epoll.
 * The 'turbo' mode is not enabled (mode is disabled) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TURBO (
  enum MHD_Bool value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_TURBO;
  opt_val.val.turbo = (value); \

  return opt_val;
}


/**
 * Disable some internal thread safety.
 * Indicates that MHD daemon will be used by application in single-threaded mode only.  When this flag is set then application must call any MHD function only within a single thread.
 * This flag turns off some internal thread-safety and allows MHD making some of the internal optimisations suitable only for single-threaded environment.
 * Not compatible with any internal threads modes.
 * If MHD is compiled with custom configuration for embedded projects without threads support, this option is mandatory.
 * Thread safety is not disabled (safety is enabled) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DISABLE_THREAD_SAFETY (
  enum MHD_Bool value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_DISABLE_THREAD_SAFETY;
  opt_val.val.disable_thread_safety = (value); \

  return opt_val;
}


/**
 * You need to set this option if you want to disable use of HTTP Upgrade.
 * Upgrade may require usage of additional internal resources, which we can avoid providing if they will not be used.
 * You should only use this option if you do not use upgrade functionality and need a generally minor boost in performance and resources saving.
 * The upgrade is not disallowed (upgrade is allowed) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DISALLOW_UPGRADE (
  enum MHD_Bool value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_DISALLOW_UPGRADE;
  opt_val.val.disallow_upgrade = (value); \

  return opt_val;
}


/**
 * Disable #MHD_action_suspend() functionality.
 *
You should only use this function if you do not use suspend functionality and need a generally minor boost in performance.
 * The suspend is not disallowed (suspend is allowed) by default.
 * @param value the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DISALLOW_SUSPEND_RESUME (
  enum MHD_Bool value
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_DISALLOW_SUSPEND_RESUME;
  opt_val.val.disallow_suspend_resume = (value); \

  return opt_val;
}


/**
 * Set a callback to be called for pre-start finalisation.
 *
The specified callback will be called one time, after network initialisation, TLS pre-initialisation, but before the start of the internal threads (if allowed)
 * @param cb the pre-start callback
 * @param cb_cls the closure for the callback
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_DAEMON_READY_CALLBACK (
  MHD_DaemonReadyCallback cb,
  void *cb_cls
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_DAEMON_READY_CALLBACK;
  opt_val.val.daemon_ready_callback.v_cb = cb;
  opt_val.val.daemon_ready_callback.v_cb_cls = cb_cls;

  return opt_val;
}


/**
 * Set a function that should be called whenever a connection is started or closed.
 * @param ncc the callback for notifications
 * @param cls the closure for the callback
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_NOTIFY_CONNECTION (
  MHD_NotifyConnectionCallback ncc,
  void *cls
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_NOTIFY_CONNECTION;
  opt_val.val.notify_connection.v_ncc = ncc;
  opt_val.val.notify_connection.v_cls = cls;

  return opt_val;
}


/**
 * Register a function that should be called whenever a stream is started or closed.
 * For HTTP/1.1 this callback is called one time for every connection.
 * @param nsc the callback for notifications
 * @param cls the closure for the callback
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_NOTIFY_STREAM (
  MHD_NotifyStreamCallback nsc,
  void *cls
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_NOTIFY_STREAM;
  opt_val.val.notify_stream.v_nsc = nsc;
  opt_val.val.notify_stream.v_cls = cls;

  return opt_val;
}


/**
 * Set strong random data to be used by MHD.
 * Currently the data is only needed for Digest Auth module.
 * Daemon support for Digest Auth is enabled automatically if this option is used.
 * The recommended size is between 8 and 32 bytes. Security can be lower for sizes less or equal four.
 * Sizes larger then 32 (or, probably, larger than 16 - debatable) will not increase the security.
 * @param buf_size the size of the buffer
 * @param buf the buffer with strong random data, the content will be copied by MHD
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_RANDOM_ENTROPY (
  size_t buf_size,
  /* const */ void *buf
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_RANDOM_ENTROPY;
  opt_val.val.random_entropy.v_buf_size = buf_size;
  opt_val.val.random_entropy.v_buf = buf;

  return opt_val;
}


/**
 * Specify the size of the internal hash map array that tracks generated digest nonces usage.
 * When the size of the map is too small then need to handle concurrent DAuth requests, a lot of stale nonce results will be produced.
 * By default the size is 1000 entries.
 * @param size the size of the map array
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_AUTH_DIGEST_MAP_SIZE (
  size_t size
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_AUTH_DIGEST_MAP_SIZE;
  opt_val.val.auth_digest_map_size = size;

  return opt_val;
}


/**
 * Nonce validity time (in seconds) used for Digest Auth.
 * If followed by zero value the value is silently ignored.
 * @see #MHD_digest_auth_check(), MHD_digest_auth_check_digest()
 * @param timeout FIXME
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_AUTH_DIGEST_NONCE_TIMEOUT (
  unsigned int timeout
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_AUTH_DIGEST_NONCE_TIMEOUT;
  opt_val.val.auth_digest_nonce_timeout = timeout;

  return opt_val;
}


/**
 * Default maximum nc (nonce count) value used for Digest Auth.
 * If followed by zero value the value is silently ignored.
 * @see #MHD_digest_auth_check(), MHD_digest_auth_check_digest()
 * @param max_nc FIXME
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_AUTH_DIGEST_DEF_MAX_NC (
  uint_fast32_t max_nc
  )
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_AUTH_DIGEST_DEF_MAX_NC;
  opt_val.val.auth_digest_def_max_nc = max_nc;

  return opt_val;
}


/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_DaemonOptionAndValue
 */
static MHD_INLINE struct MHD_DaemonOptionAndValue
MHD_D_OPTION_TERMINATE (void)
{
  struct MHD_DaemonOptionAndValue opt_val;

  opt_val.opt = MHD_D_O_END;

  return opt_val;
}


MHD_RESTORE_WARN_UNUSED_FUNC_
#endif /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */
