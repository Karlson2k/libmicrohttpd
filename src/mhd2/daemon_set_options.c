/* This is generated code, it is still under LGPLv2.1+.
   Do not edit directly! */
/* *INDENT-OFF* */
/**
 * @file daemon_set_options.c
 * @author daemon-options-generator.c
 */

/* EDITED MANUALLY */

#include "mhd_sys_options.h"
#include "sys_base_types.h"
#include "sys_malloc.h"
#include <string.h>
#include "mhd_daemon.h"
#include "daemon_options.h"
#include "mhd_public_api.h"

enum MHD_StatusCode
MHD_daemon_set_options (
  struct MHD_Daemon *daemon,
  const struct MHD_DaemonOptionAndValue *options,
  size_t options_max_num)
{
  for (size_t i=0;i<options_max_num;i++)
  {
    switch (options[i].opt) {
    case MHD_D_OPTION_WORK_MODE:
      daemon->settings.work_mode = option->val.work_mode;
      continue;
    case MHD_D_OPTION_POLL_SYSCALL:
      daemon->settings.poll_syscall = option->val.poll_syscall;
      continue;
    case MHD_D_OPTION_LOG_CALLBACK:
      daemon->settings.log_callback.v_log_cb = option->val.log_callback.v_log_cb;
      daemon->settings.log_callback.v_lob_cb_cls = option->val.log_callback.v_lob_cb_cls;
      continue;
    case MHD_D_OPTION_BIND_PORT:
      daemon->settings.bind_port.v_af = option->val.bind_port.v_af;
      daemon->settings.bind_port.v_port = option->val.bind_port.v_port;
      continue;
    case MHD_D_OPTION_BIND_SA:
      daemon->settings.bind_sa.v_sa_len = option->val.bind_sa.v_sa_len;
      daemon->settings.bind_sa.v_sa = option->val.bind_sa.v_sa;
      continue;
    case MHD_D_OPTION_LISTEN_SOCKET:
      daemon->settings.listen_socket = option->val.listen_socket;
      continue;
    case MHD_D_OPTION_LISTEN_ADDR_REUSE:
      daemon->settings.listen_addr_reuse = option->val.listen_addr_reuse;
      continue;
    case MHD_D_OPTION_TCP_FASTOPEN:
      daemon->settings.tcp_fastopen.v_option = option->val.tcp_fastopen.v_option;
      daemon->settings.tcp_fastopen.v_queue_length = option->val.tcp_fastopen.v_queue_length;
      continue;
    case MHD_D_OPTION_LISTEN_BACKLOG:
      daemon->settings.listen_backlog = option->val.listen_backlog;
      continue;
    case MHD_D_OPTION_SIGPIPE_SUPPRESSED:
      daemon->settings.sigpipe_suppressed = option->val.sigpipe_suppressed;
      continue;
    case MHD_D_OPTION_TLS:
      daemon->settings.tls = option->val.tls;
      continue;
    case MHD_D_OPTION_TLS_KEY_CERT:
      daemon->settings.tls_key_cert.v_mem_key = option->val.tls_key_cert.v_mem_key;
      daemon->settings.tls_key_cert.v_mem_cert = option->val.tls_key_cert.v_mem_cert;
      daemon->settings.tls_key_cert.v_mem_pass = option->val.tls_key_cert.v_mem_pass;
      continue;
    case MHD_D_OPTION_TLS_CLIENT_CA:
      daemon->settings.tls_client_ca = option->val.tls_client_ca;
      continue;
    case MHD_D_OPTION_TLS_PSK_CALLBACK:
      daemon->settings.tls_psk_callback.v_psk_cb = option->val.tls_psk_callback.v_psk_cb;
      daemon->settings.tls_psk_callback.v_psk_cb_cls = option->val.tls_psk_callback.v_psk_cb_cls;
      continue;
    case MHD_D_OPTION_NO_ALPN:
      daemon->settings.no_alpn = option->val.no_alpn;
      continue;
    case MHD_D_OPTION_DEFAULT_TIMEOUT:
      daemon->settings.default_timeout = option->val.default_timeout;
      continue;
    case MHD_D_OPTION_GLOBAL_CONNECTION_LIMIT:
      daemon->settings.global_connection_limit = option->val.global_connection_limit;
      continue;
    case MHD_D_OPTION_PER_IP_LIMIT:
      daemon->settings.per_ip_limit = option->val.per_ip_limit;
      continue;
    case MHD_D_OPTION_ACCEPT_POLICY:
      daemon->settings.accept_policy.v_apc = option->val.accept_policy.v_apc;
      daemon->settings.accept_policy.v_apc_cls = option->val.accept_policy.v_apc_cls;
      continue;
    case MHD_D_OPTION_PROTOCOL_STRICT_LEVEL:
      daemon->settings.protocol_strict_level.v_sl = option->val.protocol_strict_level.v_sl;
      daemon->settings.protocol_strict_level.v_how = option->val.protocol_strict_level.v_how;
      continue;
    case MHD_D_OPTION_EARLY_URI_LOGGER:
      daemon->settings.early_uri_logger.v_cb = option->val.early_uri_logger.v_cb;
      daemon->settings.early_uri_logger.v_cls = option->val.early_uri_logger.v_cls;
      continue;
    case MHD_D_OPTION_DISABLE_URI_QUERY_PLUS_AS_SPACE:
      daemon->settings.disable_uri_query_plus_as_space = option->val.disable_uri_query_plus_as_space;
      continue;
    case MHD_D_OPTION_SUPPRESS_DATE_HEADER:
      daemon->settings.suppress_date_header = option->val.suppress_date_header;
      continue;
    case MHD_D_OPTION_ENABLE_SHOUTCAST:
      daemon->settings.enable_shoutcast = option->val.enable_shoutcast;
      continue;
    case MHD_D_OPTION_CONN_MEMORY_LIMIT:
      daemon->settings.conn_memory_limit = option->val.conn_memory_limit;
      continue;
    case MHD_D_OPTION_LARGE_POOL_SIZE:
      daemon->settings.large_pool_size = option->val.large_pool_size;
      continue;
    case MHD_D_OPTION_STACK_SIZE:
      daemon->settings.stack_size = option->val.stack_size;
      continue;
    case MHD_D_OPTION_FD_NUMBER_LIMIT:
      daemon->settings.fd_number_limit = option->val.fd_number_limit;
      continue;
    case MHD_D_OPTION_TURBO:
      daemon->settings.turbo = option->val.turbo;
      continue;
    case MHD_D_OPTION_DISABLE_THREAD_SAFETY:
      daemon->settings.disable_thread_safety = option->val.disable_thread_safety;
      continue;
    case MHD_D_OPTION_DISALLOW_UPGRADE:
      daemon->settings.disallow_upgrade = option->val.disallow_upgrade;
      continue;
    case MHD_D_OPTION_DISALLOW_SUSPEND_RESUME:
      daemon->settings.disallow_suspend_resume = option->val.disallow_suspend_resume;
      continue;
    case MHD_D_OPTION_DAEMON_READY_CALLBACK:
      daemon->settings.daemon_ready_callback.v_cb = option->val.daemon_ready_callback.v_cb;
      daemon->settings.daemon_ready_callback.v_cb_cls = option->val.daemon_ready_callback.v_cb_cls;
      continue;
    case MHD_D_OPTION_NOTIFY_CONNECTION:
      daemon->settings.notify_connection.v_ncc = option->val.notify_connection.v_ncc;
      daemon->settings.notify_connection.v_cls = option->val.notify_connection.v_cls;
      continue;
    case MHD_D_OPTION_NOTIFY_STREAM:
      daemon->settings.notify_stream.v_nsc = option->val.notify_stream.v_nsc;
      daemon->settings.notify_stream.v_cls = option->val.notify_stream.v_cls;
      continue;
    case MHD_D_OPTION_RANDOM_ENTROPY:
      daemon->settings.random_entropy.v_buf_size = option->val.random_entropy.v_buf_size;
      daemon->settings.random_entropy.v_buf = option->val.random_entropy.v_buf;
      continue;
    case MHD_D_OPTION_DAUTH_MAP_SIZE:
      daemon->settings.dauth_map_size = option->val.dauth_map_size;
      continue;
    case MHD_D_OPTION_DAUTH_NONCE_BIND_TYPE:
      daemon->settings.dauth_nonce_bind_type = option->val.dauth_nonce_bind_type;
      continue;
    case MHD_D_OPTION_DAUTH_DEF_NONCE_TIMEOUT:
      daemon->settings.dauth_def_nonce_timeout = option->val.dauth_def_nonce_timeout;
      continue;
    case MHD_D_OPTION_DAUTH_DEF_MAX_NC:
      daemon->settings.dauth_def_max_nc = option->val.dauth_def_max_nc;
      continue;
    }
    return MHD_SC_OPTION_UNSUPPORTED;
  }
  return MHD_SC_OK;
}
