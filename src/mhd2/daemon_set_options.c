/* This is generated code, it is still under LGPLv2.1+.
   Do not edit directly! */
/* *INDENT-OFF* */
/**
 * @file daemon_set_options.c
 * @author daemon-options-generator.c
 */

#include "mhd_sys_options.h"
#include "sys_base_types.h"
#include "sys_malloc.h"
#include <string.h>
#include "mhd_daemon.h"
#include "daemon_options.h"
#include "mhd_public_api.h"

MHD_FN_PAR_NONNULL_ALL_ MHD_EXTERN_
enum MHD_StatusCode
MHD_daemon_set_options (
  struct MHD_Daemon *daemon,
  const struct MHD_DaemonOptionAndValue *options,
  size_t options_max_num)
{
  struct DaemonOptions *const settings = daemon->psettings;
  size_t i;

  if (NULL == settings)
    return MHD_SC_TOO_LATE;

  for (i = 0; i < options_max_num; i++)
  {
    const struct MHD_daemonOptionAndValue *const option = options + i;
    switch (option->opt)
    {
    case MHD_D_O_END:
      return MHD_SC_OK;
    case MHD_D_O_WORK_MODE:
      settings->work_mode = option->val.work_mode;
      continue;
    case MHD_D_O_POLL_SYSCALL:
      settings->poll_syscall = option->val.poll_syscall;
      continue;
    case MHD_D_O_LOG_CALLBACK:
      /* Note: set directly to the daemon */
      daemon->log_params = option->val.log_callback;
      continue;
    case MHD_D_O_BIND_PORT:
      settings->bind_port.v_af = option->val.bind_port.v_af;
      settings->bind_port.v_port = option->val.bind_port.v_port;
      continue;
    case MHD_D_O_BIND_SA:
      /* custom setter */
        if (option->val.bind_sa.v_sa_len > sizeof (bind_sa))
          return MHD_SC_OPTIONS_INVALID;
        memcpy (&settings->bind_sa.ss,
                option->val.bind_sa.v_sa,
                option->val.bind_sa.v_sa_len);
        settings->bind_sa.ss_len = option->val.bind_sa.v_sa_len;
      continue;
    case MHD_D_O_LISTEN_SOCKET:
      settings->listen_socket = option->val.listen_socket;
      continue;
    case MHD_D_O_LISTEN_ADDR_REUSE:
      settings->listen_addr_reuse = option->val.listen_addr_reuse;
      continue;
    case MHD_D_O_TCP_FASTOPEN:
      settings->tcp_fastopen.v_option = option->val.tcp_fastopen.v_option;
      settings->tcp_fastopen.v_queue_length = option->val.tcp_fastopen.v_queue_length;
      continue;
    case MHD_D_O_LISTEN_BACKLOG:
      settings->listen_backlog = option->val.listen_backlog;
      continue;
    case MHD_D_O_SIGPIPE_SUPPRESSED:
      settings->sigpipe_suppressed = option->val.sigpipe_suppressed;
      continue;
    case MHD_D_O_TLS:
      settings->tls = option->val.tls;
      continue;
    case MHD_D_O_TLS_KEY_CERT:
      settings->tls_key_cert.v_mem_key = option->val.tls_key_cert.v_mem_key;
      settings->tls_key_cert.v_mem_cert = option->val.tls_key_cert.v_mem_cert;
      settings->tls_key_cert.v_mem_pass = option->val.tls_key_cert.v_mem_pass;
      continue;
    case MHD_D_O_TLS_CLIENT_CA:
      settings->tls_client_ca = option->val.tls_client_ca;
      continue;
    case MHD_D_O_TLS_PSK_CALLBACK:
      settings->tls_psk_callback.v_psk_cb = option->val.tls_psk_callback.v_psk_cb;
      settings->tls_psk_callback.v_psk_cb_cls = option->val.tls_psk_callback.v_psk_cb_cls;
      continue;
    case MHD_D_O_NO_ALPN:
      settings->no_alpn = option->val.no_alpn;
      continue;
    case MHD_D_O_DEFAULT_TIMEOUT:
      settings->default_timeout = option->val.default_timeout;
      continue;
    case MHD_D_O_GLOBAL_CONNECTION_LIMIT:
      settings->global_connection_limit = option->val.global_connection_limit;
      continue;
    case MHD_D_O_PER_IP_LIMIT:
      settings->per_ip_limit = option->val.per_ip_limit;
      continue;
    case MHD_D_O_ACCEPT_POLICY:
      settings->accept_policy.v_apc = option->val.accept_policy.v_apc;
      settings->accept_policy.v_apc_cls = option->val.accept_policy.v_apc_cls;
      continue;
    case MHD_D_O_PROTOCOL_STRICT_LEVEL:
      settings->protocol_strict_level.v_sl = option->val.protocol_strict_level.v_sl;
      settings->protocol_strict_level.v_how = option->val.protocol_strict_level.v_how;
      continue;
    case MHD_D_O_EARLY_URI_LOGGER:
      settings->early_uri_logger.v_cb = option->val.early_uri_logger.v_cb;
      settings->early_uri_logger.v_cls = option->val.early_uri_logger.v_cls;
      continue;
    case MHD_D_O_DISABLE_URI_QUERY_PLUS_AS_SPACE:
      settings->disable_uri_query_plus_as_space = option->val.disable_uri_query_plus_as_space;
      continue;
    case MHD_D_O_SUPPRESS_DATE_HEADER:
      settings->suppress_date_header = option->val.suppress_date_header;
      continue;
    case MHD_D_O_ENABLE_SHOUTCAST:
      settings->enable_shoutcast = option->val.enable_shoutcast;
      continue;
    case MHD_D_O_CONN_MEMORY_LIMIT:
      settings->conn_memory_limit = option->val.conn_memory_limit;
      continue;
    case MHD_D_O_LARGE_POOL_SIZE:
      settings->large_pool_size = option->val.large_pool_size;
      continue;
    case MHD_D_O_STACK_SIZE:
      settings->stack_size = option->val.stack_size;
      continue;
    case MHD_D_O_FD_NUMBER_LIMIT:
      settings->fd_number_limit = option->val.fd_number_limit;
      continue;
    case MHD_D_O_TURBO:
      settings->turbo = option->val.turbo;
      continue;
    case MHD_D_O_DISABLE_THREAD_SAFETY:
      settings->disable_thread_safety = option->val.disable_thread_safety;
      continue;
    case MHD_D_O_DISALLOW_UPGRADE:
      settings->disallow_upgrade = option->val.disallow_upgrade;
      continue;
    case MHD_D_O_DISALLOW_SUSPEND_RESUME:
      settings->disallow_suspend_resume = option->val.disallow_suspend_resume;
      continue;
    case MHD_D_O_DAEMON_READY_CALLBACK:
      settings->daemon_ready_callback.v_cb = option->val.daemon_ready_callback.v_cb;
      settings->daemon_ready_callback.v_cb_cls = option->val.daemon_ready_callback.v_cb_cls;
      continue;
    case MHD_D_O_NOTIFY_CONNECTION:
      settings->notify_connection.v_ncc = option->val.notify_connection.v_ncc;
      settings->notify_connection.v_cls = option->val.notify_connection.v_cls;
      continue;
    case MHD_D_O_NOTIFY_STREAM:
      settings->notify_stream.v_nsc = option->val.notify_stream.v_nsc;
      settings->notify_stream.v_cls = option->val.notify_stream.v_cls;
      continue;
    case MHD_D_O_RANDOM_ENTROPY:
      /* custom setter */
      if (0 != option->val.random_entropy.v_buf_size)
      {
        MHD_entropy_hash_ (&settings->random_entropy,
                           option->val.random_entropy.v_buf,
                           option->val.random_entropy.v_buf_size);
      }
      continue;
    case MHD_D_O_DAUTH_MAP_SIZE:
      settings->dauth_map_size = option->val.dauth_map_size;
      continue;
    case MHD_D_O_DAUTH_NONCE_BIND_TYPE:
      settings->dauth_nonce_bind_type = option->val.dauth_nonce_bind_type;
      continue;
    case MHD_D_O_DAUTH_DEF_NONCE_TIMEOUT:
      settings->dauth_def_nonce_timeout = option->val.dauth_def_nonce_timeout;
      continue;
    case MHD_D_O_DAUTH_DEF_MAX_NC:
      settings->dauth_def_max_nc = option->val.dauth_def_max_nc;
      continue;
    case MHD_D_O_SENTINEL:
    default: /* for -WFIXME_EG */ 
      break;
    }
    return MHD_SC_OPTION_UNKNOWN;
  }
  return MHD_SC_OK;
}
