/* This is generated code, it is still under LGPLv2.1+.
   Do not edit directly! */
/* *INDENT-OFF* */
/**
 * @file response_set_options.c
 * @author response-options-generator.c
 */

#include "mhd_sys_options.h"
#include "sys_bool_type.h"
#include "sys_base_types.h"
#include "sys_malloc.h"
#include <string.h>
#include "mhd_response.h"
#include "response_options.h"
#include "mhd_public_api.h"
#include "mhd_locks.h"
#include "mhd_assert.h"
#include "response_funcs.h"

MHD_FN_PAR_NONNULL_ALL_ MHD_EXTERN_
enum MHD_StatusCode
MHD_response_set_options (
  struct MHD_Response *response,
  const struct MHD_ResponseOptionAndValue *options,
  size_t options_max_num)
{
  struct ResponseOptions *restrict settings = response->settings;
  enum MHD_StatusCode res = MHD_SC_OK;
  size_t i;
  bool need_unlock = false;

  if (response->frozen)
    return MHD_SC_TOO_LATE;
  if (response->reuse.reusable)
  {
    need_unlock = true;
    if (! mhd_mutex_lock(&response->reuse.settings_lock))
      return MHD_SC_RESPONSE_MUTEX_LOCK_FAILED;
    mhd_assert (1 == mhd_atomic_counter_get(&response->reuse.counter));
    if (! response->frozen) /* Firm re-check under the lock */
    {
      mhd_mutex_unlock_chk(&response->reuse.settings_lock);
      return MHD_SC_TOO_LATE;
    }
  }

  for (i = 0; i < options_max_num; i++)
  {
    const struct MHD_ResponseOptionAndValue *const option
      = options + i;
    switch (option->opt)
    {
    case MHD_R_O_END:
      i = options_max_num - 1;
      break;
    case MHD_R_O_REUSABLE:
      settings->reusable = option->val.reusable;
      continue;
    case MHD_R_O_HEAD_ONLY_RESPONSE:
      settings->head_only_response = option->val.head_only_response;
      continue;
    case MHD_R_O_CHUNKED_ENC:
      settings->chunked_enc = option->val.chunked_enc;
      continue;
    case MHD_R_O_CONN_CLOSE:
      settings->conn_close = option->val.conn_close;
      continue;
    case MHD_R_O_HTTP_1_0_COMPATIBLE_STRICT:
      settings->http_1_0_compatible_strict = option->val.http_1_0_compatible_strict;
      continue;
    case MHD_R_O_HTTP_1_0_SERVER:
      settings->http_1_0_server = option->val.http_1_0_server;
      continue;
    case MHD_R_O_INSANITY_HEADER_CONTENT_LENGTH:
      settings->insanity_header_content_length = option->val.insanity_header_content_length;
      continue;
    case MHD_R_O_TERMINATION_CALLBACK:
      settings->termination_callback.v_term_cb = option->val.termination_callback.v_term_cb;
      settings->termination_callback.v_term_cb_cls = option->val.termination_callback.v_term_cb_cls;
      continue;
    case MHD_R_O_SENTINEL:
    default: /* for -Wswitch-default -Wswitch-enum */ 
      res = MHD_SC_OPTION_UNKNOWN;
      i = options_max_num - 1;
      break;
    }
  }

  if (need_unlock)
    mhd_mutex_unlock_chk(&response->reuse.settings_lock);

  return res;
}
