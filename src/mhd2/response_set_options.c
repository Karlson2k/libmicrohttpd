/* This is generated code, it is still under LGPLv2.1+.
   Do not edit directly! */
/* *INDENT-OFF* */
/**
 * @file response_set_options.c
 * @author response-options-generator.c
 */

/* EDITED MANUALLY */


#include "mhd_sys_options.h"
#include "response_set_options.h"
#include "sys_base_types.h"
#include "sys_bool_type.h"
#include "response_options.h"
#include "mhd_response.h"
#include "mhd_public_api.h"
#include "mhd_locks.h"
#include "mhd_assert.h"

/**
 * Internal version of the #MHD_response_set_options()
 * Assuming that settings lock is held by the MHD_response_set_options()
 * @param response the response to change
 * @param options the options to use
 * @param options_max_num the maximum number of @a options to use
 * @return #MHD_SC_OK on success, error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ enum MHD_StatusCode
response_set_options_int (
  struct MHD_Response *restrict response,
  const struct MHD_ResponseOptionAndValue *restrict options,
  size_t options_max_num)
{
  struct ResponseOptions *restrict settings;
  size_t i;

  if (response->frozen)
    return MHD_SC_TOO_LATE; /* Re-check under the lock (if any) */

  settings = response->settings;

  for (i = 0; i < options_max_num; i++)
  {
    const struct MHD_ResponseOptionAndValue *const volatile option =
      options + i;

    switch (option->opt)
    {
    case MHD_R_O_END:
      return MHD_SC_OK;
    case MHD_R_O_REUSABLE:
      if (response->reuse.reusable && !option->val.reusable)
        return MHD_SC_RESPONSE_CANNOT_CLEAR_REUSE;
      else if (response->reuse.reusable)
        continue; /* This flag has been set before */
      else
        if (! response_make_reusable(response))
          return MHD_SC_RESPONSE_MUTEX_INIT_FAILED;
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
    default:
      break;
    }
    return MHD_SC_OPTION_UNKNOWN;
  }
  return MHD_SC_OK;
}

MHD_FN_PAR_NONNULL_ALL_ MHD_EXTERN_ enum MHD_StatusCode
MHD_response_set_options (struct MHD_Response *response,
                          const struct MHD_ResponseOptionAndValue *options,
                          size_t options_max_num)
{
  bool need_unlock;
  enum MHD_StatusCode res;

  if (response->frozen)
    return MHD_SC_TOO_LATE;

  need_unlock = false;
  if (response->reuse.reusable)
  {
    need_unlock = true;
    if (! mhd_mutex_lock(&(response->reuse.settings_lock)))
      return MHD_SC_RESPONSE_MUTEX_LOCK_FAILED;
    mhd_assert (1 == mhd_atomic_counter_get(&(response->reuse.counter)));
  }

  res = response_set_options_int(response, options, options_max_num);

  if (need_unlock)
    mhd_mutex_unlock_chk(&(response->reuse.settings_lock));

  return res;
}
