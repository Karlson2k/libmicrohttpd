/* This is generated code, it is still under LGPLv2.1+.
   Do not edit directly! */
/* *INDENT-OFF* */
/**
 * @file response_set_options.c
 * @author response-options-generator.c
 */

/* EDITED MANUALLY */


#include "mhd_sys_options.h"
#include "sys_base_types.h"
#include "mhd_response.h"
#include "response_options.h"
#include "mhd_public_api.h"


MHD_FN_PAR_NONNULL_ALL_ MHD_EXTERN_ enum MHD_StatusCode
MHD_response_set_options (struct MHD_Response *response,
                          const struct MHD_ResponseOptionAndValue *options,
                          size_t options_max_num)
{
  size_t i;

  if (response->frozen)
    return MHD_SC_TOO_LATE;

  for (i=0;i<options_max_num;i++)
  {
    const struct MHD_ResponseOptionAndValue *const option = options + i;
    switch (option->opt) {
    case MHD_R_O_END:
      return MHD_SC_OK;
    case MHD_R_OPTION_REUSABLE:
      response->settings.reusable = option->val.reusable;
      continue;
    case MHD_R_OPTION_HEAD_ONLY_RESPONSE:
      response->settings.head_only_response = option->val.head_only_response;
      continue;
    case MHD_R_OPTION_CHUNKED_ENC:
      response->settings.chunked_enc = option->val.chunked_enc;
      continue;
    case MHD_R_OPTION_CONN_CLOSE:
      response->settings.conn_close = option->val.conn_close;
      continue;
    case MHD_R_OPTION_HTTP_1_0_COMPATIBLE_STRICT:
      response->settings.http_1_0_compatible_strict = option->val.http_1_0_compatible_strict;
      continue;
    case MHD_R_OPTION_HTTP_1_0_SERVER:
      response->settings.http_1_0_server = option->val.http_1_0_server;
      continue;
    case MHD_R_OPTION_INSANITY_HEADER_CONTENT_LENGTH:
      response->settings.insanity_header_content_length = option->val.insanity_header_content_length;
      continue;
    case MHD_R_OPTION_TERMINATION_CALLBACK:
      response->settings.termination_callback.v_term_cb = option->val.termination_callback.v_term_cb;
      response->settings.termination_callback.v_term_cb_cls = option->val.termination_callback.v_term_cb_cls;
      continue;
    case MHD_R_O_SENTINEL:
    default:
      break;
    }
    return MHD_SC_OPTION_UNKNOWN;
  }
  return MHD_SC_OK;
}
