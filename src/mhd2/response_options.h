/* This is generated code, it is still under LGPLv2.1+.
   Do not edit directly! */
/* *INDENT-OFF* */
/**
 * @file response_options.h
 * @author response-options-generator.c
 */

#ifndef MHD_RESPONSE_OPTIONS_H
#define MHD_RESPONSE_OPTIONS_H 1

#include "mhd_sys_options.h"
#include "mhd_public_api.h"

struct ResponseOptions
{
  /**
   * Value for #MHD_R_O_REUSABLE.
   */
  enum MHD_Bool reusable;


  /**
   * Value for #MHD_R_O_HEAD_ONLY_RESPONSE.
   */
  enum MHD_Bool head_only_response;


  /**
   * Value for #MHD_R_O_CHUNKED_ENC.
   */
  enum MHD_Bool chunked_enc;


  /**
   * Value for #MHD_R_O_CONN_CLOSE.
   */
  enum MHD_Bool conn_close;


  /**
   * Value for #MHD_R_O_HTTP_1_0_COMPATIBLE_STRICT.
   */
  enum MHD_Bool http_1_0_compatible_strict;


  /**
   * Value for #MHD_R_O_HTTP_1_0_SERVER.
   */
  enum MHD_Bool http_1_0_server;


  /**
   * Value for #MHD_R_O_INSANITY_HEADER_CONTENT_LENGTH.
   */
  enum MHD_Bool insanity_header_content_length;


  /**
   * Value for #MHD_R_O_TERMINATION_CALLBACK.
   * the function to call,
   * NULL to not use the callback
   */
  struct MHD_ResponeOptionValueTermCB termination_callback;


};

#endif /* ! MHD_RESPONSE_OPTIONS_H 1 */
