/* This is generated code, it is still under LGPLv3+.
   Do not edit directly! */
/* *INDENT-OFF* */
/**
/* @file response_options.h
/* @author response-options-generator.c
 */

#include "microhttpd2.h"
#include "internal.h"

struct ResponseOptions {
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