/**
 * The options (parameters) for MHD response
 */
enum MHD_FIXED_ENUM_APP_SET_ MHD_ResponseOption
{  /**
   * Not a real option.
   * Should not be used directly.
   * This value indicates the end of the list of the options.
   */
  MHD_R_O_END = 0
  ,

  /**
   * Make the response object re-usable. (FIXME: not used in struct ResponseOptions; remove!?)
   * The response will not be consumed by MHD_action_from_response() and must be destroyed by MHD_response_destroy().
   * Useful if the same response is often used to reply.
   */
  MHD_R_O_REUSABLE = 20
  ,

  /**
   * Enable special processing of the response as body-less (with undefined body size). No automatic 'Content-Length' or 'Transfer-Encoding: chunked' headers are added when the response is used with #MHD_HTTP_STATUS_NOT_MODIFIED code or to respond to HEAD request.
   * The flag also allow to set arbitrary 'Content-Length' by #MHD_response_add_header() function.
   * This flag value can be used only with responses created without body (zero-size body).
   * Responses with this flag enabled cannot be used in situations where reply body must be sent to the client.
   * This flag is primarily intended to be used when automatic 'Content-Length' header is undesirable in response to HEAD requests.
   */
  MHD_R_O_HEAD_ONLY_RESPONSE = 40
  ,

  /**
   * Force use of chunked encoding even if the response content size is known.
   * Ignored when the reply cannot have body/content.
   */
  MHD_R_O_CHUNKED_ENC = 41
  ,

  /**
   * Force close connection after sending the response, prevents keep-alive connections and adds 'Connection: close' header.
   */
  MHD_R_O_CONN_CLOSE = 60
  ,

  /**
   * Only respond in conservative (dumb) HTTP/1.0-compatible mode.
   * Response still use HTTP/1.1 version in header, but always close the connection after sending the response and do not use chunked encoding for the response.
   * You can also set the #MHD_R_O_HTTP_1_0_SERVER flag to force HTTP/1.0 version in the response.
   * Responses are still compatible with HTTP/1.1.
   * Summary:
   * + declared reply version: HTTP/1.1
   * + keep-alive: no
   * + chunked: no
   *
This option can be used to communicate with some broken client, which does not implement HTTP/1.1 features, but advertises HTTP/1.1 support.
   */
  MHD_R_O_HTTP_1_0_COMPATIBLE_STRICT = 80
  ,

  /**
   * Only respond in HTTP/1.0-mode.
   * Contrary to the #MHD_R_O_HTTP_1_0_COMPATIBLE_STRICT flag, the response's HTTP version will always be set to 1.0 and keep-alive connections will be used if explicitly requested by the client.
   * The 'Connection:' header will be added for both 'close' and 'keep-alive' connections.
   * Chunked encoding will not be used for the response.
   * Due to backward compatibility, responses still can be used with HTTP/1.1 clients.
   * This option can be used to emulate HTTP/1.0 server (for response part only as chunked encoding in requests (if any) is processed by MHD).
   * Summary:
   * + declared reply version: HTTP/1.0
   * + keep-alive: possible
   * + chunked: no
   *
With this option HTTP/1.0 server is emulated (with support for 'keep-alive' connections).
   */
  MHD_R_O_HTTP_1_0_SERVER = 81
  ,

  /**
   * Disable sanity check preventing clients from manually setting the HTTP content length option.
   * Allow to set several 'Content-Length' headers. These headers will be used even with replies without body.
   */
  MHD_R_O_INSANITY_HEADER_CONTENT_LENGTH = 100
  ,

  /**
   * Set a function to be called once MHD is finished with the request.
   */
  MHD_R_O_TERMINATION_CALLBACK = 121
  ,

  /**
   * The sentinel value.
   * This value enforces specific underlying integer type for the enum.
   * Do not use.
   */
  MHD_R_O_SENTINEL = 65535

};

/**
 * Data for #MHD_R_O_TERMINATION_CALLBACK
 */
struct MHD_ResponeOptionValueTermCB
{
  /**
   * the function to call,
   * NULL to not use the callback
   */
  MHD_RequestTerminationCallback v_term_cb;

  /**
   * the closure for the callback
   */
  void *v_term_cb_cls;

};

/**
 * Parameters for MHD response options
 */
union MHD_ResponseOptionValue
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


struct MHD_ResponseOptionAndValue
{
  /**
   * The response configuration option
   */
  enum MHD_ResponseOption opt;

  /**
   * The value for the @a opt option
   */
  union MHD_ResponseOptionValue val;
};

#if defined(MHD_USE_COMPOUND_LITERALS) && defined(MHD_USE_DESIG_NEST_INIT)
/**
 * Make the response object re-usable. (FIXME: not used in struct ResponseOptions; remove!?)
 * The response will not be consumed by MHD_action_from_response() and must be destroyed by MHD_response_destroy().
 * Useful if the same response is often used to reply.
 * @param val the value of the parameter * @return structure with the requested setting
 */
#  define MHD_R_OPTION_REUSABLE(val) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_ResponseOptionAndValue) \
        { \
          .opt = MHD_R_O_REUSABLE,  \
          .val.reusable = (val) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Enable special processing of the response as body-less (with undefined body size). No automatic 'Content-Length' or 'Transfer-Encoding: chunked' headers are added when the response is used with #MHD_HTTP_STATUS_NOT_MODIFIED code or to respond to HEAD request.
 * The flag also allow to set arbitrary 'Content-Length' by #MHD_response_add_header() function.
 * This flag value can be used only with responses created without body (zero-size body).
 * Responses with this flag enabled cannot be used in situations where reply body must be sent to the client.
 * This flag is primarily intended to be used when automatic 'Content-Length' header is undesirable in response to HEAD requests.
 * @param val the value of the parameter * @return structure with the requested setting
 */
#  define MHD_R_OPTION_HEAD_ONLY_RESPONSE(val) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_ResponseOptionAndValue) \
        { \
          .opt = MHD_R_O_HEAD_ONLY_RESPONSE,  \
          .val.head_only_response = (val) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Force use of chunked encoding even if the response content size is known.
 * Ignored when the reply cannot have body/content.
 * @param val the value of the parameter * @return structure with the requested setting
 */
#  define MHD_R_OPTION_CHUNKED_ENC(val) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_ResponseOptionAndValue) \
        { \
          .opt = MHD_R_O_CHUNKED_ENC,  \
          .val.chunked_enc = (val) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Force close connection after sending the response, prevents keep-alive connections and adds 'Connection: close' header.
 * @param val the value of the parameter * @return structure with the requested setting
 */
#  define MHD_R_OPTION_CONN_CLOSE(val) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_ResponseOptionAndValue) \
        { \
          .opt = MHD_R_O_CONN_CLOSE,  \
          .val.conn_close = (val) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Only respond in conservative (dumb) HTTP/1.0-compatible mode.
 * Response still use HTTP/1.1 version in header, but always close the connection after sending the response and do not use chunked encoding for the response.
 * You can also set the #MHD_R_O_HTTP_1_0_SERVER flag to force HTTP/1.0 version in the response.
 * Responses are still compatible with HTTP/1.1.
 * Summary:
 * + declared reply version: HTTP/1.1
 * + keep-alive: no
 * + chunked: no
 *
This option can be used to communicate with some broken client, which does not implement HTTP/1.1 features, but advertises HTTP/1.1 support.
 * @param val the value of the parameter * @return structure with the requested setting
 */
#  define MHD_R_OPTION_HTTP_1_0_COMPATIBLE_STRICT(val) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_ResponseOptionAndValue) \
        { \
          .opt = MHD_R_O_HTTP_1_0_COMPATIBLE_STRICT,  \
          .val.http_1_0_compatible_strict = (val) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Only respond in HTTP/1.0-mode.
 * Contrary to the #MHD_R_O_HTTP_1_0_COMPATIBLE_STRICT flag, the response's HTTP version will always be set to 1.0 and keep-alive connections will be used if explicitly requested by the client.
 * The 'Connection:' header will be added for both 'close' and 'keep-alive' connections.
 * Chunked encoding will not be used for the response.
 * Due to backward compatibility, responses still can be used with HTTP/1.1 clients.
 * This option can be used to emulate HTTP/1.0 server (for response part only as chunked encoding in requests (if any) is processed by MHD).
 * Summary:
 * + declared reply version: HTTP/1.0
 * + keep-alive: possible
 * + chunked: no
 *
With this option HTTP/1.0 server is emulated (with support for 'keep-alive' connections).
 * @param val the value of the parameter * @return structure with the requested setting
 */
#  define MHD_R_OPTION_HTTP_1_0_SERVER(val) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_ResponseOptionAndValue) \
        { \
          .opt = MHD_R_O_HTTP_1_0_SERVER,  \
          .val.http_1_0_server = (val) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Disable sanity check preventing clients from manually setting the HTTP content length option.
 * Allow to set several 'Content-Length' headers. These headers will be used even with replies without body.
 * @param val the value of the parameter * @return structure with the requested setting
 */
#  define MHD_R_OPTION_INSANITY_HEADER_CONTENT_LENGTH(val) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_ResponseOptionAndValue) \
        { \
          .opt = MHD_R_O_INSANITY_HEADER_CONTENT_LENGTH,  \
          .val.insanity_header_content_length = (val) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_
/**
 * Set a function to be called once MHD is finished with the request.
 * @param term_cb the function to call,
 *   NULL to not use the callback
 * @param term_cb_cls the closure for the callback
 * @return structure with the requested setting
 */
#  define MHD_R_OPTION_TERMINATION_CALLBACK(term_cb,term_cb_cls) \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_ResponseOptionAndValue) \
        { \
          .opt = MHD_R_O_TERMINATION_CALLBACK,  \
          .val.termination_callback.v_term_cb = (term_cb), \
          .val.termination_callback.v_term_cb_cls = (term_cb_cls) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_ResponseOptionAndValue
 */
#  define MHD_R_OPTION_TERMINATE() \
        MHD_NOWARN_COMPOUND_LITERALS_ \
          (const struct MHD_ResponseOptionAndValue) \
        { \
          .opt = (MHD_R_O_END) \
        } \
        MHD_RESTORE_WARN_COMPOUND_LITERALS_

#else /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */
MHD_NOWARN_UNUSED_FUNC_
/**
 * Make the response object re-usable. (FIXME: not used in struct ResponseOptions; remove!?)
 * The response will not be consumed by MHD_action_from_response() and must be destroyed by MHD_response_destroy().
 * Useful if the same response is often used to reply.
 * @param val the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_ResponseOptionAndValue
MHD_R_OPTION_REUSABLE (
  enum MHD_Bool val
  )
{
  struct MHD_ResponseOptionAndValue opt_val;

  opt_val.opt = MHD_R_O_REUSABLE;
  opt_val.val.reusable = (val); \

  return opt_val;
}


/**
 * Enable special processing of the response as body-less (with undefined body size). No automatic 'Content-Length' or 'Transfer-Encoding: chunked' headers are added when the response is used with #MHD_HTTP_STATUS_NOT_MODIFIED code or to respond to HEAD request.
 * The flag also allow to set arbitrary 'Content-Length' by #MHD_response_add_header() function.
 * This flag value can be used only with responses created without body (zero-size body).
 * Responses with this flag enabled cannot be used in situations where reply body must be sent to the client.
 * This flag is primarily intended to be used when automatic 'Content-Length' header is undesirable in response to HEAD requests.
 * @param val the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_ResponseOptionAndValue
MHD_R_OPTION_HEAD_ONLY_RESPONSE (
  enum MHD_Bool val
  )
{
  struct MHD_ResponseOptionAndValue opt_val;

  opt_val.opt = MHD_R_O_HEAD_ONLY_RESPONSE;
  opt_val.val.head_only_response = (val); \

  return opt_val;
}


/**
 * Force use of chunked encoding even if the response content size is known.
 * Ignored when the reply cannot have body/content.
 * @param val the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_ResponseOptionAndValue
MHD_R_OPTION_CHUNKED_ENC (
  enum MHD_Bool val
  )
{
  struct MHD_ResponseOptionAndValue opt_val;

  opt_val.opt = MHD_R_O_CHUNKED_ENC;
  opt_val.val.chunked_enc = (val); \

  return opt_val;
}


/**
 * Force close connection after sending the response, prevents keep-alive connections and adds 'Connection: close' header.
 * @param val the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_ResponseOptionAndValue
MHD_R_OPTION_CONN_CLOSE (
  enum MHD_Bool val
  )
{
  struct MHD_ResponseOptionAndValue opt_val;

  opt_val.opt = MHD_R_O_CONN_CLOSE;
  opt_val.val.conn_close = (val); \

  return opt_val;
}


/**
 * Only respond in conservative (dumb) HTTP/1.0-compatible mode.
 * Response still use HTTP/1.1 version in header, but always close the connection after sending the response and do not use chunked encoding for the response.
 * You can also set the #MHD_R_O_HTTP_1_0_SERVER flag to force HTTP/1.0 version in the response.
 * Responses are still compatible with HTTP/1.1.
 * Summary:
 * + declared reply version: HTTP/1.1
 * + keep-alive: no
 * + chunked: no
 *
This option can be used to communicate with some broken client, which does not implement HTTP/1.1 features, but advertises HTTP/1.1 support.
 * @param val the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_ResponseOptionAndValue
MHD_R_OPTION_HTTP_1_0_COMPATIBLE_STRICT (
  enum MHD_Bool val
  )
{
  struct MHD_ResponseOptionAndValue opt_val;

  opt_val.opt = MHD_R_O_HTTP_1_0_COMPATIBLE_STRICT;
  opt_val.val.http_1_0_compatible_strict = (val); \

  return opt_val;
}


/**
 * Only respond in HTTP/1.0-mode.
 * Contrary to the #MHD_R_O_HTTP_1_0_COMPATIBLE_STRICT flag, the response's HTTP version will always be set to 1.0 and keep-alive connections will be used if explicitly requested by the client.
 * The 'Connection:' header will be added for both 'close' and 'keep-alive' connections.
 * Chunked encoding will not be used for the response.
 * Due to backward compatibility, responses still can be used with HTTP/1.1 clients.
 * This option can be used to emulate HTTP/1.0 server (for response part only as chunked encoding in requests (if any) is processed by MHD).
 * Summary:
 * + declared reply version: HTTP/1.0
 * + keep-alive: possible
 * + chunked: no
 *
With this option HTTP/1.0 server is emulated (with support for 'keep-alive' connections).
 * @param val the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_ResponseOptionAndValue
MHD_R_OPTION_HTTP_1_0_SERVER (
  enum MHD_Bool val
  )
{
  struct MHD_ResponseOptionAndValue opt_val;

  opt_val.opt = MHD_R_O_HTTP_1_0_SERVER;
  opt_val.val.http_1_0_server = (val); \

  return opt_val;
}


/**
 * Disable sanity check preventing clients from manually setting the HTTP content length option.
 * Allow to set several 'Content-Length' headers. These headers will be used even with replies without body.
 * @param val the value of the parameter * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_ResponseOptionAndValue
MHD_R_OPTION_INSANITY_HEADER_CONTENT_LENGTH (
  enum MHD_Bool val
  )
{
  struct MHD_ResponseOptionAndValue opt_val;

  opt_val.opt = MHD_R_O_INSANITY_HEADER_CONTENT_LENGTH;
  opt_val.val.insanity_header_content_length = (val); \

  return opt_val;
}


/**
 * Set a function to be called once MHD is finished with the request.
 * @param term_cb the function to call,
 *   NULL to not use the callback
 * @param term_cb_cls the closure for the callback
 * @return structure with the requested setting
 */
static MHD_INLINE struct MHD_ResponseOptionAndValue
MHD_R_OPTION_TERMINATION_CALLBACK (
  MHD_RequestTerminationCallback term_cb,
  void *term_cb_cls
  )
{
  struct MHD_ResponseOptionAndValue opt_val;

  opt_val.opt = MHD_R_O_TERMINATION_CALLBACK;
  opt_val.val.termination_callback.v_term_cb = term_cb;
  opt_val.val.termination_callback.v_term_cb_cls = term_cb_cls;

  return opt_val;
}


/**
 * Terminate the list of the options
 * @return the terminating object of struct MHD_ResponseOptionAndValue
 */
static MHD_INLINE struct MHD_ResponseOptionAndValue
MHD_R_OPTION_TERMINATE (void)
{
  struct MHD_ResponseOptionAndValue opt_val;

  opt_val.opt = MHD_R_O_END;

  return opt_val;
}


MHD_RESTORE_WARN_UNUSED_FUNC_
#endif /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */
