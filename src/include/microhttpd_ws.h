/*
     This file is part of libmicrohttpd
     Copyright (C) 2021 Christian Grothoff (and other contributing authors)

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
/**
 * @file microhttpd_ws.h
 * @brief interface for experimental web socket extension to libmicrohttpd
 * @author David Gausmann
 */
#ifndef MHD_MICROHTTPD_WS_H
#define MHD_MICROHTTPD_WS_H


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * @brief Handle for the encoding/decoding of websocket data
 *        (one stream is used per websocket)
 * @ingroup websocket
 */
struct MHD_WebSocketStream;

/**
 * @brief Flags for the initialization of a websocket stream
 *        `struct MHD_WebSocketStream` used by
 *        #MHD_websocket_stream_init() or
 *        #MHD_websocket_stream_init2().
 * @ingroup websocket
 */
enum MHD_WEBSOCKET_FLAG
{
  /**
   * The websocket is used by the server (default).
   * Thus all outgoing payload will not be "masked".
   * All incoming payload must be masked.
   * This cannot be used together with #MHD_WEBSOCKET_FLAG_CLIENT
   */
  MHD_WEBSOCKET_FLAG_SERVER = 0,
  /**
   * The websocket is used by the client
   * (not used if you provide the server).
   * Thus all outgoing payload will be "masked" (XOR-ed with random values).
   * All incoming payload must be unmasked.
   * Please note that this implementation doesn't use a strong random
   * number generator for the mask as suggested in RFC6455 10.3, because
   * the main intention of this implementation is the use as server
   * with MHD, which doesn't need masking.
   * Instead a weak random number generator is used (`rand()`).
   * You can set the seed for the random number generator
   * by calling #MHD_websocket_srand().
   * This cannot be used together with #MHD_WEBSOCKET_FLAG_SERVER
   */
  MHD_WEBSOCKET_FLAG_CLIENT = 1,
  /**
   * You don't want to get fragmented data while decoding.
   * Fragmented frames will be internally put together until
   * they are complete.
   * Whether or not data is fragmented is decided
   * by the sender of the data during encoding.
   * This cannot be used together with #MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS
   */
  MHD_WEBSOCKET_FLAG_NO_FRAGMENTS = 0,
  /**
   * You want fragmented data, if it appears while decoding.
   * You will receive the content of the fragmented frame,
   * but if you are decoding text, you will never get an unfinished
   * UTF-8 sequences (if the sequence appears between two fragments).
   * Instead the text will end before the unfinished UTF-8 sequence.
   * With the next fragment, which finishes the UTF-8 sequence,
   * you will get the complete UTF-8 sequence.
   * This cannot be used together with #MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS
   */
  MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS = 2,
  /**
   * If the websocket stream becomes invalid during decoding due to
   * protocol errors, a matching close frame will automatically
   * be generated.
   * The close frame will be returned via the parameters
   * result and result_len of #MHD_websocket_decode() and
   * the return value is negative
   * (a value of `enum MHD_WEBSOCKET_STATUS`).
   * The generated close frame must be freed by the caller
   * with #MHD_websocket_free().
   */
  MHD_WEBSOCKET_FLAG_GENERATE_CLOSE_FRAMES_ON_ERROR = 4
};

/**
 * @brief Enum to specify the fragmenting behavior
 *        while encoding with #MHD_websocket_encode_text() or
 *        #MHD_websocket_encode_binary().
 * @ingroup websocket
 */
enum MHD_WEBSOCKET_FRAGMENTATION
{
  /**
   * You don't want to use fragmentation.
   * The encoded frame consists of only one frame.
   */
  MHD_WEBSOCKET_FRAGMENTATION_NONE = 0,
  /**
   * You want to use fragmentation.
   * The encoded frame is the first frame of
   * a series of data frames of the same type
   * (text or binary).
   * You may send control frames (ping, pong or close)
   * between these data frames.
   */
  MHD_WEBSOCKET_FRAGMENTATION_FIRST = 1,
  /**
   * You want to use fragmentation.
   * The encoded frame is not the first frame of
   * the series of data frames, but also not the last one.
   * You may send control frames (ping, pong or close)
   * between these data frames.
   */
  MHD_WEBSOCKET_FRAGMENTATION_FOLLOWING = 2,
  /**
   * You want to use fragmentation.
   * The encoded frame is the last frame of
   * the series of data frames, but also not the first one.
   * After this frame, you may send all type of frames again.
   */
  MHD_WEBSOCKET_FRAGMENTATION_LAST = 3
};

/**
 * @brief Enum of the return value for almost every MHD_websocket function.
 *        Errors are negative and values equal to or above zero mean a success.
 *        Positive values are only used by #MHD_websocket_decode().
 * @ingroup websocket
 */
enum MHD_WEBSOCKET_STATUS
{
  /**
   * The call succeeded.
   * For #MHD_websocket_decode() this means that no error occurred,
   * but also no frame has been completed yet.
   */
  MHD_WEBSOCKET_STATUS_OK = 0,
  /**
   * #MHD_websocket_decode() has decoded a text frame.
   * The parameters result and result_len are filled with the decoded text
   * (if any).
   */
  MHD_WEBSOCKET_STATUS_TEXT_FRAME = 0x1,
  /**
   * #MHD_websocket_decode() has decoded a binary frame.
   * The parameters result and result_len are filled with the decoded
   * binary data (if any).
   */
  MHD_WEBSOCKET_STATUS_BINARY_FRAME = 0x2,
  /**
   * #MHD_websocket_decode() has decoded a close frame.
   * This means you must close the socket using #MHD_upgrade_action()
   * with #MHD_UPGRADE_ACTION_CLOSE.
   * You may respond with a close frame before closing.
   * The parameters result and result_len are filled with
   * the close reason (if any).
   * The close reason starts with a two byte sequence of close code
   * in network byte order (see `enum MHD_WEBSOCKET_CLOSEREASON`).
   * After these two bytes a UTF-8 encoded close reason may follow.
   * Compare with result_len to decide whether there is any close reason.
   */
  MHD_WEBSOCKET_STATUS_CLOSE_FRAME = 0x8,
  /**
   * #MHD_websocket_decode() has decoded a ping frame.
   * You should respond to this with a pong frame.
   * The pong frame must contain the same binary data as
   * the corresponding ping frame (if it had any).
   * The parameters result and result_len are filled with
   * the binary ping data (if any).
   */
  MHD_WEBSOCKET_STATUS_PING_FRAME = 0x9,
  /**
   * #MHD_websocket_decode() has decoded a pong frame.
   * You should usually only receive pong frames if you sent
   * a ping frame before.
   * The binary data should be equal to your ping frame and can be
   * used to distinguish the response if you sent multiple ping frames.
   * The parameters result and result_len are filled with
   * the binary pong data (if any).
   */
  MHD_WEBSOCKET_STATUS_PONG_FRAME = 0xA,
  /**
   * #MHD_websocket_decode() has decoded a text frame fragment.
   * The parameters result and result_len are filled with the decoded text
   * (if any).
   * This is like #MHD_WEBSOCKET_STATUS_TEXT_FRAME, but it can only
   * appear if you specified #MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS during
   * the call of #MHD_websocket_stream_init() or
   * #MHD_websocket_stream_init2().
   */
  MHD_WEBSOCKET_STATUS_TEXT_FRAGMENT = 0x11,
  /**
   * #MHD_websocket_decode() has decoded a binary frame fragment.
   * The parameters result and result_len are filled with the decoded
   * binary data (if any).
   * This is like #MHD_WEBSOCKET_STATUS_BINARY_FRAME, but it can only
   * appear if you specified #MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS during
   * the call of #MHD_websocket_stream_init() or
   * #MHD_websocket_stream_init2().
   */
  MHD_WEBSOCKET_STATUS_BINARY_FRAGMENT = 0x12,
  /**
  * #MHD_websocket_decode() has decoded the last text frame fragment.
  * The parameters result and result_len are filled with the decoded text
  * (if any).
  * This is like #MHD_WEBSOCKET_STATUS_TEXT_FRAGMENT, but it appears
  * only for the last fragment of a series of fragments.
  * It can only appear if you specified #MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS
  * during the call of #MHD_websocket_stream_init() or
  * #MHD_websocket_stream_init2().
  */
  MHD_WEBSOCKET_STATUS_TEXT_LAST_FRAGMENT = 0x21,
  /**
  * #MHD_websocket_decode() has decoded the last binary frame fragment.
  * The parameters result and result_len are filled with the decoded
  * binary data (if any).
  * This is like #MHD_WEBSOCKET_STATUS_BINARY_FRAGMENT, but it appears
  * only for the last fragment of a series of fragments.
  * It can only appear if you specified #MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS
  * during the call of #MHD_websocket_stream_init() or
  * #MHD_websocket_stream_init2().
  */
  MHD_WEBSOCKET_STATUS_BINARY_LAST_FRAGMENT = 0x22,
  /**
   * The call failed and the stream is invalid now for decoding.
   * You must close the websocket now using #MHD_upgrade_action()
   * with #MHD_UPGRADE_ACTION_CLOSE.
   * You can send a close frame before closing.
   * This is only used by #MHD_websocket_decode() and happens
   * if the stream contains errors (i. e. invalid byte data).
   */
  MHD_WEBSOCKET_STATUS_PROTOCOL_ERROR = -1,
  /**
   * You tried to decode something, but the stream has already
   * been marked invalid.
   * You must close the websocket now using #MHD_upgrade_action()
   * with #MHD_UPGRADE_ACTION_CLOSE.
   * You can send a close frame before closing.
   * This is only used by #MHD_websocket_decode() and happens
   * if you call #MDM_websocket_decode() again after is
   * has been invalidated.
   */
  MHD_WEBSOCKET_STATUS_STREAM_BROKEN = -2,
  /**
   * A memory allocation failed. The stream remains valid.
   * If this occurred while decoding, the decoding could be
   * possible later if enough memory is available.
   * This could happen while decoding if you received a too big data frame.
   * You could try to specify max_payload_size during the call of
   * #MHD_websocket_stream_init() or #MHD_websocket_stream_init2() then to
   * avoid this and close the frame instead.
   */
  MHD_WEBSOCKET_STATUS_MEMORY_ERROR = -3,
  /**
   * You passed invalid parameters during the function call
   * (i. e. a NULL pointer for a required parameter).
   * The stream remains valid.
   */
  MHD_WEBSOCKET_STATUS_PARAMETER_ERROR = -4,
  /**
   * The maximum payload size has been exceeded.
   * If you got this return code from #MHD_websocket_decode() then
   * the stream becomes invalid and the websocket must be closed
   * using #MHD_upgrade_action() with #MHD_UPGRADE_ACTION_CLOSE.
   * You can send a close frame before closing.
   * The maximum payload size is specified during the call of
   * #MHD_websocket_stream_init() or #MHD_websocket_stream_init2().
   * This can also appear if you specified 0 as maximum payload size
   * when the message is greater than the maximum allocatable memory size
   * (i. e. more than 4 GB on 32 bit systems).
   * If you got this return code from #MHD_websocket_encode_close(),
   * #MHD_websocket_encode_ping() or #MHD_websocket_encode_pong() then
   * you passed to much payload data. The stream remains valid then.
   */
  MHD_WEBSOCKET_STATUS_MAXIMUM_SIZE_EXCEEDED = -5,
  /**
   * An UTF-8 text is invalid.
   * If you got this return code from #MHD_websocket_decode() then
   * the stream becomes invalid and you must close the websocket
   * using #MHD_upgrade_action() with #MHD_UPGRADE_ACTION_CLOSE.
   * You can send a close frame before closing.
   * If you got this from #MHD_websocket_encode_text() or
   * #MHD_websocket_encode_close() then you passed invalid UTF-8 text.
   * The stream remains valid then.
   */
  MHD_WEBSOCKET_STATUS_UTF8_ENCODING_ERROR = -6
};

/**
 * @brief Enumeration of possible close reasons for close frames.
 *
 * The possible values are specified in RFC 6455 7.4.1
 * These close reasons here are the default set specified by RFC 6455,
 * but also other close reasons could be used.
 *
 * The definition is for short:
 * 0-999 are never used (if you pass 0 in
 *   #MHD_websocket_encode_close() then no close reason is used).
 * 1000-2999 are specified by RFC 6455.
 * 3000-3999 are specified by libraries, etc. but must be registered by IANA.
 * 4000-4999 are reserved for private use.
 *
 * @ingroup websocket
 */
enum MHD_WEBSOCKET_CLOSEREASON
{
  /**
   * This value is used as placeholder for #MHD_websocket_encode_close()
   * to tell that you don't want to specify any reason.
   * If you use this value then no reason text may be used.
   * This value cannot a result of decoding, because this value
   * is not a valid close reason for the WebSocket protocol.
   */
  MHD_WEBSOCKET_CLOSEREASON_NO_REASON = 0,
  /**
   * You close the websocket fulfilled its purpose and shall
   * now be closed in a normal, planned way.
   */
  MHD_WEBSOCKET_CLOSEREASON_REGULAR = 1000,
  /**
   * You close the websocket because are shutting down the server or
   * something similar.
   */
  MHD_WEBSOCKET_CLOSEREASON_GOING_AWAY = 1001,
  /**
   * You close the websocket because you a protocol error occurred
   * during decoding (i. e. invalid byte data).
   */
  MHD_WEBSOCKET_CLOSEREASON_PROTOCOL_ERROR = 1002,
  /**
   * You close the websocket because you received data which you don't accept.
   * For example if you received a binary frame,
   * but your application only expects text frames.
   */
  MHD_WEBSOCKET_CLOSEREASON_UNSUPPORTED_DATATYPE = 1003,
  /**
   * You close the websocket because it contains malformed UTF-8.
   * The UTF-8 validity is automatically checked by #MHD_websocket_decode(),
   * so you don't need to check it on your own.
   * UTF-8 is specified in RFC 3629.
   */
  MHD_WEBSOCKET_CLOSEREASON_MALFORMED_UTF8 = 1007,
  /**
   * You close the websocket because of any reason.
   * Usually this close reason is used if no other close reason
   * is more specific or if you don't want to use any other close reason.
   */
  MHD_WEBSOCKET_CLOSEREASON_POLICY_VIOLATED = 1008,
  /**
   * You close the websocket because you received a frame which is too big to process.
   * You can specify the maximum allowed payload size during the call of
   * #MHD_websocket_stream_init() or #MHD_websocket_stream_init2().
   */
  MHD_WEBSOCKET_CLOSEREASON_MAXIMUM_ALLOWED_PAYLOAD_SIZE_EXCEEDED = 1009,
  /**
   * This status code can be sent by the client if it
   * expected a specific extension, but this extension hasn't been negotiated.
   */
  MHD_WEBSOCKET_CLOSEREASON_MISSING_EXTENSION = 1010,
  /**
   * The server closes the websocket because it encountered
   * an unexpected condition that prevented it from fulfilling the request.
   */
  MHD_WEBSOCKET_CLOSEREASON_UNEXPECTED_CONDITION = 1011
};

/**
 * @brief Enumeration of possible UTF-8 check steps
 *
 * These values are used during the encoding of fragmented text frames
 * or for error analysis while encoding text frames.
 * Its values specify the next step of the UTF-8 check.
 * UTF-8 sequences consist of one to four bytes.
 * This enumeration just says how long the current UTF-8 sequence is
 * and what is the next expected byte.
 *
 * @ingroup websocket
 */
enum MHD_WEBSOCKET_UTF8STEP
{
  /**
   * There is no open UTF-8 sequence.
   * The next byte must be 0x00-0x7F or 0xC2-0xF4.
   */
  MHD_WEBSOCKET_UTF8STEP_NORMAL   = 0,
  /**
   * The second byte of a two byte UTF-8 sequence.
   * The first byte was 0xC2-0xDF.
   * The next byte must be 0x80-0xBF.
   */
  MHD_WEBSOCKET_UTF8STEP_UTF2TAIL_1OF1 = 1,
  /**
   * The second byte of a three byte UTF-8 sequence.
   * The first byte was 0xE0.
   * The next byte must be 0xA0-0xBF.
   */
  MHD_WEBSOCKET_UTF8STEP_UTF3TAIL1_1OF2 = 2,
  /**
  * The second byte of a three byte UTF-8 sequence.
  * The first byte was 0xED.
  * The next byte must by 0x80-0x9F.
  */
  MHD_WEBSOCKET_UTF8STEP_UTF3TAIL2_1OF2 = 3,
  /**
  * The second byte of a three byte UTF-8 sequence.
  * The first byte was 0xE1-0xEC or 0xEE-0xEF.
  * The next byte must be 0x80-0xBF.
  */
  MHD_WEBSOCKET_UTF8STEP_UTF3TAIL_1OF2 = 4,
  /**
  * The third byte of a three byte UTF-8 sequence.
  * The next byte must be 0x80-0xBF.
  */
  MHD_WEBSOCKET_UTF8STEP_UTF3TAIL_2OF2 = 5,
  /**
   * The second byte of a four byte UTF-8 sequence.
   * The first byte was 0xF0.
   * The next byte must be 0x90-0xBF.
   */
  MHD_WEBSOCKET_UTF8STEP_UTF4TAIL1_1OF3 = 6,
  /**
   * The second byte of a four byte UTF-8 sequence.
   * The first byte was 0xF4.
   * The next byte must be 0x80-0x8F.
   */
  MHD_WEBSOCKET_UTF8STEP_UTF4TAIL2_1OF3 = 7,
  /**
   * The second byte of a four byte UTF-8 sequence.
   * The first byte was 0xF1-0xF3.
   * The next byte must be 0x80-0xBF.
   */
  MHD_WEBSOCKET_UTF8STEP_UTF4TAIL_1OF3 = 8,
  /**
   * The third byte of a four byte UTF-8 sequence.
   * The next byte must be 0x80-0xBF.
   */
  MHD_WEBSOCKET_UTF8STEP_UTF4TAIL_2OF3 = 9,
  /**
  * The fourth byte of a four byte UTF-8 sequence.
  * The next byte must be 0x80-0xBF.
  */
  MHD_WEBSOCKET_UTF8STEP_UTF4TAIL_3OF3 = 10
};

/**
* @brief Enumeration of validity values
*
* These values are used for #MHD_websocket_stream_is_valid()
* and specify the validity status.
*
* @ingroup websocket
*/
enum MHD_WEBSOCKET_VALIDITY
{
  /**
  * The stream is invalid.
  * It cannot be used for decoding anymore.
  */
  MHD_WEBSOCKET_VALIDITY_INVALID = 0,
  /**
   * The stream is valid.
   * Decoding works as expected.
   */
  MHD_WEBSOCKET_VALIDITY_VALID   = 1,
  /**
   * The stream has received a close frame and
   * is partly invalid.
   * You can still use the stream for decoding,
   * but if a data frame is received an error will be reported.
   * After a close frame has been sent, no data frames
   * may follow from the sender of the close frame.
   */
  MHD_WEBSOCKET_VALIDITY_ONLY_VALID_FOR_CONTROL_FRAMES = 2
};
/**
 * This method is called by many websocket
 * functions for allocating data.
 * By default 'malloc' is used.
 * This can be used for operating systems like Windows
 * where malloc, realloc and free are compiler dependent.
 *
 * @param len new size
 * @return allocated memory
 * @ingroup websocket
 */
typedef void*
(*MHD_WebSocketMallocCallback) (size_t len);
/**
 * This method is called by many websocket
 * functions for reallocating data.
 * By default 'realloc' is used.
 * This can be used for operating systems like Windows
 * where malloc, realloc and free are compiler dependent.
 *
 * @param cls closure
 * @param len new size
 * @return reallocated memory
 * @ingroup websocket
 */
typedef void*
(*MHD_WebSocketReallocCallback) (void *cls, size_t len);
/**
 * This method is called by many websocket
 * functions for freeing data.
 * By default 'free' is used.
 * This can be used for operating systems like Windows
 * where malloc, realloc and free are compiler dependent.
 *
 * @param cls closure
 * @ingroup websocket
 */
typedef void
(*MHD_WebSocketFreeCallback) (void *cls);

/**
 * Creates the response value for the incoming 'Sec-WebSocket-Key' header.
 * The generated value must be sent to the client as 'Sec-WebSocket-Accept' response header.
 *
 * @param sec_websocket_key The value of the 'Sec-WebSocket-Key' request header
 * @param[out] sec_websocket_accept The response buffer, which will receive
 *                                  the generated 'Sec-WebSocket-Accept' header.
 *                                  This buffer must be at least 29 bytes long and
 *                                  will contain a terminating NUL character.
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         Typically 0 on success or less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_create_accept (const char*sec_websocket_key,
                             char*sec_websocket_accept);

/**
 * Creates a new websocket stream, used for decoding/encoding.
 *
 * @param[out] ws The websocket stream
 * @param flags Combination of `enum MHD_WEBSOCKET_FLAG` values
 *              to modify the behavior of the websocket stream.
 * @param max_message_size The maximum size for incoming payload
 *                         data in bytes. Use 0 to allow each size.
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         Typically 0 on success or less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_stream_init (struct MHD_WebSocketStream**ws,
                           int flags,
                           size_t max_payload_size);

/**
 * Creates a new websocket stream, used for decoding/encoding,
 * but with custom memory functions for malloc, realloc and free.
 *
 * @param[out] ws The websocket stream
 * @param flags Combination of `enum MHD_WEBSOCKET_FLAG` values
 *              to modify the behavior of the websocket stream.
 * @param max_message_size The maximum size for incoming payload
 *                         data in bytes. Use 0 to allow each size.
 * @param callback_malloc  The callback function for 'malloc'.
 * @param callback_realloc The callback function for 'realloc'.
 * @param callback_free    The callback function for 'free'.
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         Typically 0 on success or less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_stream_init2 (struct MHD_WebSocketStream**ws,
                            int flags,
                            size_t max_payload_size,
                            MHD_WebSocketMallocCallback callback_malloc,
                            MHD_WebSocketReallocCallback callback_realloc,
                            MHD_WebSocketFreeCallback callback_free);

/**
 * Frees a websocket stream
 *
 * @param ws The websocket stream. This value may be NULL.
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         Typically 0 on success or less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_stream_free (struct MHD_WebSocketStream*ws);

/**
 * Invalidates a websocket stream.
 * After invalidation a websocket stream cannot be used for decoding anymore.
 * Encoding is still possible.
 *
 * @param ws The websocket stream.
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         Typically 0 on success or less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_stream_invalidate (struct MHD_WebSocketStream*ws);

/**
 * Queries whether a websocket stream is valid.
 * Invalidated websocket streams cannot be used for decoding anymore.
 * Encoding is still possible.
 *
 * @param ws The websocket stream.
 * @return A value of `enum MHD_WEBSOCKET_VALIDITY`.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_stream_is_valid (struct MHD_WebSocketStream*ws);

/**
 * Decodes a byte sequence via this websocket stream.
 * Decoding is done until either a frame is complete or
 * the end of the byte sequence is reached.
 *
 * @param ws The websocket stream.
 * @param streambuf The byte sequence for decoding.
 *                  Typically that what you received via `recv()`.
 * @param streambuf_len The length of the byte sequence @a streambuf
 * @param[out] streambuf_read_len The number of bytes which has been processed
 *                                by this call. This value may be less
 *                                than @a streambuf_len when a frame is decoded
 *                                before the end of the buffer is reached.
 *                                The remaining bytes of @a buf must be passed
 *                                in the following decoding.
 * @param[out] payload This variable receives a buffer with the decoded
 *                     payload data.
 *                     If no decoded data is available this is NULL.
 *                     When this variable is not NULL then
 *                     the buffer contains always @a payload_len bytes plus
 *                     one terminating NUL character.
 *                     The caller must free this buffer
 *                     using #MHD_websocket_free().
 *                     If you passed the flag
 *                     #MHD_WEBSOCKET_FLAG_GENERATE_CLOSE_FRAMES_ON_ERROR
 *                     upon creation of this websocket stream and
 *                     a decoding error occurred
 *                     (return value less than 0), then this
 *                     buffer contains a generated close frame
 *                     which must be sent via the socket to the recipient.
 *                     If you passed the flag #MHD_WEBSOCKET_FLAG_WANT_FRAGMENTS
 *                     upon creation of this websocket stream then
 *                     this payload may only be a part of the complete message.
 *                     Only complete UTF-8 sequences are returned
 *                     for fragmented text frames.
 *                     If necessary the UTF-8 sequence will be completed
 *                     with the next text fragment.
 * @param[out] payload_len The length of the result payload buffer in bytes.
 *
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         This is greater than 0 if a frame has is complete, equal to 0 if more data
 *         is needed an less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_decode (struct MHD_WebSocketStream*ws,
                      const char*streambuf,
                      size_t streambuf_len,
                      size_t*streambuf_read_len,
                      char**payload,
                      size_t*payload_len);

/**
 * Splits the payload of of a decoded close frame.
 *
 * @param payload The payload of the close frame.
 *                This parameter may be NULL if @a payload_len is 0.
 * @param payload_len The length of @a payload.
 * @param[out] reason_code The numeric close reason.
 *                         If there was no close reason, this is
 *                         #MHD_WEBSOCKET_CLOSEREASON_NO_REASON.
 *                         Compare with `enum MHD_WEBSOCKET_CLOSEREASON`.
 *                         This parameter is optional and can be NULL.
 * @param[out] reason_utf8 The literal close reason.
 *                         If there was no literal close reason, this is NULL.
 *                         This parameter is optional and can be NULL.
 *                         Please note that no memory is allocated
 *                         in this function.
 *                         If not NULL the returned value of this parameter
 *                         points to a position in the specified @a payload.
 * @param[out] reason_utf8_len The length of the literal close reason.
 *                             If there was no literal close reason, this is 0.
 *                             This parameter is optional and can be NULL.
 *
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         This is #MHD_WEBSOCKET_STATUS_OK (= 0) on success
 *         or a value less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_split_close_reason (const char*payload,
                                  size_t payload_len,
                                  unsigned short*reason_code,
                                  const char**reason_utf8,
                                  size_t*reason_utf8_len);

/**
 * Encodes an UTF-8 encoded text into websocket text frame.
 *
 * @param ws The websocket stream.
 * @param payload_utf8 The UTF-8 encoded text to send.
 *                     This can be NULL if payload_utf8_len is 0.
 * @param payload_utf8_len The length of the UTF-8 encoded text in bytes.
 * @param fragmentation A value of `enum MHD_WEBSOCKET_FRAGMENTATION`
 *                      to specify the fragmentation behavior.
 *                      Specify MHD_WEBSOCKET_FRAGMENTATION_NONE
 *                      if you don't want to use fragmentation.
 * @param[out] frame This variable receives a buffer with the encoded frame.
 *                   This is what you typically send via `send()` to the recipient.
 *                   If no encoded data is available this is NULL.
 *                   When this variable is not NULL then the buffer contains always
 *                   @a frame_len bytes plus one terminating NUL character.
 *                   The caller must free this buffer using #MHD_websocket_free().
 * @param[out] frame_len The length of the encoded frame in bytes.
 * @param[out] utf8_step This parameter is required for fragmentation and
 *                       can be NULL if no fragmentation is used.
 *                       It contains information about the last encoded
 *                       UTF-8 sequence and is required to continue a previous
 *                       UTF-8 sequence when fragmentation is used.
 *                       The `enum MHD_WEBSOCKET_UTF8STEP` is for this.
 *                       If you start a new fragment using
 *                       MHD_WEBSOCKET_FRAGMENTATION_NONE or
 *                       MHD_WEBSOCKET_FRAGMENTATION_FIRST the value
 *                       of this variable will be initialized
 *                       to MHD_WEBSOCKET_UTF8STEP_NORMAL.
 *
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         This is #MHD_WEBSOCKET_STATUS_OK (= 0) on success
 *         or a value less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_encode_text (struct MHD_WebSocketStream*ws,
                           const char*payload_utf8,
                           size_t payload_utf8_len,
                           int fragmentation,
                           char**frame,
                           size_t*frame_len,
                           int*utf8_step);

/**
 * Encodes a binary data into websocket binary frame.
 *
 * @param ws The websocket stream.
 * @param payload The binary data to send.
 * @param payload_len The length of the binary data in bytes.
 * @param fragmentation A value of `enum MHD_WEBSOCKET_FRAGMENTATION`
 *                      to specify the fragmentation behavior.
 *                      Specify MHD_WEBSOCKET_FRAGMENTATION_NONE
 *                      if you don't want to use fragmentation.
 * @param[out] frame This variable receives a buffer with
 *                   the encoded binary frame.
 *                   This is what you typically send via `send()`
 *                   to the recipient.
 *                   If no encoded frame is available this is NULL.
 *                   When this variable is not NULL then the allocated buffer
 *                   contains always @a frame_len bytes plus one terminating
 *                   NUL character.
 *                   The caller must free this buffer using #MHD_websocket_free().
 * @param[out] frame_len The length of the result frame buffer in bytes.
 *
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         This is #MHD_WEBSOCKET_STATUS_OK (= 0) on success
 *         or a value less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_encode_binary (struct MHD_WebSocketStream*ws,
                             const char*payload,
                             size_t payload_len,
                             int fragmentation,
                             char**frame,
                             size_t*frame_len);

/**
 * Encodes a websocket ping frame
 *
 * @param ws The websocket stream.
 * @param payload The binary ping payload data to send.
 *                This may be NULL if @a payload_len is 0.
 * @param payload_len The length of the payload data in bytes.
 *                    This may not exceed 125 bytes.
 * @param[out] frame This variable receives a buffer with the encoded ping frame data.
 *                   This is what you typically send via `send()` to the recipient.
 *                   If no encoded frame is available this is NULL.
 *                   When this variable is not NULL then the buffer contains always
 *                   @a frame_len bytes plus one terminating NUL character.
 *                   The caller must free this buffer using #MHD_websocket_free().
 * @param[out] frame_len The length of the result frame buffer in bytes.
 *
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         This is #MHD_WEBSOCKET_STATUS_OK (= 0) on success
 *         or a value less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_encode_ping (struct MHD_WebSocketStream*ws,
                           const char*payload,
                           size_t payload_len,
                           char**frame,
                           size_t*frame_len);

/**
 * Encodes a websocket pong frame
 *
 * @param ws The websocket stream.
 * @param payload The binary pong payload data, which is typically
 *                the decoded payload from the received ping frame.
 *                This may be NULL if @a payload_len is 0.
 * @param payload_len The length of the payload data in bytes.
 *                    This may not exceed 125 bytes.
 * @param[out] frame This variable receives a buffer with
 *                   the encoded pong frame data.
 *                   This is what you typically send via `send()`
 *                   to the recipient.
 *                   If no encoded frame is available this is NULL.
 *                   When this variable is not NULL then the buffer
 *                   contains always @a frame_len bytes plus one
 *                   terminating NUL character.
 *                   The caller must free this buffer
 *                   using #MHD_websocket_free().
 * @param[out] frame_len The length of the result frame buffer in bytes.
 *
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         This is #MHD_WEBSOCKET_STATUS_OK (= 0) on success
 *         or a value less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_encode_pong (struct MHD_WebSocketStream*ws,
                           const char*payload,
                           size_t payload_len,
                           char**frame,
                           size_t*frame_len);

/**
 * Encodes a websocket close frame
 *
 * @param ws The websocket stream.
 * @param reason_code The reason for close.
 *                    You can use `enum MHD_WEBSOCKET_CLOSEREASON`
 *                    for typical reasons,
 *                    but you are not limited to these values.
 *                    The allowed values are specified in RFC 6455 7.4.
 *                    If you don't want to enter a reason, you can specify
 *                    #MHD_WEBSOCKET_CLOSEREASON_NO_REASON then
 *                    no reason is encoded.
 * @param reason_utf8 An UTF-8 encoded text reason why the connection is closed.
 *                    This may be NULL if @a reason_utf8_len is 0.
 *                    This must be NULL if @a reason_code is
 *                    #MHD_WEBSOCKET_CLOSEREASON_NO_REASON (= 0).
 * @param reason_utf8_len The length of the UTF-8 encoded text reason in bytes.
 *                        This may not exceed 123 bytes.
 * @param[out] frame This variable receives a buffer with
 *                   the encoded close frame.
 *                   This is what you typically send via `send()`
 *                   to the recipient.
 *                   If no encoded frame is available this is NULL.
 *                   When this variable is not NULL then the buffer
 *                   contains always @a frame_len bytes plus
 *                   one terminating NUL character.
 *                   The caller must free this buffer
 *                   using #MHD_websocket_free().
 * @param[out] frame_len The length of the result frame buffer in bytes.
 *
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         This is #MHD_WEBSOCKET_STATUS_OK (= 0) on success
 *         or a value less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_encode_close (struct MHD_WebSocketStream*ws,
                            unsigned short reason_code,
                            const char*reason_utf8,
                            size_t reason_utf8_len,
                            char**frame,
                            size_t*frame_len);

/**
 * Sets the seed for the random number generated used for
 * the generation of masked frames (this is only used for client websockets).
 * This seed is used for all websocket streams.
 * Internally `srand()` is called.
 * Please note that on some situations
 * (where `rand()` and `srand()` are shared between your program
 * and this library) this could cause unwanted results in your program if
 * your program relies on a specific seed.
 *
 * @param seed The seed used for the initialization of
 *             the pseudo random number generator.
 *             Typically `time(NULL)` is used here to
 *             generate a seed.
 *
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         This is #MHD_WEBSOCKET_STATUS_OK (= 0) on success
 *         or a value less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_srand (unsigned long seed);

/**
 * Allocates memory with the associated 'malloc' function
 * of the websocket stream
 *
 * @param ws The websocket stream.
 * @param len The length of the memory to allocate in bytes
 *
 * @return The allocated memory on success or NULL on failure.
 * @ingroup websocket
 */
_MHD_EXTERN void*
MHD_websocket_malloc (struct MHD_WebSocketStream*ws,
                      size_t len);

/**
 * Reallocates memory with the associated 'realloc' function
 * of the websocket stream
 *
 * @param ws The websocket stream.
 * @param cls The previously allocated memory or NULL
 * @param len The new length of the memory in bytes
 *
 * @return The allocated memory on success or NULL on failure.
 *         If NULL is returned the previously allocated buffer
 *         remains valid.
 * @ingroup websocket
 */
_MHD_EXTERN void*
MHD_websocket_realloc (struct MHD_WebSocketStream*ws,
                       void*cls,
                       size_t len);

/**
 * Frees memory with the associated 'free' function
 * of the websocket stream
 *
 * @param ws The websocket stream.
 * @param cls The previously allocated memory or NULL
 *
 * @return A value of `enum MHD_WEBSOCKET_STATUS`.
 *         This is #MHD_WEBSOCKET_STATUS_OK (= 0) on success
 *         or a value less than 0 on errors.
 * @ingroup websocket
 */
_MHD_EXTERN int
MHD_websocket_free (struct MHD_WebSocketStream*ws,
                    void*cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
