/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file src/mhd2/mhd_post_parser.h
 * @brief  The definition of the post parsers data structures
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_POST_PARSER_H
#define MHD_POST_PARSER_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"
#include "sys_bool_type.h"

#include "http_post_enc.h"
#include "mhd_post_result.h"
#include "mhd_buffer.h"

#ifdef SIZE_MAX
#  define mhd_POST_INVALID_POS SIZE_MAX
#else
#  define mhd_POST_INVALID_POS ((size_t) (~((size_t) (0))))
#endif

/**
 * The states of the "application/x-www-form-urlencoded" field parsing
 */
enum MHD_FIXED_ENUM_ mhd_PostUrlEncState
{
  /**
   * The field processing has not been started
   */
  mhd_POST_UENC_ST_NOT_STARTED = 0
  ,
  /**
   * Processing name of the field
   */
  mhd_POST_UENC_ST_NAME
  ,
  /**
   * At the '=' character after the name.
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_UENC_ST_AT_EQ
  ,
  /**
   * The '=' character after the name has been found.
   * Looking for the first value character.
   */
  mhd_POST_UENC_ST_EQ_FOUND
  ,
  /**
   * Processing the value of the field.
   */
  mhd_POST_UENC_ST_VALUE
  ,
  /**
   * At the ampersand '&' character.
   * Means that full field is found.
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_UENC_ST_AT_AMPRSND
  ,
  /**
   * Full field found.
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_UENC_ST_FULL_FIELD_FOUND
};

/**
 * The "application/x-www-form-urlencoded" parsing data
 */
struct mhd_PostParserUrlEncData
{
  /**
   * The parsing state
   */
  enum mhd_PostUrlEncState st;

  /**
   * The index of the start of the name.
   */
  size_t name_idx;

  /**
   * The length of the name of the current field, not including
   * the terminating zero.
   * Zero until the length is found.
   */
  size_t name_len;

  /**
   * The index of the start of the value.
   * Zero until the value is found.
   * Cannot be zero if any (including zero-length) value available.
   */
  size_t value_idx;

  /**
   * The length of the value of the current field, not including
   * the terminating zero.
   * Zero until the length is found.
   * If @a st is #mhd_POST_UENC_ST_VALUE and @a value_len is not zero,
   * then it is the length of the partial (decoded) value provided previously
   * to the "stream" processing callback (which responded with a "suspend"
   * action).
   */
  size_t value_len;

  /**
   * The index of the last percent ('%') character found.
   * Set to #mhd_POST_INVALID_POS when no '%' char found.
   * Used for two proposes:
   * + indicates that "name" or "value" needs persent-deconding
   * + helps to detect incomplete percent-encoded char for stream processing
   */
  size_t last_pct_idx;
};


/**
 * The states of the "multipart/form-data" parsing
 */
enum MHD_FIXED_ENUM_ mhd_PostMPartState
{
  /**
   * The parsing has not been started
   * Should not be used outside processing loop except initial initialisation.
   */
  mhd_POST_MPART_ST_NOT_STARTED = 0
  ,
  /**
   * Check for delimiter failed, continuing processing of the preabmle
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_MPART_ST_BACK_TO_PREAMBL
  ,
  /**
   * Processing preabmle
   */
  mhd_POST_MPART_ST_PREAMBL
  ,
  /**
   * Found CR char in the preamble
   */
  mhd_POST_MPART_ST_PREAMBL_CR_FOUND
  ,
  /**
   * Found LF char in the preamble (after CR or just bare LF if allowed)
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_MPART_ST_PREAMBL_LINE_START
  ,
  /**
   * Checking for potential delimiter marker at the start of the string
   */
  mhd_POST_MPART_ST_PREAMBL_CHECKING_FOR_DELIM
  ,
  /**
   * Found the first delimiter.
   * Need to find the end of the delimiter string and check for possible "final"
   * delimiter.
   */
  mhd_POST_MPART_ST_FIRST_DELIM_FOUND
  ,
  /**
   * Found start of the first "part"
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   */
  mhd_POST_MPART_ST_FIRST_PART_START
  ,
  /**
   * Found start of the "part" (after the delimiter)
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   */
  mhd_POST_MPART_ST_PART_START
  ,
  /**
   * Starting processing of embedded header line
   */
  mhd_POST_MPART_ST_HEADER_LINE_START
  ,
  /**
   * Processing embedded header line
   */
  mhd_POST_MPART_ST_HEADER_LINE
  ,
  /**
   * Found CR char in the embedded header line
   */
  mhd_POST_MPART_ST_HEADER_LINE_CR_FOUND
  ,
  /**
   * Found complete embedded header line, at the final character.
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_MPART_ST_HEADER_LINE_END
  ,
  /**
   * Starting processing of the "value"
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   */
  mhd_POST_MPART_ST_VALUE_START
  ,
  /**
   * Check for delimiter failed, continuing processing of the "value"
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Can be used outside processing loop if streaming partial value.
   */
  mhd_POST_MPART_ST_BACK_TO_VALUE
  ,
  /**
   * Processing "value"
   */
  mhd_POST_MPART_ST_VALUE
  ,
  /**
   * Found CR char in the "value"
   */
  mhd_POST_MPART_ST_VALUE_CR_FOUND
  ,
  /**
   * Found LF char in the "value"
   */
  mhd_POST_MPART_ST_VALUE_LINE_START
  ,
  /**
   * Checking for potential delimiter marker at the start of the string
   */
  mhd_POST_MPART_ST_VALUE_CHECKING_FOR_DELIM
  ,
  /**
   * Found the delimiter.
   * Need to find the end of the delimiter string and check for possible "final"
   * delimiter.
   */
  mhd_POST_MPART_ST_DELIM_FOUND
  ,
  /**
   * Found the end of the "value"
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_MPART_ST_VALUE_END_FOUND
  ,
  /**
   * Found the end of the "value" closed by the "final" delimiter
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_MPART_ST_VALUE_END_FOUND_FINAL
  ,
  /**
   * Found the complete field
   */
  mhd_POST_MPART_ST_FULL_FIELD_FOUND
  ,
  /**
   * Found the complete field closed by the "final" delimiter
   */
  mhd_POST_MPART_ST_FULL_FIELD_FOUND_FINAL
  ,
  /**
   * Processing "epilogue"
   */
  mhd_POST_MPART_ST_EPILOGUE
  ,
  /**
   * The format of the input data is invalid
   */
  mhd_POST_MPART_ST_FORMAT_ERROR
};


/**
 * The "multipart/form-data" field parsing data
 */
struct mhd_PostParserMPartFieldData
{
  /**
   * The index of the start of the name.
   */
  size_t name_idx;
  /**
   * The length of the name of the current field, not including
   * the terminating zero.
   * Zero until the length is found.
   */
  size_t name_len;
  /**
   * The index of the start of the value.
   * Zero until the value is found.
   * Cannot be zero if any (including zero-length) value available.
   */
  size_t value_idx;
  /**
   * The length of the value of the current field, not including
   * the terminating zero.
   * Zero until the length is found.
   */
  size_t value_len;
  /**
   * The index of the start of the filename of the current field.
   * Zero until the value is found.
   * Cannot be zero if any (including zero-length) filename available.
   */
  size_t filename_idx;
  /**
   * The length of the filename of the current field, not including
   * the terminating zero.
   * Zero until the length is found.
   */
  size_t filename_len;
  /**
   * The index of the start of the value of the Content-Type of the current
   * field.
   * Zero until the value is found.
   * Cannot be zero if any (including zero-length) filename available.
   */
  size_t cntn_type_idx;
  /**
   * The length of the filename of the value of the Content-Type of the current
   * field, not including the terminating zero.
   * Zero until the length is found.
   */
  size_t cntn_type_len;
  /**
   * The index of the start of the value of the Content-Encoding of the current
   * field.
   * Zero until the value is found.
   * Cannot be zero if any (including zero-length) filename available.
   */
  size_t enc_idx;
  /**
   * The length of the filename of the value of the Content-Encoding of
   * the current field, not including the terminating zero.
   * Zero until the length is found.
   */
  size_t enc_len;
};

/**
 * The "multipart/form-data" parsing data
 */
struct mhd_PostParserMPartFormData
{
  /**
   * The parsing state
   */
  enum mhd_PostMPartState st;

  /**
   * The field parsing data
   */
  struct mhd_PostParserMPartFieldData f;

  /**
   * Position of the first character when checking for the delimiter or for
   * the embedded header
   */
  size_t line_start;

  /**
   * The first position where the check for the delimiter has been started.
   * Should be CR char (or bare LR if allowed).
   * If delimiter is not found, re-interpreted as part of the filed "value".
   * If delimiter is found, this position can be moved to the second character
   * if the first position of the delimiter is used to put zero-termination
   * of previous field "value".
   */
  size_t delim_check_start;

  /**
   * The boundary marker.
   * Allocated in the stream's memory pool
   */
  struct mhd_BufferConst bound;
};


/**
 * The states of the "text/plain" parsing
 */
enum MHD_FIXED_ENUM_ mhd_PostTextState
{
  /**
   * The line processing has not been started yet
   */
  mhd_POST_TEXT_ST_NOT_STARTED = 0
  ,
  /**
   * Processing name of the field
   */
  mhd_POST_TEXT_ST_NAME
  ,
  /**
   * At the '=' character after the name.
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_TEXT_ST_AT_EQ
  ,
  /**
   * The '=' character after the name has been found.
   * Looking for the first value character.
   */
  mhd_POST_TEXT_ST_EQ_FOUND
  ,
  /**
   * Processing the value of the field.
   */
  mhd_POST_TEXT_ST_VALUE
  ,
  /**
   * At the CR character.
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_TEXT_ST_AT_CR
  ,
  /**
   * Looking for LF character after CR character.
   */
  mhd_POST_TEXT_ST_CR_FOUND
  ,
  /**
   * At the LF character without preceding CR character.
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_TEXT_ST_AT_LF_BARE
  ,
  /**
   * End of the line found.
   * This is an intermediate state, should be processed and switched to the next
   * state immediately.
   * Should not be used outside processing loop.
   */
  mhd_POST_TEXT_ST_FULL_LINE_FOUND
};

/**
 * The "text/plain" parsing data
 */
struct mhd_PostParserTextData
{
  /**
   * The parsing state
   */
  enum mhd_PostTextState st;

  /**
   * The index of the start of the name.
   */
  size_t name_idx;

  /**
   * The length of the name of the current field, not including
   * the terminating zero.
   * Zero until the length is found.
   */
  size_t name_len;

  /**
   * The index of the start of the value.
   * Zero until the value is found.
   * Cannot be zero if any (including zero-length) value available.
   */
  size_t value_idx;

  /**
   * The length of the value of the current field, not including
   * the terminating zero.
   * Zero until the length is found.
   */
  size_t value_len;
};


/**
 * The encoding-specific parsing data
 */
union mhd_PostParserDetailedData
{
  /**
   * The "application/x-www-form-urlencoded" parsing data
   */
  struct mhd_PostParserUrlEncData u_enc;

  /**
   * The "multipart/form-data" parsing data
   */
  struct mhd_PostParserMPartFormData m_form;

  /**
   * The "text/plain" parsing data
   */
  struct mhd_PostParserTextData text;
};

// TODO: remove?
/**
 * The type of partially processed data in the buffer
 */
enum MHD_FIXED_ENUM_ mhd_PostParserPartProcType
{
  /**
   * No data in the buffer
   */
  mhd_POST_PARSER_PART_PROC_TYPE_NONE = 0
  ,
  /**
   * The data is partially processed name
   */
  mhd_POST_PARSER_PART_PROC_TYPE_NAME
  ,
  /**
   * The data is partially processed value
   */
  mhd_POST_PARSER_PART_PROC_TYPE_VALUE
};

// TODO: remove?
/**
 * Buffered partially processed data
 */
struct mhd_PostParserPartProcessedData
{
  /**
   * Partially processed data, left from previous upload data portion
   */
  struct mhd_Buffer data;

  /**
   * The type of partially processed data in the @a data buffer
   */
  enum mhd_PostParserPartProcType d_type;
};

/**
 * The POST parsing data
 */
struct mhd_PostParserData
{
  /**
   * The result of parsing POST data
   */
  enum MHD_PostParseResult parse_result;

  /**
   * The type of POSE encoding is used.
   * Active member of @a e_d depends on this type.
   */
  enum MHD_HTTP_PostEncoding enc;

  /**
   * The encoding-specific parsing data
   */
  union mhd_PostParserDetailedData e_d;

  /**
   * The size of the data currently in the @a lbuf
   */
  size_t lbuf_used;

  /**
   * The maximum possible lbuf allocation size
   */
  size_t lbuf_limit;

  /**
   * True if any POST data was parsed successfully.
   */
  bool some_data_provided;

  /**
   * The start index of the current field.
   * If the field is processed by incremental callback, buffer can be freed or
   * reused up to this position (inclusive).
   */
  size_t field_start;

  /**
   * 'true' if current filed 'value' must be "streamed".
   */
  bool force_streamed;

  /**
   * The offset in the current value data.
   * Used when value is processed incrementally otherwise it is zero.
   */
  size_t value_off;

  /**
   * The position of the next character to be parsed
   */
  size_t next_parse_pos;
};

#endif /* ! MHD_POST_PARSER_H */
