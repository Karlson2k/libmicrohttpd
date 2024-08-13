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

/**
 * The "application/x-www-form-urlencoded" parsing data
 */
struct mhd_PostParserUrlEncData
{

};

/**
 * The "multipart/form-data" parsing data
 */
struct mhd_PostParserMPartFormData
{
  /**
   * The boundary marker.
   * Allocated in the stream pool
   */
  struct mhd_BufferConst bound;
};


// TODO: describe
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
   * The "large" buffer for POST parsing and POST upload values
   */
  struct mhd_Buffer lbuf;

  /**
   * The size of the data currently in the @a lbuf
   */
  size_t lbuf_used;

  /**
   * The remaining size of "large shared buffer" allowed to allocate for this
   * POST parsing
   */
  size_t lbuf_left; // TODO: Remove? Rename to 'lbuf_limit'?

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
   * The offset in the value data.
   * Used when value is processed incrementally otherwise it is zero.
   */
  size_t value_off;

  /**
   * The position of the next character to be parsed
   */
  size_t next_parse_pos;
};

#endif /* ! MHD_POST_PARSER_H */
