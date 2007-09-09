/*
     This file is part of libmicrohttpd
     (C) 2007 Daniel Pittman and Christian Grothoff

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
 * @file postprocessor.c
 * @brief  Methods for parsing POST data
 * @author Christian Grothoff
 */

#include "internal.h"

/**
 * States in the PP parser's state machine.
 */
enum PP_State
{

  PP_Init = 0,

  PP_HaveKey = 1,

  PP_ExpectNewLine = 2,

  PP_ExpectNewLineR = 3,

  PP_ExpectNewLineN = 4,

  PP_Headers = 5,

  PP_SkipRNRN = 6,

  PP_SkipNRN = 7,

  PP_SkipRN = 8,

  PP_SkipN = 9,

  PP_ValueToBoundary = 10,

  PP_FinalDash = 11,

  PP_Error = 9999,


};

/**
 * Internal state of the post-processor.
 */
struct MHD_PostProcessor
{

  /**
   * The connection for which we are doing
   * POST processing.
   */
  struct MHD_Connection *connection;

  /**
   * Function to call with POST data.
   */
  MHD_PostDataIterator ikvi;

  /**
   * Extra argument to ikvi.
   */
  void *cls;

  /**
   * Encoding as given by the headers of the
   * connection.
   */
  const char *encoding;

  /**
   * Pointer to the name given in disposition.
   */
  char *content_disposition;

  /**
   * Pointer to the (current) content type.
   */
  char *content_type;

  /**
   * Pointer to the (current) filename.
   */
  char *filename;

  /**
   * Pointer to the (current) encoding.
   */
  char *transfer_encoding;

  /**
   * Unprocessed value bytes due to escape
   * sequences (URL-encoding only).
   */
  char xbuf[8];

  /**
   * Size of our buffer for the key.
   */
  unsigned int buffer_size;

  /**
   * Current position in the key buffer.
   */
  unsigned int buffer_pos;

  /**
   * Current position in xbuf.
   */
  unsigned int xbuf_pos;

  /**
   * Current offset in the value being processed.
   */
  unsigned int value_offset;

  /**
   * State of the parser.
   */
  enum PP_State state;

};


/**
 * Create a PostProcessor.
 * 
 * A PostProcessor can be used to (incrementally)
 * parse the data portion of a POST request.
 *
 * @param connection the connection on which the POST is
 *        happening (used to determine the POST format)
 * @param buffer_size maximum number of bytes to use for
 *        internal buffering (used only for the parsing,
 *        specifically the parsing of the keys).  A
 *        tiny value (256-1024) should be sufficient.
 *        Do NOT use 0.
 * @param ikvi iterator to be called with the parsed data
 * @param cls first argument to ikvi
 * @return NULL on error (out of memory, unsupported encoding),
 *         otherwise a PP handle
 */
struct MHD_PostProcessor *
MHD_create_post_processor (struct MHD_Connection *connection,
                           unsigned int buffer_size,
                           MHD_PostDataIterator ikvi, void *cls)
{
  struct MHD_PostProcessor *ret;
  const char *encoding;

  if ((buffer_size < 256) || (connection == NULL) || (ikvi == NULL))
    abort ();
  encoding = MHD_lookup_connection_value (connection,
                                          MHD_HEADER_KIND,
                                          MHD_HTTP_HEADER_CONTENT_TYPE);
  if (encoding == NULL)
    return NULL;
  if ((0 != strcasecmp (MHD_HTTP_POST_ENCODING_FORM_URLENCODED,
                        encoding)) &&
      (0 != strcasecmp (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA, encoding)))
    return NULL;
  ret = malloc (sizeof (struct MHD_PostProcessor) + buffer_size + 1);
  if (ret == NULL)
    return NULL;
  memset (ret, 0, sizeof (struct MHD_PostProcessor));
  ret->connection = connection;
  ret->ikvi = ikvi;
  ret->cls = cls;
  ret->encoding = encoding;
  ret->buffer_size = buffer_size;
  ret->state = PP_Init;
  return ret;
}

/**
 * On-stack buffer that we use for un-escaping of the value.
 */
#define XBUF_SIZE 1024

/**
 * Process url-encoded POST data.
 */
static int
post_process_urlencoded (struct MHD_PostProcessor *pp,
                         const char *post_data, unsigned int post_data_len)
{
  unsigned int equals;
  unsigned int amper;
  unsigned int poff;
  unsigned int xoff;
  unsigned int delta;
  char *buf;
  char xbuf[XBUF_SIZE + 1];

  buf = (char *) &pp[1];
  poff = 0;
  while (poff < post_data_len)
    {
      switch (pp->state)
        {
        case PP_Init:
          equals = 0;
          while ((equals + poff < post_data_len) &&
                 (post_data[equals + poff] != '='))
            equals++;
          if (equals + pp->buffer_pos > pp->buffer_size)
            {
              pp->state = PP_Error;     /* out of memory */
              return MHD_NO;
            }
          memcpy (&buf[pp->buffer_pos], &post_data[poff], equals);
          pp->buffer_pos += equals;
          if (equals + poff == post_data_len)
            return MHD_YES;     /* no '=' yet */
          buf[pp->buffer_pos] = '\0';   /* 0-terminate key */
          pp->buffer_pos = 0;   /* reset for next key */
          MHD_http_unescape (buf);
          poff += equals + 1;
          pp->state = PP_HaveKey;
          pp->value_offset = 0;
          break;
        case PP_HaveKey:
          /* obtain rest of value from previous iteration */
          memcpy (xbuf, pp->xbuf, pp->xbuf_pos);
          xoff = pp->xbuf_pos;
          pp->xbuf_pos = 0;

          /* find last position in input buffer that is part of the value */
          amper = 0;
          while ((amper + poff < post_data_len) &&
                 (post_data[amper + poff] != '&') &&
                 (post_data[amper + poff] != '\n') &&
                 (post_data[amper + poff] != '\r'))
            amper++;

          /* compute delta, the maximum number of bytes that we will be able to
             process right now (either amper-limited of xbuf-size limited) */
          delta = amper;
          if (delta > XBUF_SIZE - xoff)
            delta = XBUF_SIZE - xoff;

          /* move input into processing buffer */
          memcpy (&xbuf[xoff], &post_data[poff], delta);
          xoff += delta;
          poff += delta;

          /* find if escape sequence is at the end of the processing buffer;
             if so, exclude those from processing (reduce delta to point at
             end of processed region) */
          delta = xoff;
          if ((delta > 0) && (xbuf[delta - 1] == '%'))
            delta--;
          else if ((delta > 1) && (xbuf[delta - 2] == '%'))
            delta -= 2;

          /* if we have an incomplete escape sequence, save it to 
             pp->xbuf for later */
          if (delta < xoff)
            {
              memcpy (pp->xbuf, &xbuf[delta], xoff - delta);
              pp->xbuf_pos = xoff - delta;
              xoff = delta;
            }

          /* If we have nothing to do (delta == 0) and
             not just because the value is empty (are
             waiting for more data), go for next iteration */
          if ((xoff == 0) && (poff == post_data_len))
            continue;

          /* unescape */
          xbuf[xoff] = '\0';    /* 0-terminate in preparation */
          MHD_http_unescape (xbuf);

          /* finally: call application! */
          pp->ikvi (pp->cls, MHD_POSTDATA_KIND, (const char *) &pp[1],  /* key */
                    NULL, NULL, NULL, xbuf, pp->value_offset, xoff);
          pp->value_offset += xoff;

          /* are we done with the value? */
          if (poff < post_data_len)
            {
              /* we found the end of the value! */
              pp->state = PP_Init;
              poff++;           /* skip '&' or new-lines */

              if ((post_data[poff - 1] == '\n') ||
                  (post_data[poff - 1] == '\r'))
                pp->state = PP_ExpectNewLine;
            }
          break;
        case PP_ExpectNewLine:
          if ((post_data[poff] == '\n') || (post_data[poff] == '\r'))
            {
              poff++;
              /* we are done, report error if we receive any more... */
              pp->state = PP_Error;
              return MHD_YES;
            }
          return MHD_NO;
        case PP_Error:
          return MHD_NO;
        default:
          abort ();             /* should never happen! */
        }
    }
  return MHD_YES;
}

/**
 * If the given line matches the prefix, strdup the
 * rest of the line into the suffix ptr.
 *
 * @return MHD_YES if there was a match, MHD_NO if not
 */
static int
try_match_header (const char *prefix, char *line, char **suffix)
{
  if (0 == strncasecmp (prefix, line, strlen (prefix)))
    {
      *suffix = strdup (&line[strlen (prefix)]);
      return MHD_YES;
    }
  return MHD_NO;
}

/**
 * Decode multipart POST data. 
 *
 * TODO: If the content-type is multipart/mixed, we do not do anything
 * special.  However, we should probably break the individual values
 * apart and give them to the callback individually (will require some
 * additional states & state).
 *
 * TODO: this code has never been tested...
 * 
 * See http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4 
 */
static int
post_process_multipart (struct MHD_PostProcessor *pp,
                        const char *post_data, unsigned int post_data_len)
{
  char *buf;
  const char *boundary;
  unsigned int max;
  unsigned int ioff;
  unsigned int poff;
  unsigned int newline;
  unsigned int endquote;
  size_t blen;

  buf = (char *) &pp[1];
  ioff = 0;
  poff = 0;
  boundary =
    &pp->encoding[strlen (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA)];
  /* Q: should this be "strcasestr"? */
  if (NULL != strstr (boundary, "boundary="))
    boundary = strstr (boundary, "boundary=") + strlen ("boundary=");
  else
    return MHD_NO;              /* failed to determine boundary */
  blen = strlen (boundary);
  if (blen * 2 + 2 > pp->buffer_size)
    return MHD_NO;              /* (will be) out of memory */
  while ((poff < post_data_len) || (pp->buffer_pos > ioff))
    {
      /* first, move data to our internal buffer */
      max = pp->buffer_size - pp->buffer_pos;
      if ((max < ioff) && (max < post_data_len))
        {
          memmove (buf, &buf[ioff], pp->buffer_pos - ioff);
          pp->buffer_pos -= ioff;
          ioff = 0;
          max = pp->buffer_size - pp->buffer_pos;
        }
      if (max > post_data_len)
        max = post_data_len;
      memcpy (&buf[pp->buffer_pos], post_data, max);
      poff += max;
      pp->buffer_pos += max;

      switch (pp->state)
        {
        case PP_Init:
          /* we're looking for the boundary */
          if (pp->buffer_pos < 2 + blen + ioff)
            goto END;
          if ((0 != memcmp ("--", &buf[ioff], 2)) ||
              (0 != memcmp (&buf[ioff + 2], boundary, blen)))
            return MHD_NO;      /* expected boundary */

          /* remove boundary from buffer */
          ioff += 2 + blen;

          /* next: start with headers */
          pp->state = PP_ExpectNewLineR;
          break;
        case PP_ExpectNewLineR:
          if (buf[ioff] == '-')
            {
              /* last boundary ends with "--" */
              ioff++;
              pp->state = PP_FinalDash;
              break;
            }
          if (buf[ioff] == '\r')
            {
              ioff++;
              pp->state = PP_ExpectNewLineN;
              break;
            }
          /* fall through! */
        case PP_ExpectNewLineN:
          if (buf[ioff] == '\n')
            {
              ioff++;
              pp->state = PP_Headers;
              break;
            }
          return MHD_NO;
        case PP_Headers:
          newline = 0;
          while ((newline + ioff < pp->buffer_pos) &&
                 (buf[newline + ioff] != '\r') &&
                 (buf[newline + ioff] != '\n'))
            newline++;
          if (newline == pp->buffer_size)
            return MHD_NO;      /* out of memory */
          if (newline + ioff == pp->buffer_pos)
            {
              /* try to make more room */
              memmove (buf, &buf[ioff], pp->buffer_pos - ioff);
              pp->buffer_pos -= ioff;
              ioff = 0;
              break;
            }
          if (newline == 0)
            {
              pp->state = PP_SkipRNRN;
              break;
            }
          buf[ioff + newline] = '\0';
          if ((MHD_YES
               == try_match_header ("Content-Disposition: form-data; name=\"",
                                    &buf[ioff],
                                    &pp->content_disposition)) &&
              (pp->content_disposition != NULL) &&
              (0 < strlen (pp->content_disposition)))
            {
              /* find end-quote; then check if we also have a filename! */
              endquote = 0;
              while ((pp->content_disposition[endquote] != '\"') &&
                     (pp->content_disposition[endquote] != '\0'))
                endquote++;
              pp->content_disposition[endquote++] = '\0';       /* remove end-quote */
              if ((MHD_YES
                   == try_match_header (" filename=",
                                        &pp->content_disposition[endquote],
                                        &pp->filename)) &&
                  (pp->filename != NULL) && (0 < strlen (pp->filename)))
                pp->filename[strlen (pp->filename) - 1] = '\0'; /* remove end-quote */
            }
          try_match_header ("Content-Type: ", &buf[ioff], &pp->content_type);
          try_match_header ("Content-Transfer-Encoding: ",
                            &buf[ioff], &pp->transfer_encoding);
          break;
        case PP_SkipRNRN:
          if (buf[ioff] == '\r')
            {
              ioff++;
              pp->state = PP_SkipNRN;
              break;
            }
          /* fall through! */
        case PP_SkipNRN:
          if (buf[ioff] == '\n')
            {
              ioff++;
              pp->state = PP_SkipRN;
              break;
            }
          return MHD_NO;        /* parse error */
        case PP_SkipRN:
          if (buf[ioff] == '\r')
            {
              ioff++;
              pp->state = PP_SkipN;
              break;
            }
          /* fall through! */
        case PP_SkipN:
          if (buf[ioff] == '\n')
            {
              ioff++;
              pp->state = PP_ValueToBoundary;
              pp->value_offset = 0;
              break;
            }
          return MHD_NO;        /* parse error */
        case PP_ValueToBoundary:
          /* all data in buf until the boundary
             (\r\n--+boundary) is part of the value */
          newline = 0;
          while (1)
            {
              while ((newline + ioff + 4 < pp->buffer_pos) &&
                     (0 != memcmp ("\r\n--", &buf[newline + ioff], 4)))
                newline++;
              if (newline + blen + 4 > pp->buffer_size)
                {
                  /* boundary not in sight -- 
                     process data, then make room for more! */
                  if (MHD_NO == pp->ikvi (pp->cls,
                                          MHD_POSTDATA_KIND,
                                          pp->content_disposition,
                                          pp->filename,
                                          pp->content_type,
                                          pp->transfer_encoding,
                                          &buf[ioff],
                                          pp->value_offset, newline))
                    {
                      pp->state = PP_Error;
                      break;
                    }
                  pp->value_offset += newline;
                  ioff += newline;
                  memmove (buf, &buf[ioff], pp->buffer_pos - ioff);
                  pp->buffer_pos -= ioff;
                  break;
                }
              if (newline + blen + 4 < pp->buffer_pos)
                {
                  /* can check for boundary right now! */
                  if (0 == memcmp (&buf[newline + ioff + 4], boundary, blen))
                    {
                      /* found: process data, then look for more */
                      if (MHD_NO == pp->ikvi (pp->cls,
                                              MHD_POSTDATA_KIND,
                                              pp->content_disposition,
                                              pp->filename,
                                              pp->content_type,
                                              pp->transfer_encoding,
                                              &buf[ioff],
                                              pp->value_offset, newline))
                        {
                          pp->state = PP_Error;
                          break;
                        }

                      /* clean up! */
                      if (pp->content_type != NULL)
                        {
                          free (pp->content_type);
                          pp->content_type = NULL;
                        }
                      if (pp->content_disposition != NULL)
                        {
                          free (pp->content_disposition);
                          pp->content_disposition = NULL;
                        }
                      if (pp->filename != NULL)
                        {
                          free (pp->filename);
                          pp->filename = NULL;
                        }
                      if (pp->transfer_encoding != NULL)
                        {
                          free (pp->transfer_encoding);
                          pp->transfer_encoding = NULL;
                        }
                      pp->value_offset = 0;
                      ioff += newline + 2;      /* skip data + new line */
                      pp->state = PP_Init;
                      break;
                    }
                  /* not the boundary, look further! */
                  newline += 4;
                  continue;
                }


            }
          break;
        case PP_FinalDash:
          if (buf[ioff] == '-')
            {
              /* last boundary ends with "--" */
              ioff++;
              pp->state = PP_Error;
              break;
            }
          return MHD_NO;        /* parse error */
        case PP_Error:
          return MHD_NO;
        default:
          abort ();             /* should never happen! */

        }
    }
END:
  memmove (buf, &buf[ioff], pp->buffer_pos - ioff);
  pp->buffer_pos -= ioff;
  return MHD_YES;
}

/**
 * Parse and process POST data.
 * Call this function when POST data is available
 * (usually during an MHD_AccessHandlerCallback)
 * with the upload_data and upload_data_size.  
 * Whenever possible, this will then cause calls
 * to the MHD_IncrementalKeyValueIterator.  
 *
 * @param pp the post processor
 * @param post_data post_data_len bytes of POST data
 * @param post_data_len length of post_data
 * @return MHD_YES on success, MHD_NO on error
 *         (out-of-memory, iterator aborted, parse error)
 */
int
MHD_post_process (struct MHD_PostProcessor *pp,
                  const char *post_data, unsigned int post_data_len)
{
  if (post_data_len == 0)
    return MHD_YES;
  if (0 == strcasecmp (MHD_HTTP_POST_ENCODING_FORM_URLENCODED, pp->encoding))
    return post_process_urlencoded (pp, post_data, post_data_len);
  if (0 ==
      strncasecmp (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA, pp->encoding,
                   strlen (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA)))
    return post_process_multipart (pp, post_data, post_data_len);
  /* this should never be reached */
  return MHD_NO;
}

/**
 * Release PostProcessor resources.
 */
void
MHD_destroy_post_processor (struct MHD_PostProcessor *pp)
{
  /* These internal strings need cleaning up since
     the post-processing may have been interrupted
     at any stage */
  if (pp->content_type != NULL)
    free (pp->content_type);
  if (pp->content_disposition != NULL)
    free (pp->content_disposition);
  if (pp->filename != NULL)
    free (pp->filename);
  if (pp->transfer_encoding != NULL)
    free (pp->transfer_encoding);
  free (pp);
}

/* end of postprocessor.c */
