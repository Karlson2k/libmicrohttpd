/*
     This file is part of libmicrohttpd
     Copyright (C) 2013-2024 Christian Grothoff (and other contributing authors)
     Copyright (C) 2014-2022 Evgeny Grin (Karlson2k)

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
 * @file demo.c
 * @brief complex demonstration site: create directory index, offer
 *        upload via form and HTTP POST, download with mime type detection
 *        and error reporting (403, etc.) --- and all of this with
 *        high-performance settings (large buffers, thread pool).
 *        If you want to benchmark MHD, this code should be used to
 *        run tests against.  Note that the number of threads may need
 *        to be adjusted depending on the number of available cores.
 * @author Christian Grothoff
 * @author Karlson2k (Evgeny Grin)
 */
#include <microhttpd2.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#ifdef MHD_HAVE_LIBMAGIC
#include <magic.h>
#endif /* MHD_HAVE_LIBMAGIC */
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#if defined(MHD_CPU_COUNT) && (MHD_CPU_COUNT + 0) < 2
#undef MHD_CPU_COUNT
#endif
#if ! defined(MHD_CPU_COUNT)
#define MHD_CPU_COUNT 2
#endif

#ifndef PATH_MAX
/* Some platforms (namely: GNU Hurd) do no define PATH_MAX.
   As it is only example for MHD, just use reasonable value for PATH_MAX. */
#define PATH_MAX 16384
#endif

/**
 * Number of threads to run in the thread pool.  Should (roughly) match
 * the number of cores on your system.
 */
#define NUMBER_OF_THREADS MHD_CPU_COUNT

#ifdef MHD_HAVE_LIBMAGIC
/**
 * How many bytes of a file do we give to libmagic to determine the mime type?
 * 16k might be a bit excessive, but ought not hurt performance much anyway,
 * and should definitively be on the safe side.
 */
#define MAGIC_HEADER_SIZE (16 * 1024)
#endif /* MHD_HAVE_LIBMAGIC */


/**
 * Page returned for file-not-found.
 */
#define FILE_NOT_FOUND_PAGE \
        "<html><head><title>File not found</title></head><body>File not found</body></html>"


/**
 * Page returned for internal errors.
 */
#define INTERNAL_ERROR_PAGE \
        "<html><head><title>Internal error</title></head><body>Internal error</body></html>"


/**
 * Page returned for refused requests.
 */
#define REQUEST_REFUSED_PAGE \
        "<html><head><title>Request refused</title></head><body>Request refused (file exists?)</body></html>"


/**
 * Head of index page.
 */
#define INDEX_PAGE_HEADER \
        "<html>\n<head><title>Welcome</title></head>\n<body>\n" \
        "<h1>Upload</h1>\n" \
        "<form method=\"POST\" enctype=\"multipart/form-data\" action=\"/\">\n" \
        "<dl><dt>Content type:</dt><dd>" \
        "<input type=\"radio\" name=\"category\" value=\"books\">Book</input>" \
        "<input type=\"radio\" name=\"category\" value=\"images\">Image</input>" \
        "<input type=\"radio\" name=\"category\" value=\"music\">Music</input>" \
        "<input type=\"radio\" name=\"category\" value=\"software\">Software</input>" \
        "<input type=\"radio\" name=\"category\" value=\"videos\">Videos</input>\n" \
        "<input type=\"radio\" name=\"category\" value=\"other\" checked>Other</input></dd>" \
        "<dt>Language:</dt><dd>" \
        "<input type=\"radio\" name=\"language\" value=\"no-lang\" checked>none</input>" \
        "<input type=\"radio\" name=\"language\" value=\"en\">English</input>" \
        "<input type=\"radio\" name=\"language\" value=\"de\">German</input>" \
        "<input type=\"radio\" name=\"language\" value=\"fr\">French</input>" \
        "<input type=\"radio\" name=\"language\" value=\"es\">Spanish</input></dd>\n" \
        "<dt>File:</dt><dd>" \
        "<input type=\"file\" name=\"upload\"/></dd></dl>" \
        "<input type=\"submit\" value=\"Send!\"/>\n" \
        "</form>\n" \
        "<h1>Download</h1>\n" \
        "<ol>\n"

/**
 * Footer of index page.
 */
#define INDEX_PAGE_FOOTER "</ol>\n</body>\n</html>"


/**
 * NULL-terminated array of supported upload categories.  Should match HTML
 * in the form.
 */
static const char *const categories[] = {
  "books",
  "images",
  "music",
  "software",
  "videos",
  "other",
  NULL,
};


/**
 * Specification of a supported language.
 */
struct Language
{
  /**
   * Directory name for the language.
   */
  const char *dirname;

  /**
   * Long name for humans.
   */
  const char *longname;

};

/**
 * NULL-terminated array of supported upload categories.  Should match HTML
 * in the form.
 */
static const struct Language languages[] = {
  { "no-lang", "No language specified" },
  { "en", "English" },
  { "de", "German" },
  { "fr", "French" },
  { "es", "Spanish" },
  { NULL, NULL },
};


/**
 * Response returned if the requested file does not exist (or is not accessible).
 */
static struct MHD_Response *file_not_found_response;

/**
 * Response returned for internal errors.
 */
static struct MHD_Response *internal_error_response;

/**
 * Response returned for '/' (GET) to list the contents of the directory and allow upload.
 */
static struct MHD_Response *cached_directory_response;

/**
 * Response returned for refused uploads.
 */
static struct MHD_Response *request_refused_response;

/**
 * Mutex used when we update the cached directory response object.
 */
static pthread_mutex_t mutex;

#ifdef MHD_HAVE_LIBMAGIC
/**
 * Global handle to MAGIC data.
 */
static magic_t magic;
#endif /* MHD_HAVE_LIBMAGIC */


/**
 * Mark the given response as HTML for the browser.
 *
 * @param response response to mark
 */
static void
mark_as_html (struct MHD_Response *response)
{
  (void) MHD_response_add_header (response,
                                  MHD_HTTP_HEADER_CONTENT_TYPE,
                                  "text/html");
}


/**
 * Replace the existing 'cached_directory_response' with the
 * given response.
 *
 * @param response new directory response
 */
static void
update_cached_response (struct MHD_Response *response)
{
  (void) pthread_mutex_lock (&mutex);
  if (NULL != cached_directory_response)
    MHD_response_destroy (cached_directory_response);
  cached_directory_response = response;
  if (MHD_SC_OK !=
      MHD_response_set_option (response,
                               &MHD_R_OPTION_REUSABLE (
                                 MHD_YES)))
    exit (1);
  (void) pthread_mutex_unlock (&mutex);
}


/**
 * Context keeping the data for the response we're building.
 */
struct ResponseDataContext
{
  /**
   * Response data string.
   */
  char *buf;

  /**
   * Number of bytes allocated for 'buf'.
   */
  size_t buf_len;

  /**
   * Current position where we append to 'buf'. Must be smaller or equal to 'buf_len'.
   */
  size_t off;

};


/**
 * Create a listing of the files in 'dirname' in HTML.
 *
 * @param rdc where to store the list of files
 * @param dirname name of the directory to list
 * @return true on success, false on error
 */
static bool
list_directory (struct ResponseDataContext *rdc,
                const char *dirname)
{
  char fullname[PATH_MAX];
  struct stat sbuf;
  DIR *dir;
  struct dirent *de;

  if (NULL == (dir = opendir (dirname)))
    return false;
  while (NULL != (de = readdir (dir)))
  {
    int res;
    if ('.' == de->d_name[0])
      continue;
    if (sizeof (fullname) <= (unsigned int)
        snprintf (fullname, sizeof (fullname),
                  "%s/%s",
                  dirname, de->d_name))
      continue;  /* ugh, file too long? how can this be!? */
    if (0 != stat (fullname, &sbuf))
      continue;  /* ugh, failed to 'stat' */
    if (! S_ISREG (sbuf.st_mode))
      continue;  /* not a regular file, skip */
    if (rdc->off + 1024 > rdc->buf_len)
    {
      void *r;

      if ( (2 * rdc->buf_len + 1024) < rdc->buf_len)
        break; /* more than SIZE_T _index_ size? Too big for us */
      rdc->buf_len = 2 * rdc->buf_len + 1024;
      if (NULL == (r = realloc (rdc->buf, rdc->buf_len)))
        break; /* out of memory */
      rdc->buf = r;
    }
    res = snprintf (&rdc->buf[rdc->off],
                    rdc->buf_len - rdc->off,
                    "<li><a href=\"/%s\">%s</a></li>\n",
                    fullname,
                    de->d_name);
    if (0 >= res)
      continue;  /* snprintf() error */
    if (rdc->buf_len - rdc->off <= (size_t) res)
      continue;  /* buffer too small?? */
    rdc->off += (size_t) res;
  }
  (void) closedir (dir);
  return true;
}


/**
 * Re-scan our local directory and re-build the index.
 */
static void
update_directory (void)
{
  static size_t initial_allocation = 32 * 1024; /* initial size for response buffer */
  struct MHD_Response *response;
  struct ResponseDataContext rdc;
  unsigned int language_idx;
  unsigned int category_idx;
  const struct Language *language;
  const char *category;
  char dir_name[128];
  struct stat sbuf;
  int res;
  size_t len;

  rdc.buf_len = initial_allocation;
  if (NULL == (rdc.buf = malloc (rdc.buf_len)))
  {
    update_cached_response (NULL);
    return;
  }
  len = strlen (INDEX_PAGE_HEADER);
  if (rdc.buf_len <= len)
  { /* buffer too small */
    free (rdc.buf);
    update_cached_response (NULL);
    return;
  }
  memcpy (rdc.buf,
          INDEX_PAGE_HEADER,
          len);
  rdc.off = len;
  for (language_idx = 0; NULL != languages[language_idx].dirname;
       language_idx++)
  {
    language = &languages[language_idx];

    if (0 != stat (language->dirname, &sbuf))
      continue; /* empty */
    /* we ensured always +1k room, filenames are ~256 bytes,
       so there is always still enough space for the header
       without need for an additional reallocation check. */
    res = snprintf (&rdc.buf[rdc.off], rdc.buf_len - rdc.off,
                    "<h2>%s</h2>\n",
                    language->longname);
    if (0 >= res)
      continue;  /* snprintf() error */
    if (rdc.buf_len - rdc.off <= (size_t) res)
      continue;  /* buffer too small?? */
    rdc.off += (size_t) res;
    for (category_idx = 0; NULL != categories[category_idx]; category_idx++)
    {
      category = categories[category_idx];
      res = snprintf (dir_name, sizeof (dir_name),
                      "%s/%s",
                      language->dirname,
                      category);
      if ((0 >= res) || (sizeof (dir_name) <= (size_t) res))
        continue;  /* cannot print dir name */
      if (0 != stat (dir_name, &sbuf))
        continue;  /* empty */

      /* we ensured always +1k room, filenames are ~256 bytes,
         so there is always still enough space for the header
         without need for an additional reallocation check. */
      res = snprintf (&rdc.buf[rdc.off], rdc.buf_len - rdc.off,
                      "<h3>%s</h3>\n",
                      category);
      if (0 >= res)
        continue;  /* snprintf() error */
      if (rdc.buf_len - rdc.off <= (size_t) res)
        continue;  /* buffer too small?? */
      rdc.off += (size_t) res;

      if (! list_directory (&rdc,
                            dir_name))
      {
        free (rdc.buf);
        update_cached_response (NULL);
        return;
      }
    }
  }
  /* we ensured always +1k room, filenames are ~256 bytes,
     so there is always still enough space for the footer
     without need for a final reallocation check. */
  len = strlen (INDEX_PAGE_FOOTER);
  if (rdc.buf_len - rdc.off <= len)
  { /* buffer too small */
    free (rdc.buf);
    update_cached_response (NULL);
    return;
  }
  memcpy (rdc.buf, INDEX_PAGE_FOOTER, len);
  rdc.off += len;
  initial_allocation = rdc.buf_len; /* remember for next time */
  response =
    MHD_response_from_buffer (MHD_HTTP_STATUS_OK,
                              rdc.off,
                              rdc.buf,
                              &free,
                              rdc.buf);
  mark_as_html (response);
#ifdef FORCE_CLOSE
  (void) MHD_response_add_header (response,
                                  MHD_HTTP_HEADER_CONNECTION,
                                  "close");
#endif
  update_cached_response (response);
}


/**
 * Context we keep for an upload.
 */
struct UploadContext
{
  /**
   * Handle where we write the uploaded file to.
   */
  int fd;

  /**
   * Name of our temporary file where we initially read to.
   */
  char tmpname[PATH_MAX];

  /**
   * Name of the file on disk.
   */
  char *filename;

  /**
   * True once @a tmpfile exists.
   */
  bool have_file;
};


/**
 * "Stream" reader for POST data.
 * This callback is called to incrementally process parsed POST data sent by
 * the client.
 * The pointers to the MHD_String and MHD_StringNullable are valid only until
 * return from this callback.
 * The pointers to the strings and the @a data are valid only until return from
 * this callback.
 *
 * @param req the request
 * @param cls user-specified closure
 * @param name the name of the POST field
 * @param filename the name of the uploaded file, @a cstr member is NULL if not
 *                 known / not provided
 * @param content_type the mime-type of the data, cstr member is NULL if not
 *                     known / not provided
 * @param encoding the encoding of the data, cstr member is NULL if not known /
 *                 not provided
 * @param size the number of bytes in @a data available, may be zero if
 *             the @a final_data is #MHD_YES
 * @param data the pointer to @a size bytes of data at the specified
 *             @a off offset, NOT zero-terminated
 * @param off the offset of @a data in the overall value, always equal to
 *            the sum of sizes of previous calls for the same field / file;
 *            client may provide more than one field with the same name and
 *            the same filename, the new filed (or file) is indicated by zero
 *            value of @a off (and the end is indicated by @a final_data)
 * @param final_data if set to #MHD_YES then full field data is provided,
 *                   if set to #MHD_NO then more field data may be provided
 * @return action specifying how to proceed:
 *         #MHD_upload_action_continue() if all is well,
 *         #MHD_upload_action_suspend() to stop reading the upload until
 *         the request is resumed,
 *         #MHD_upload_action_abort_request() to close the socket,
 *         or a response to discard the rest of the upload and transmit
 *         the response
 * @ingroup action
 */
static const struct MHD_UploadAction *
stream_reader (struct MHD_Request *req,
               void *cls,
               const struct MHD_String *name,
               const struct MHD_StringNullable *filename,
               const struct MHD_StringNullable *content_type,
               const struct MHD_StringNullable *encoding,
               size_t size,
               const void *data,
               uint_fast64_t off,
               enum MHD_Bool final_data)
{
  struct UploadContext *uc = cls;

  (void) content_type;      /* Unused. Silent compiler warning. */
  (void) encoding;          /* Unused. Silent compiler warning. */
  (void) off;               /* Unused. Silent compiler warning. */
  if ( (0 == strcmp (name->cstr,
                     "category")) ||
       (0 == strcmp (name->cstr,
                     "filename")) ||
       (0 == strcmp (name->cstr,
                     "language")) )
  {
    free (uc);
    return MHD_upload_action_from_response (req,
                                            request_refused_response);
  }
  if (0 != strcmp (name->cstr,
                   "upload"))
  {
    fprintf (stderr,
             "Ignoring unexpected form value `%s'\n",
             name->cstr);
    return MHD_upload_action_continue (req);
  }
  if (NULL == filename->cstr)
  {
    fprintf (stderr,
             "No filename, aborting upload.\n");
    free (uc);
    return MHD_upload_action_from_response (req,
                                            request_refused_response);
  }
  if (-1 == uc->fd)
  {
    if ( (NULL != strstr (filename->cstr,
                          "..")) ||
         (NULL != strchr (filename->cstr,
                          '/')) ||
         (NULL != strchr (filename->cstr,
                          '\\')) )
    {
      free (uc);
      return MHD_upload_action_from_response (req,
                                              request_refused_response);
    }
    uc->filename = strdup (filename->cstr);
    if (NULL == uc->filename)
    {
      free (uc);
      return MHD_upload_action_from_response (req,
                                              internal_error_response);
    }
    {
      size_t slen = strlen (uc->filename);
      size_t i;

      for (i = 0; i < slen; i++)
        if (! isprint ((unsigned char) uc->filename[i]))
          uc->filename[i] = '_';
    }
    uc->fd = mkstemp (uc->tmpname);
    if (-1 == uc->fd)
    {
      fprintf (stderr,
               "Error creating temporary file `%s' for upload: %s\n",
               uc->tmpname,
               strerror (errno));
      free (uc->filename);
      free (uc);
      return MHD_upload_action_from_response (req,
                                              request_refused_response);
    }
  }
  if ( (0 != size) &&
#if ! defined(_WIN32) || defined(__CYGWIN__)
       (size !=
        (size_t) write (uc->fd,
                        data,
                        size))
#else  /* Native W32 */
       (size !=
        (size_t) write (uc->fd,
                        data,
                        (unsigned int) size))
#endif /* Native W32 */
       )
  {
    /* write failed; likely: disk full */
    fprintf (stderr,
             "Error writing to file `%s': %s\n",
             uc->tmpname,
             strerror (errno));
    (void) close (uc->fd);
    uc->fd = -1;
    free (uc->filename);
    unlink (uc->tmpname);
    free (uc);
    return MHD_upload_action_from_response (req,
                                            internal_error_response);
  }
  if (final_data)
  {
    (void) close (uc->fd);
    uc->fd = -1;
    uc->have_file = true;
  }
  return MHD_upload_action_continue (req);
}


/**
 * The callback to be called when finished with processing
 * of the postprocessor upload data.
 * @param req the request
 * @param cls the closure
 * @param parsing_result the result of POST data parsing
 * @return the action to proceed
 */
static const struct MHD_UploadAction *
done_cb (struct MHD_Request *req,
         void *cls,
         enum MHD_PostParseResult parsing_result)
{
  struct UploadContext *uc = cls;
  const struct MHD_UploadAction *ret;
  const struct MHD_StringNullable *cat;
  const struct MHD_StringNullable *lang;
  const struct MHD_StringNullable *upload;
  char fn[PATH_MAX];
  int res;

  if (MHD_POST_PARSE_RES_OK != parsing_result)
  {
    free (uc->filename);
    free (uc);
    return MHD_upload_action_from_response (req,
                                            request_refused_response);
  }
  if (-1 != uc->fd)
  {
    (void) close (uc->fd);
    if (NULL != uc->filename)
    {
      fprintf (stderr,
               "Upload of file `%s' failed (incomplete or aborted), removing file.\n",
               uc->filename);
    }
    (void) unlink (uc->tmpname);
    free (uc->filename);
    free (uc);
    return MHD_upload_action_from_response (req,
                                            internal_error_response);
  }
  cat = MHD_request_get_value (req,
                               MHD_VK_POSTDATA,
                               "category");
  lang = MHD_request_get_value (req,
                                MHD_VK_POSTDATA,
                                "language");
  if ( (NULL == lang) ||
       (NULL == lang->cstr) ||
       (NULL == cat) ||
       (NULL == cat->cstr) )
  {
    if (uc->have_file)
      (void) unlink (uc->tmpname);
    free (uc->filename);
    free (uc);
    return MHD_upload_action_from_response (req,
                                            request_refused_response);
  }
  /* FIXME: ugly that we may have to deal with upload
     here as well! */
  upload = MHD_request_get_value (req,
                                  MHD_VK_POSTDATA,
                                  "upload");
  if ( (NULL != upload) &&
       (NULL != upload->cstr) )
  {
    if (uc->have_file)
    {
      free (uc->filename);
      free (uc);
      return MHD_upload_action_from_response (req,
                                              internal_error_response);
    }
    uc->fd = mkstemp (uc->tmpname);
    if (-1 == uc->fd)
    {
      fprintf (stderr,
               "Error creating temporary file `%s' for upload: %s\n",
               uc->tmpname,
               strerror (errno));
      free (uc->filename);
      free (uc);
      return MHD_upload_action_from_response (req,
                                              request_refused_response);
    }
    // FIXME: error handling, ...
    write (uc->fd,
           upload->cstr,
           upload->len);
    close (uc->fd);
    uc->have_file = true;
  }
  /* create directories -- if they don't exist already */
#ifdef WINDOWS
  (void) mkdir (lang->cstr);
#else
  (void) mkdir (lang->cstr,
                S_IRWXU);
#endif
  res = snprintf (fn,
                  sizeof (fn),
                  "%s/%s",
                  lang->cstr,
                  cat->cstr);
  if ( (0 >= res) ||
       (sizeof (fn) <= (size_t) res) )
  {
    free (uc);
    return MHD_upload_action_from_response (req,
                                            request_refused_response);
  }
 #ifdef WINDOWS
  (void) mkdir (fn);
#else
  (void) mkdir (fn,
                S_IRWXU);
#endif
  /* compute filename */
  res = snprintf (fn,
                  sizeof (fn),
                  "%s/%s/%s",
                  lang->cstr,
                  cat->cstr,
                  uc->filename);
  if ( (0 >= res) ||
       (sizeof (fn) <= (size_t) res) )
  {
    free (uc);
    return MHD_upload_action_from_response (req,
                                            request_refused_response);
  }

  if (0 !=
      rename (uc->tmpname,
              uc->filename))
  {
    free (uc->filename);
    free (uc);
    return MHD_upload_action_from_response (req,
                                            request_refused_response);
  }
  chmod (uc->filename,
         S_IRUSR | S_IWUSR);
  free (uc->filename);
  free (uc);

  update_directory ();
  (void) pthread_mutex_lock (&mutex);
  if (NULL == cached_directory_response)
    ret = MHD_upload_action_from_response (req,
                                           internal_error_response);
  else
    ret = MHD_upload_action_from_response (req,
                                           cached_directory_response);
  (void) pthread_mutex_unlock (&mutex);
  return ret;
}


/**
 * Main callback from MHD, used to generate the page.
 *
 * @param cls NULL
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure). */
static const struct MHD_Action *
generate_page (void *cls,
               struct MHD_Request *request,
               const struct MHD_String *path,
               enum MHD_HTTP_Method method,
               uint_fast64_t upload_size)
{
  struct MHD_Response *response;
  const char *url = path->cstr;

  (void ) cls;

  if ((0 != upload_size) &&
      ( (MHD_HTTP_METHOD_GET == method) ||
        (MHD_HTTP_METHOD_HEAD == method) ))
  {
    /* Wrong request, refuse */
    return MHD_action_from_response (request,
                                     request_refused_response);
  }

  if ( ( (MHD_HTTP_METHOD_GET == method) ||
         (MHD_HTTP_METHOD_HEAD == method) ) &&
       (0 != strcmp (url,
                     "/")) )
  {
    /* should be file download */
#ifdef MHD_HAVE_LIBMAGIC
    char file_data[MAGIC_HEADER_SIZE];
    ssize_t got;
#endif /* MHD_HAVE_LIBMAGIC */
    const char *mime;
    int fd = -1;
    struct stat buf;

    fd = -1;
    if ( (NULL == strstr (&url[1],
                          "..")) &&
         ('/' != url[1]) )
    {
      fd = open (&url[1],
                 O_RDONLY);
      if ( (-1 != fd) &&
           ( (0 != fstat (fd,
                          &buf)) ||
             (! S_ISREG (buf.st_mode)) ) )
      {
        (void) close (fd);
        fd = -1;
      }
    }
    if (-1 == fd)
      return MHD_action_from_response (request,
                                       file_not_found_response);
#ifdef MHD_HAVE_LIBMAGIC
    /* read beginning of the file to determine mime type  */
    got = read (fd,
                file_data,
                sizeof (file_data));
    (void) lseek (fd,
                  0,
                  SEEK_SET);
    if (0 < got)
      mime = magic_buffer (magic,
                           file_data,
                           (size_t) got);
    else
#endif /* MHD_HAVE_LIBMAGIC */
    mime = NULL;
    {
      /* Set mime-type by file-extension in some cases */
      const char *ldot = strrchr (&url[1],
                                  '.');

      if (NULL != ldot)
      {
        if (0 == strcasecmp (ldot,
                             ".html"))
          mime = "text/html";
        if (0 == strcasecmp (ldot,
                             ".css"))
          mime = "text/css";
        if (0 == strcasecmp (ldot,
                             ".css3"))
          mime = "text/css";
        if (0 == strcasecmp (ldot,
                             ".js"))
          mime = "application/javascript";
      }
    }

    response = MHD_response_from_fd (MHD_HTTP_STATUS_OK,
                                     fd,
                                     0LLU /* offset */,
                                     (uint_fast64_t) buf.st_size);
    if (NULL == response)
    {
      /* internal error (i.e. out of memory) */
      (void) close (fd);
      return MHD_action_abort_request (request);
    }

    /* add mime type if we had one */
    if (NULL != mime)
      (void) MHD_response_add_header (response,
                                      MHD_HTTP_HEADER_CONTENT_TYPE,
                                      mime);
    return MHD_action_from_response (request,
                                     response);
  }

  if ( (MHD_HTTP_METHOD_POST == method) &&
       (0 == strcmp (path->cstr,
                     "/")) )
  {
    struct UploadContext *uc;

    uc = malloc (sizeof (struct UploadContext));
    if (NULL == uc)
      return MHD_action_abort_request (request); /* out of memory, close connection */
    memset (uc,
            0,
            sizeof (struct UploadContext));
    strcpy (uc->tmpname,
            "/tmp/mhd-demo-XXXXXX");
    uc->fd = -1;
    return MHD_action_parse_post (request,
                                  64 * 1024 /* buffer size */,
                                  1024 /* max non-stream size */,
                                  MHD_HTTP_POST_ENCODING_OTHER,
                                  &stream_reader,
                                  uc,
                                  &done_cb,
                                  uc);
  }
  if (  ( (MHD_HTTP_METHOD_GET == method) ||
          (MHD_HTTP_METHOD_HEAD == method) ) &&
        (0 == strcmp (url,
                      "/")) )
  {
    const struct MHD_Action *ret;

    (void) pthread_mutex_lock (&mutex);
    if (NULL == cached_directory_response)
      ret = MHD_action_from_response (request,
                                      internal_error_response);
    else
      ret = MHD_action_from_response (request,
                                      cached_directory_response);
    (void) pthread_mutex_unlock (&mutex);
    return ret;
  }
  /* unexpected request, refuse */
  return MHD_action_from_response (request,
                                   request_refused_response);
}


#ifndef MINGW
/**
 * Function called if we get a SIGPIPE. Does nothing.
 *
 * @param sig will be SIGPIPE (ignored)
 */
static void
catcher (int sig)
{
  (void) sig;  /* Unused. Silent compiler warning. */
  /* do nothing */
}


/**
 * setup handlers to ignore SIGPIPE.
 */
static void
ignore_sigpipe (void)
{
  struct sigaction oldsig;
  struct sigaction sig;

  sig.sa_handler = &catcher;
  sigemptyset (&sig.sa_mask);
#ifdef SA_INTERRUPT
  sig.sa_flags = SA_INTERRUPT;  /* SunOS */
#else
  sig.sa_flags = SA_RESTART;
#endif
  if (0 != sigaction (SIGPIPE,
                      &sig,
                      &oldsig))
    fprintf (stderr,
             "Failed to install SIGPIPE handler: %s\n", strerror (errno));
}


#endif


/**
 * Entry point to demo.  Note: this HTTP server will make all
 * files in the current directory and its subdirectories available
 * to anyone.  Press ENTER to stop the server once it has started.
 *
 * @param argc number of arguments in argv
 * @param argv first and only argument should be the port number
 * @return 0 on success
 */
int
main (int argc,
      char *const *argv)
{
  struct MHD_Daemon *d;
  unsigned int port;

  if ( (argc != 2) ||
       (1 != sscanf (argv[1], "%u", &port)) ||
       (UINT16_MAX < port) )
  {
    fprintf (stderr,
             "%s PORT\n", argv[0]);
    return 1;
  }
#ifndef MINGW
  ignore_sigpipe ();
#endif
#ifdef MHD_HAVE_LIBMAGIC
  magic = magic_open (MAGIC_MIME_TYPE);
  (void) magic_load (magic, NULL);
#endif /* MHD_HAVE_LIBMAGIC */

  (void) pthread_mutex_init (&mutex, NULL);
  file_not_found_response =
    MHD_response_from_buffer_static (
      MHD_HTTP_STATUS_NOT_FOUND,
      strlen (FILE_NOT_FOUND_PAGE),
      (const void *) FILE_NOT_FOUND_PAGE);
  mark_as_html (file_not_found_response);
  if (MHD_SC_OK !=
      MHD_response_set_option (file_not_found_response,
                               &MHD_R_OPTION_REUSABLE (
                                 MHD_YES)))
    return 1;
  request_refused_response =
    MHD_response_from_buffer_static (
      MHD_HTTP_STATUS_FORBIDDEN,
      strlen (REQUEST_REFUSED_PAGE),
      (const void *) REQUEST_REFUSED_PAGE);
  mark_as_html (request_refused_response);
  if (MHD_SC_OK !=
      MHD_response_set_option (request_refused_response,
                               &MHD_R_OPTION_REUSABLE (
                                 MHD_YES)))
    return 1;
  internal_error_response =
    MHD_response_from_buffer_static (
      MHD_HTTP_STATUS_INTERNAL_SERVER_ERROR,
      strlen (INTERNAL_ERROR_PAGE),
      (const void *) INTERNAL_ERROR_PAGE);
  mark_as_html (internal_error_response);
  if (MHD_SC_OK !=
      MHD_response_set_option (internal_error_response,
                               &MHD_R_OPTION_REUSABLE (
                                 MHD_YES)))
    return 1;
  update_directory ();
  d = MHD_daemon_create (&generate_page,
                         NULL);
  if (NULL == d)
    return 1;
  if (MHD_SC_OK !=
      MHD_DAEMON_SET_OPTIONS (
        d,
        MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_AUTO),
        MHD_D_OPTION_WM_WORKER_THREADS (NUMBER_OF_THREADS),
#ifdef PRODUCTION
        MHD_D_OPTION_PER_IP_LIMIT (64),
#endif
        MHD_D_OPTION_DEFAULT_TIMEOUT (120 /* seconds */),
        MHD_D_OPTION_CONN_MEMORY_LIMIT (256 * 1024),
        MHD_D_OPTION_BIND_PORT (MHD_AF_AUTO,
                                (uint_least16_t) port)))
    return 1;
  if (MHD_SC_OK !=
      MHD_daemon_start (d))
  {
    MHD_daemon_destroy (d);
    return 1;
  }
  fprintf (stderr, "HTTP server running. Press ENTER to stop the server.\n");
  (void) getc (stdin);
  MHD_daemon_destroy (d);
  MHD_response_destroy (file_not_found_response);
  MHD_response_destroy (request_refused_response);
  MHD_response_destroy (internal_error_response);
  update_cached_response (NULL);
  (void) pthread_mutex_destroy (&mutex);
#ifdef MHD_HAVE_LIBMAGIC
  magic_close (magic);
#endif /* MHD_HAVE_LIBMAGIC */
  return 0;
}


/* end of demo.c */
