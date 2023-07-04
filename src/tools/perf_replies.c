/*
    This file is part of GNU libmicrohttpd
    Copyright (C) 2023 Evgeny Grin (Karlson2k)

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE GNU LIBMICROHTTPD "AS IS" AND ANY EXPRESS
    OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
    NO EVENT SHALL THE LIBMICROHTTPD OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
    INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
    THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * @file examples/perf_replies.c
 * @brief  Implementation of HTTP server optimised for fast replies
 *         based on MHD.
 * @author Karlson2k (Evgeny Grin)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "mhd_options.h"
#include "microhttpd.h"

#if defined(MHD_REAL_CPU_COUNT)
#if MHD_REAL_CPU_COUNT == 0
#undef MHD_REAL_CPU_COUNT
#endif /* MHD_REAL_CPU_COUNT == 0 */
#endif /* MHD_REAL_CPU_COUNT */

#define PERF_RPL_ERR_CODE_BAD_PARAM 65

#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro) / sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */

/* Static constants */
static const char *const tool_copyright =
  "Copyright (C) 2023 Evgeny Grin (Karlson2k)";

/* Package or build specific string, like
   "Debian 1.2.3-4" or "RevX, built by MSYS2" */
static const char *const build_revision = ""
#ifdef MHD_BUILD_REV_STR
                                          MHD_BUILD_REV_STR
#endif /* MHD_BUILD_REV_STR */
;

#define PERF_REPL_PORT_FALLBACK 48080

/* Dynamic variables */
static char self_name[500] = "perf_replies";
static uint16_t mhd_port = 0;
static struct MHD_Response **resps = NULL;
static unsigned int num_resps = 0;
static char *body_dyn = NULL; /* Non-static body data */

static void
set_self_name (int argc, char *const *argv)
{
  if ((argc >= 1) && (NULL != argv[0]))
  {
    const char *last_dir_sep;
    last_dir_sep = strrchr (argv[0], '/');
#ifdef _WIN32
    if (1)
    {
      const char *last_w32_dir_sep;
      last_w32_dir_sep = strrchr (argv[0], '\\');
      if ((NULL == last_dir_sep) ||
          ((NULL != last_w32_dir_sep) && (last_w32_dir_sep > last_dir_sep)))
        last_dir_sep = last_w32_dir_sep;
    }
#endif /* _WIN32 */
    if (NULL != last_dir_sep)
    {
      size_t name_len;
      name_len = strlen (last_dir_sep + 1);
      if ((0 != name_len) && ((sizeof(self_name) / sizeof(char)) > name_len))
      {
        strcpy (self_name, last_dir_sep + 1);
        return;
      }
    }
  }
  /* Set default name */
  strcpy (self_name, "perf_replies");
  return;
}


/**
 * Convert decimal string to unsigned int.
 * Function stops at the end of the string or on first non-digit character.
 * @param str the string to convert
 * @param[out] value the pointer to put the result
 * @return return the number of digits converted or
 *         zero if no digits found or result would overflow the output
 *         variable (the output set to UINT_MAX in this case).
 */
static size_t
str_to_uint (const char *str, unsigned int *value)
{
  size_t i;
  unsigned int v = 0;
  *value = 0;

  for (i = 0; 0 != str[i]; ++i)
  {
    const char chr = str[i];
    unsigned int digit;
    if (('0' > chr) || ('9' < chr))
      break;
    digit = (unsigned char) (chr - '0');
    if ((((0U - 1) / 10) < v) || ((v * 10 + digit) < v))
    {
      /* Overflow */
      *value = 0U - 1;
      return 0;
    }
    v *= 10;
    v += digit;
  }
  *value = v;
  return i;
}


#if defined (HAVE_POPEN) && defined(HAVE_PCLOSE)
/**
 * Read the command output as a number and return the number.
 * Only positive decimal numbers are supported
 * @param cmd the command to run
 * @return zero or positive number read if success,
 *         negative number if any error occurs
 */
static int
get_cmd_out_as_number (const char *cmd)
{
  FILE *cmd_out;
  char buf[255];
  int ret;
  size_t len;

  cmd_out = popen (cmd, "r"
#ifdef _WIN32
                   "t"
#endif /* _WIN32 */
                   );
  if (NULL == cmd_out)
    return -1;
  ret = -1;
  if (buf != fgets (buf, sizeof(buf), cmd_out))
    len = 0;
  else
    len = strlen (buf);
  if ((0 != len) && (sizeof(buf) > (len + 2)) && ! ferror (cmd_out))
  {
    size_t digits_found;
    unsigned int out_value;
    digits_found = str_to_uint (buf, &out_value);
    if (0 != digits_found)
    {
      if ((0 == buf[digits_found])
#ifdef _WIN32
          || ('\r' == buf[digits_found])
#endif /* _WIN32 */
          || ('\n' == buf[digits_found]))
      {
        ret = (int) out_value; /* Possible negative cast result is interpreted as an error */
      }
    }
  }
  if (0 != pclose (cmd_out))
    ret = -1;
  return ret;
}


#else  /* ! HAVE_POPEN || ! HAVE_PCLOSE */
#define read_cmd_out_as_number(ignore) (-1)
#endif /* ! HAVE_POPEN || ! HAVE_PCLOSE */

static unsigned int
detect_cpu_core_count (void)
{
  int sys_cpu_count = -1;
#if ! defined(_WIN32) || defined(__CYGWIN__)
  sys_cpu_count = get_cmd_out_as_number ("nproc 2>/dev/null");
#endif /* ! _WIN32) || __CYGWIN__ */
#ifdef _WIN32
  if (0 >= sys_cpu_count)
    sys_cpu_count = get_cmd_out_as_number ("echo %NUMBER_OF_PROCESSORS%");
#endif /* _WIN32 */
  if (0 >= sys_cpu_count)
  {
    fprintf (stderr, "Failed to detect the number of available CPU cores.\n");
#ifdef MHD_REAL_CPU_COUNT
    fprintf (stderr, "Hardcoded number is used as a fallback.\n");
    sys_cpu_count = MHD_REAL_CPU_COUNT;
#endif
    if (0 >= sys_cpu_count)
      sys_cpu_count = 1;
    printf ("Assuming %d CPU cores.\n", sys_cpu_count);
  }
  else
  {
    printf ("Detected %d CPU cores.\n", sys_cpu_count);
  }
  return (unsigned int) sys_cpu_count;
}


static unsigned int
get_cpu_core_count (void)
{
  static unsigned int num_cpu_cores = 0;
  if (0 == num_cpu_cores)
    num_cpu_cores = detect_cpu_core_count ();
  return num_cpu_cores;
}


static unsigned int num_threads = 0;

static unsigned int
get_num_threads (void)
{
  static const unsigned int max_threads = 32;
  if (0 == num_threads)
  {
    num_threads = get_cpu_core_count () / 2;
    if (0 == num_threads)
      num_threads = 1;
    else
      printf ("Using half of all available CPU cores, assuming the other half "
              "is used by client / requests generator.\n");
  }
  if (max_threads < num_threads)
  {
    printf ("Number of threads are limited to %u as more threads "
            "are unlikely to improve the performance.\n", max_threads);
    num_threads = max_threads;
  }

  return num_threads;
}


/**
 * The result of short parameters processing
 */
enum PerfRepl_param_result
{
  PERF_RPL_PARAM_ERROR,        /**< Error processing parameter */
  PERF_RPL_PARAM_ONE_CHAR,     /**< Processed exactly one character */
  PERF_RPL_PARAM_FULL_STR,     /**< Processed current parameter completely */
  PERF_RPL_PARAM_STR_PLUS_NEXT /**< Current parameter completely and next parameter processed */
};

/**
 * Extract parameter value
 * @param param_name the name of the parameter
 * @param param_tail the pointer to the character after parameter name in
 *                   the parameter string
 * @param next_param the pointer to the next parameter (if any) or NULL
 * @param[out] param_value the pointer where to store resulting value
 * @return enum value, the PERF_PERPL_SPARAM_ONE_CHAR is not used by
 *                     this function
 */
static enum PerfRepl_param_result
get_param_value (const char *param_name, const char *param_tail,
                 const char *next_param, unsigned int *param_value)
{
  const char *value_str;
  size_t digits;
  if (0 != param_tail[0])
  {
    if ('=' != param_tail[0])
      value_str = param_tail;
    else
      value_str = param_tail + 1;
  }
  else
    value_str = next_param;

  if (NULL != value_str)
    digits = str_to_uint (value_str, param_value);
  else
    digits = 0;

  if ((0 == digits) || (0 != value_str[digits]))
  {
    fprintf (stderr, "Parameter '%s' is not followed by valid number.\n",
             param_name);
    return PERF_RPL_PARAM_ERROR;
  }

  if (0 != param_tail[0])
    return PERF_RPL_PARAM_FULL_STR;

  return PERF_RPL_PARAM_STR_PLUS_NEXT;
}


static void
show_help (void)
{
  printf ("Usage: %s [OPTIONS] [PORT_NUMBER]\n", self_name);
  printf ("Start MHD-based web-server optimised for fast replies.\n");
  printf ("\n");
  printf ("Threads options (mutually exclusive):\n");
  printf ("  -A,     --all-cpus        use all available CPU cores (for \n"
          "                            testing with remote client)\n");
  printf ("  -t NUM, --threads=NUM     use NUM threads\n");
  printf ("\n");
  printf ("Force polling function (mutually exclusive):\n");
  if (MHD_NO != MHD_is_feature_supported (MHD_FEATURE_EPOLL))
    printf ("          --epoll           use 'epoll' functionality\n");
  if (MHD_NO != MHD_is_feature_supported (MHD_FEATURE_POLL))
    printf ("          --poll            use poll() function\n");
  printf ("          --select          use select() function\n");
  printf ("\n");
  printf ("Response size options (mutually exclusive):\n");
  printf ("  -E,     --empty           empty response, 0 bytes\n");
  printf ("  -T,     --tiny            tiny response, 3 bytes (default)\n");
  printf ("  -M,     --medium          medium response, 8 KB\n");
  printf ("  -L,     --large           large response, 1 MB\n");
  printf ("\n");
  printf ("Other options:\n");
  printf ("  -c NUM, --connections=NUM reject more than NUM client \n"
          "                            connections\n");
  printf ("  -O NUM, --timeout=NUM     set connection timeout to NUM seconds,\n"
          "                            zero means no timeout\n");
  printf ("          --date-header     use the 'Date:' header in every\n"
          "                            reply\n");
  printf ("          --help            display this help and exit\n");
  printf ("  -V,     --version         output version information and exit\n");
  printf ("\n");
  printf ("This tool is part of GNU libmicrohttpd suite.\n");
  printf ("%s\n", tool_copyright);
}


struct PerfRepl_parameters
{
  unsigned int port;
  int all_cpus;
  unsigned int threads;
  int epoll;
  int poll;
  int select;
  int empty;
  int tiny;
  int medium;
  int large;
  unsigned int connections;
  unsigned int timeout;
  int date_header;
  int help;
  int version;
};

static struct PerfRepl_parameters tool_params = {
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0
};

/**
 * Process parameter '-t' or '--threads'
 * @param param_name the name of the parameter as specified in command line
 * @param param_tail the pointer to the character after parameter name in
 *                   the parameter string
 * @param next_param the pointer to the next parameter (if any) or NULL
 * @return enum value, the PERF_PERPL_SPARAM_ONE_CHAR is not used by
 *                     this function
 */
static enum PerfRepl_param_result
process_param__threads (const char *param_name, const char *param_tail,
                        const char *next_param)
{
  unsigned int param_value;
  enum PerfRepl_param_result value_res;

  if (tool_params.all_cpus)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-A' or '--all-cpus'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  value_res = get_param_value (param_name, param_tail, next_param,
                               &param_value);
  if (PERF_RPL_PARAM_ERROR == value_res)
    return value_res;

  if (0 == param_value)
  {
    fprintf (stderr, "'0' is not valid value for parameter '%s'.\n",
             param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.threads = param_value;
  return value_res;
}


static enum PerfRepl_param_result
process_param__all_cpus (const char *param_name)
{
  if (0 != tool_params.threads)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-t' or '--threads'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.all_cpus = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


static enum PerfRepl_param_result
process_param__epoll (const char *param_name)
{
  if (tool_params.poll)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '--poll'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.select)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '--select'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.epoll = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


static enum PerfRepl_param_result
process_param__poll (const char *param_name)
{
  if (tool_params.epoll)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '--epoll'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.select)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '--select'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.poll = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


static enum PerfRepl_param_result
process_param__select (const char *param_name)
{
  if (tool_params.epoll)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '--epoll'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.poll)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '--poll'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.select = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


static enum PerfRepl_param_result
process_param__empty (const char *param_name)
{
  if (tool_params.tiny)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-T' or '--tiny'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.medium)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-M' or '--medium'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.large)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-L' or '--large'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.empty = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


static enum PerfRepl_param_result
process_param__tiny (const char *param_name)
{
  if (tool_params.empty)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-E' or '--empty'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.medium)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-M' or '--medium'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.large)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-L' or '--large'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.tiny = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


static enum PerfRepl_param_result
process_param__medium (const char *param_name)
{
  if (tool_params.empty)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-E' or '--empty'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.tiny)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-T' or '--tiny'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.large)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-L' or '--large'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.medium = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


static enum PerfRepl_param_result
process_param__large (const char *param_name)
{
  if (tool_params.empty)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-E' or '--empty'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.tiny)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-T' or '--tiny'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  if (tool_params.medium)
  {
    fprintf (stderr, "Parameter '%s' cannot be used together "
             "with '-M' or '--medium'.\n", param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.large = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


/**
 * Process parameter '-c' or '--connections'
 * @param param_name the name of the parameter as specified in command line
 * @param param_tail the pointer to the character after parameter name in
 *                   the parameter string
 * @param next_param the pointer to the next parameter (if any) or NULL
 * @return enum value, the PERF_PERPL_SPARAM_ONE_CHAR is not used by
 *                     this function
 */
static enum PerfRepl_param_result
process_param__connections (const char *param_name, const char *param_tail,
                            const char *next_param)
{
  unsigned int param_value;
  enum PerfRepl_param_result value_res;

  value_res = get_param_value (param_name, param_tail, next_param,
                               &param_value);
  if (PERF_RPL_PARAM_ERROR == value_res)
    return value_res;

  if (0 == param_value)
  {
    fprintf (stderr, "'0' is not valid value for parameter '%s'.\n",
             param_name);
    return PERF_RPL_PARAM_ERROR;
  }
  tool_params.connections = param_value;
  return value_res;
}


/**
 * Process parameter '-O' or '--timeout'
 * @param param_name the name of the parameter as specified in command line
 * @param param_tail the pointer to the character after parameter name in
 *                   the parameter string
 * @param next_param the pointer to the next parameter (if any) or NULL
 * @return enum value, the PERF_PERPL_SPARAM_ONE_CHAR is not used by
 *                     this function
 */
static enum PerfRepl_param_result
process_param__timeout (const char *param_name, const char *param_tail,
                        const char *next_param)
{
  unsigned int param_value;
  enum PerfRepl_param_result value_res;

  value_res = get_param_value (param_name, param_tail, next_param,
                               &param_value);
  if (PERF_RPL_PARAM_ERROR == value_res)
    return value_res;

  tool_params.timeout = param_value;
  return value_res;
}


static enum PerfRepl_param_result
process_param__date_header (const char *param_name)
{
  tool_params.date_header = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


static enum PerfRepl_param_result
process_param__help (const char *param_name)
{
  /* Use only one of help | version */
  if (! tool_params.version)
    tool_params.help = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


static enum PerfRepl_param_result
process_param__version (const char *param_name)
{
  /* Use only one of help | version */
  if (! tool_params.help)
    tool_params.version = ! 0;
  return '-' == param_name[1] ?
         PERF_RPL_PARAM_FULL_STR :PERF_RPL_PARAM_ONE_CHAR;
}


/**
 * Process "short" (one character) parameter.
 * @param param the pointer to character after "-" or after another valid
 *              parameter
 * @param next_param the pointer to the next parameter (if any) or
 *                   NULL if no next parameter
 * @return enum value with result
 */
static enum PerfRepl_param_result
process_short_param (const char *param, const char *next_param)
{
  const char param_chr = param[0];
  if ('A' == param_chr)
    return process_param__all_cpus ("-A");
  else if ('t' == param_chr)
    return process_param__threads ("-t", param + 1, next_param);
  else if ('E' == param_chr)
    return process_param__empty ("-E");
  else if ('T' == param_chr)
    return process_param__tiny ("-T");
  else if ('M' == param_chr)
    return process_param__medium ("-M");
  else if ('L' == param_chr)
    return process_param__large ("-L");
  else if ('c' == param_chr)
    return process_param__connections ("-c", param + 1, next_param);
  else if ('O' == param_chr)
    return process_param__timeout ("-O", param + 1, next_param);
  else if ('V' == param_chr)
    return process_param__version ("-V");

  fprintf (stderr, "Unrecognised parameter: -%c.\n", param_chr);
  return PERF_RPL_PARAM_ERROR;
}


/**
 * Process string of "short" (one character) parameters.
 * @param params_str the pointer to first character after "-"
 * @param next_param the pointer to the next parameter (if any) or
 *                   NULL if no next parameter
 * @return enum value with result
 */
static enum PerfRepl_param_result
process_short_params_str (const char *params_str, const char *next_param)
{
  if (0 == params_str[0])
  {
    fprintf (stderr, "Unrecognised parameter: -\n");
    return PERF_RPL_PARAM_ERROR;
  }
  do
  {
    enum PerfRepl_param_result param_res;
    param_res = process_short_param (params_str, next_param);
    if (PERF_RPL_PARAM_ONE_CHAR != param_res)
      return param_res;
  } while (0 != (++params_str)[0]);
  return PERF_RPL_PARAM_FULL_STR;
}


/**
 * Process "long" (--something) parameters.
 * @param param the pointer to first character after "--"
 * @param next_param the pointer to the next parameter (if any) or
 *                   NULL if no next parameter
 * @return enum value, the PERF_PERPL_SPARAM_ONE_CHAR is not used by
 *                     this function
 */
static enum PerfRepl_param_result
process_long_param (const char *param, const char *next_param)
{
  const size_t param_len = strlen (param);

  if ((MHD_STATICSTR_LEN_ ("all-cpus") == param_len) &&
      (0 == memcmp (param, "all-cpus", MHD_STATICSTR_LEN_ ("all-cpus"))))
    return process_param__all_cpus ("--all-cpus");
  else if ((MHD_STATICSTR_LEN_ ("threads") <= param_len) &&
           (0 == memcmp (param, "threads", MHD_STATICSTR_LEN_ ("threads"))))
    return process_param__threads ("--threads",
                                   param + MHD_STATICSTR_LEN_ ("threads"),
                                   next_param);
  else if ((MHD_STATICSTR_LEN_ ("epoll") == param_len) &&
           (0 == memcmp (param, "epoll", MHD_STATICSTR_LEN_ ("epoll"))))
    return process_param__epoll ("--epoll");
  else if ((MHD_STATICSTR_LEN_ ("poll") == param_len) &&
           (0 == memcmp (param, "poll", MHD_STATICSTR_LEN_ ("poll"))))
    return process_param__poll ("--poll");
  else if ((MHD_STATICSTR_LEN_ ("select") == param_len) &&
           (0 == memcmp (param, "select", MHD_STATICSTR_LEN_ ("select"))))
    return process_param__select ("--select");
  else if ((MHD_STATICSTR_LEN_ ("empty") == param_len) &&
           (0 == memcmp (param, "empty", MHD_STATICSTR_LEN_ ("empty"))))
    return process_param__empty ("--empty");
  else if ((MHD_STATICSTR_LEN_ ("tiny") == param_len) &&
           (0 == memcmp (param, "tiny", MHD_STATICSTR_LEN_ ("tiny"))))
    return process_param__tiny ("--tiny");
  else if ((MHD_STATICSTR_LEN_ ("medium") == param_len) &&
           (0 == memcmp (param, "medium", MHD_STATICSTR_LEN_ ("medium"))))
    return process_param__medium ("--medium");
  else if ((MHD_STATICSTR_LEN_ ("large") == param_len) &&
           (0 == memcmp (param, "large", MHD_STATICSTR_LEN_ ("large"))))
    return process_param__large ("--large");
  else if ((MHD_STATICSTR_LEN_ ("connections") <= param_len) &&
           (0 == memcmp (param, "connections",
                         MHD_STATICSTR_LEN_ ("connections"))))
    return process_param__connections ("--connections",
                                       param
                                       + MHD_STATICSTR_LEN_ ("connections"),
                                       next_param);
  else if ((MHD_STATICSTR_LEN_ ("timeout") <= param_len) &&
           (0 == memcmp (param, "timeout",
                         MHD_STATICSTR_LEN_ ("timeout"))))
    return process_param__timeout ("--timeout",
                                   param + MHD_STATICSTR_LEN_ ("timeout"),
                                   next_param);
  else if ((MHD_STATICSTR_LEN_ ("date-header") == param_len) &&
           (0 == memcmp (param, "date-header",
                         MHD_STATICSTR_LEN_ ("date-header"))))
    return process_param__date_header ("--date-header");
  else if ((MHD_STATICSTR_LEN_ ("help") == param_len) &&
           (0 == memcmp (param, "help", MHD_STATICSTR_LEN_ ("help"))))
    return process_param__help ("--help");
  else if ((MHD_STATICSTR_LEN_ ("version") == param_len) &&
           (0 == memcmp (param, "version", MHD_STATICSTR_LEN_ ("version"))))
    return process_param__version ("--version");

  fprintf (stderr, "Unrecognised parameter: --%s.\n", param);
  return PERF_RPL_PARAM_ERROR;
}


static int
process_params (int argc, char *const *argv)
{
  int proc_dash_param = ! 0;
  int i;
  for (i = 1; i < argc; ++i)
  {
    /**
     * The currently processed argument
     */
    const char *const p = argv[i];
    const char *const p_next = (argc == (i + 1)) ? NULL : (argv[i + 1]);
    if (NULL == p)
    {
      fprintf (stderr, "The NULL in the parameter number %d. "
               "The error in the C library?\n", i);
      continue;
    }
    else if (0 == p[0])
      continue; /* Empty */
    else if (proc_dash_param && ('-' == p[0]))
    {
      enum PerfRepl_param_result param_res;
      if ('-' == p[1])
      {
        if (0 == p[2])
        {
          proc_dash_param = 0; /* The '--' parameter */
          continue;
        }
        param_res = process_long_param (p + 2, p_next);
      }
      else
        param_res = process_short_params_str (p + 1, p_next);

      if (PERF_RPL_PARAM_ERROR == param_res)
        return PERF_RPL_ERR_CODE_BAD_PARAM;
      if (PERF_RPL_PARAM_STR_PLUS_NEXT == param_res)
        ++i;
      else if (PERF_RPL_PARAM_ONE_CHAR == param_res)
        abort ();
      continue;
    }
    else if (('0' <= p[0]) && ('9' >= p[0]))
    {
      /* Process the port number */
      unsigned int read_port;
      size_t num_digits;
      num_digits = str_to_uint (p, &read_port);
      if (0 != p[num_digits])
      {
        fprintf (stderr, "Error in specified port number: %s\n", p);
        return PERF_RPL_ERR_CODE_BAD_PARAM;
      }
      else if (65535 < read_port)
      {
        fprintf (stderr, "Wrong port number: %s\n", p);
        return PERF_RPL_ERR_CODE_BAD_PARAM;
      }
      mhd_port = (uint16_t) read_port;
    }
    else
    {
      fprintf (stderr, "Unrecognised parameter: %s\n\n", p);
      return PERF_RPL_ERR_CODE_BAD_PARAM;
    }
  }
  return 0;
}


static void
print_version (void)
{
  printf ("%s (GNU libmicrohttpd", self_name);
  if (0 != build_revision[0])
    printf ("; %s", build_revision);
  printf (") %s\n", MHD_get_version ());
  printf ("%s\n", tool_copyright);
}


static void
print_all_cores_used (void)
{
  printf ("No CPU cores on this machine are left unused and available "
          "for the client / requests generator. "
          "Testing with remote client is recommended.\n");
}


/**
 * Apply parameter '-A' or '--all-cpus'
 */
static void
check_apply_param__all_cpus (void)
{
  if (! tool_params.all_cpus)
    return;

  num_threads = get_cpu_core_count ();
  printf ("Requested use of all available CPU cores for MHD threads.\n");
  print_all_cores_used ();
}


/**
 * Apply parameter '-t' or '--threads'
 */
static void
check_apply_param__threads (void)
{
  if (0 == tool_params.threads)
    return;

  num_threads = tool_params.threads;
  if (get_cpu_core_count () == num_threads)
  {
    printf ("The requested number of threads is equal to the number of "
            "detected CPU cores.\n");
    print_all_cores_used ();
  }
  else if (get_cpu_core_count () < num_threads)
  {
    fprintf (stderr, "WARNING: The requested number of threads (%u) is "
             "higher than the number of detected CPU cores (%u).\n",
             num_threads, get_cpu_core_count ());
    fprintf (stderr, "This decreases the performance. "
             "Consider using fewer threads.\n");
  }
}


static void
check_param_port (void)
{
  if (0 != tool_params.port)
    return;
  if (MHD_NO == MHD_is_feature_supported (MHD_FEATURE_AUTODETECT_BIND_PORT))
    tool_params.port = PERF_REPL_PORT_FALLBACK;
}


/* non-zero - OK, zero - error */
static int
check_param__epoll (void)
{
  if (! tool_params.epoll)
    return ! 0;
  if (MHD_NO == MHD_is_feature_supported (MHD_FEATURE_EPOLL))
  {
    fprintf (stderr, "'epoll' was requested, but this MHD build does not "
             "support 'epoll' functionality.\n");
    return 0;
  }
  return ! 0;
}


/* non-zero - OK, zero - error */
static int
check_param__poll (void)
{
  if (! tool_params.poll)
    return ! 0;
  if (MHD_NO == MHD_is_feature_supported (MHD_FEATURE_POLL))
  {
    fprintf (stderr, "poll() was requested, but this MHD build does not "
             "support polling by poll().\n");
    return 0;
  }
  return ! 0;
}


static void
check_param__empty_tiny_medium_large (void)
{
  if (0 == (tool_params.empty | tool_params.tiny | tool_params.medium
            | tool_params.large))
    tool_params.tiny = ! 0;
}


/* Must be called after 'check_apply_param__threads()' and
   'check_apply_param__all_cpus()' */
/* non-zero - OK, zero - error */
static int
check_param__connections (void)
{
  if (0 == tool_params.connections)
    return ! 0;
  if (get_num_threads () > tool_params.connections)
  {
    fprintf (stderr, "The connections number limit (%u) is less than number "
             "of threads used (%u). Use higher value for connections limit.\n",
             tool_params.connections, get_num_threads ());
    return 0;
  }
  return ! 0;
}


/**
 * Apply decoded parameters
 * @return 0 if success,
 *         positive error code if case of error,
 *         -1 to exit program with success (0) error code.
 */
static int
check_apply_params (void)
{
  if (tool_params.help)
  {
    show_help ();
    return -1;
  }
  else if (tool_params.version)
  {
    print_version ();
    return -1;
  }
  check_param_port ();
  check_apply_param__all_cpus ();
  check_apply_param__threads ();
  if (! check_param__epoll ())
    return PERF_RPL_ERR_CODE_BAD_PARAM;
  if (! check_param__poll ())
    return PERF_RPL_ERR_CODE_BAD_PARAM;
  check_param__empty_tiny_medium_large ();
  if (! check_param__connections ())
    return PERF_RPL_ERR_CODE_BAD_PARAM;
  return 0;
}


static int
init_data (void)
{
  /* Use the same memory area to avoid multiple copies.
     The system will keep it in cache. */
  static const char tiny_body[] = "Hi!";
  unsigned int i;
  size_t body_dyn_size;

  if (tool_params.medium)
    body_dyn_size = 8U * 1024U;
  else if (tool_params.large)
    body_dyn_size = 1024U * 1024U;
  else
    body_dyn_size = 0;

  if (0 != body_dyn_size)
  {
    body_dyn = (char *) malloc (body_dyn_size);
    if (NULL == body_dyn)
    {
      fprintf (stderr, "Failed to allocate memory.\n");
      return 25;
    }
    if (tool_params.medium)
    {
      /* Fill the body with HTML-like content */
      size_t pos;
      size_t filler_pos;
      static const char body_header[] =
        "<html>\n"
        "<head>\n<title>Sample page title</title>\n<head>\n"
        "<body>\n";
      static const char body_filler[] =
        "The quick brown fox jumps over the lazy dog.<br>\n";
      static const char body_footer[] =
        "</body>\n"
        "</html>\n";
      pos = 0;
      memcpy (body_dyn + pos, body_header, MHD_STATICSTR_LEN_ (body_header));
      pos += MHD_STATICSTR_LEN_ (body_header);
      for (filler_pos = 0;
           filler_pos < (body_dyn_size - (MHD_STATICSTR_LEN_ (body_header)
                                          + MHD_STATICSTR_LEN_ (body_footer)));
           ++filler_pos)
      {
        body_dyn[pos + filler_pos] =
          body_filler[filler_pos % MHD_STATICSTR_LEN_ (body_filler)];
      }
      pos += filler_pos;
      memcpy (body_dyn + pos, body_footer, MHD_STATICSTR_LEN_ (body_footer));
    }
    else
    {
      /* Fill the body with binary-like content */
      size_t pos;
      for (pos = 0; pos < body_dyn_size; ++pos)
      {
        body_dyn[pos] = (char) (unsigned char) (255U - pos % 256U);
      }
    }
  }

  /* Use more responses to minimise waiting in threads to unlock
     the response used by other thread. */
  num_resps = 16 * get_num_threads ();
  resps = (struct MHD_Response **)
          malloc ((sizeof(struct MHD_Response *)) * num_resps);
  if (NULL == resps)
  {
    if (NULL != body_dyn)
    {
      free (body_dyn);
      body_dyn = NULL;
    }
    fprintf (stderr, "Failed to allocate memory.\n");
    return 25;
  }
  for (i = 0; i < num_resps; ++i)
  {
#if MHD_VERSION >= 0x00097701
    if (NULL != body_dyn)
      resps[i] = MHD_create_response_from_buffer_static (body_dyn_size,
                                                         body_dyn);
    else if (tool_params.empty)
      resps[i] = MHD_create_response_empty (MHD_RF_NONE);
    else
      resps[i] =
        MHD_create_response_from_buffer_static (MHD_STATICSTR_LEN_ (tiny_body),
                                                tiny_body);

#else  /* MHD_VERSION < 0x00097701 */
    if (NULL != body_dyn)
      resps[i] = MHD_create_response_from_buffer (body_dyn_size,
                                                  (void *) body_dyn,
                                                  MHD_RESPMEM_PERSISTENT);
    else if (tool_params.empty)
      resps[i] = MHD_create_response_from_buffer (0,
                                                  (void *) tiny_body,
                                                  MHD_RESPMEM_PERSISTENT);
    else if (tool_params.tiny)
      resps[i] =
        MHD_create_response_from_buffer (MHD_STATICSTR_LEN_ (tiny_body),
                                         (void *) tiny_body,
                                         MHD_RESPMEM_PERSISTENT);
    else
#endif /* MHD_VERSION < 0x00097701 */
    if (NULL == resps[i])
    {
      fprintf (stderr, "Failed to create responses.\n");
      break;
    }
  }
  if (i == num_resps)
    return 0; /* Success */

  /* Cleanup */
  while (--i < num_resps)
    MHD_destroy_response (resps[i]);
  free (resps);
  resps = NULL;
  num_resps = 0;
  if (NULL != body_dyn)
    free (body_dyn);
  body_dyn = NULL;
  return 32;
}


static void
deinit_data (void)
{
  unsigned int i;
  for (i = 0; i < num_resps; ++i)
    MHD_destroy_response (resps[i]);

  free (resps);
  resps = NULL;
  num_resps = 0;
  if (NULL != body_dyn)
    free (body_dyn);
  body_dyn = NULL;
}


static enum MHD_Result
answer_shared_response (void *cls,
                        struct MHD_Connection *connection,
                        const char *url,
                        const char *method,
                        const char *version,
                        const char *upload_data,
                        size_t *upload_data_size,
                        void **req_cls)
{
  static int marker = 0;
  unsigned int resp_index;
  static volatile unsigned int last_index = 0;
  (void) cls;  /* Unused */
  (void) url; (void) version; /* Unused */
  (void) upload_data; (void) upload_data_size; /* Unused */

  if (NULL == *req_cls)
  {
    /* The fist call */
    *req_cls = (void *) &marker;
    /* Do not send reply yet. No error. */
    return MHD_YES;
  }
  if ((0 != strcmp (method, MHD_HTTP_METHOD_GET)) &&
      (0 != strcmp (method, MHD_HTTP_METHOD_HEAD)))
    return MHD_NO; /* Unsupported method, close connection */

  /* This kind of operation does not guarantee that numbers are not reused
     in parallel threads, when processed simultaneously, but this should not
     be a big problem, as it just slow down replies a bit due to
     responses locking. */
  resp_index = (last_index++) % num_resps;
  return MHD_queue_response (connection, MHD_HTTP_OK, resps[resp_index]);
}


/* Borrowed from daemon.c */
/* TODO: run-time detection */
/**
 * Default connection limit.
 */
#ifdef MHD_POSIX_SOCKETS
#define MHD_MAX_CONNECTIONS_DEFAULT (FD_SETSIZE - 4)
#else
#define MHD_MAX_CONNECTIONS_DEFAULT (FD_SETSIZE - 2)
#endif

static unsigned int
get_mhd_conn_limit (struct MHD_Daemon *d)
{
  /* TODO: implement run-time detection */
  (void) d; /* Unused */
  if (0 != tool_params.connections)
    return tool_params.connections;
  return (unsigned int) MHD_MAX_CONNECTIONS_DEFAULT;
}


static const char *
get_mhd_response_size (void)
{
  if (tool_params.empty)
    return "0 bytes (empty)";
  else if (tool_params.tiny)
    return "3 bytes (tiny)";
  else if (tool_params.medium)
    return "8 KB (medium)";
  else if (tool_params.large)
    return "1 MB (large)";
  abort ();
  return "";
}


static int
run_mhd (void)
{
  struct MHD_Daemon *d;
  unsigned int flags = MHD_NO_FLAG;
  struct MHD_OptionItem opt_arr[16];
  size_t opt_count = 0;
  const union MHD_DaemonInfo *d_info;
  const char *poll_mode;
  uint16_t port;

#if defined (_DEBUG)
  fprintf (stderr, "WARNING: Running with debug asserts enabled, "
           "the performance is suboptimal.\n");
#endif /* _DEBUG */
#if defined(__GNUC__) && ! defined (__OPTIMIZE__)
  fprintf (stderr, "WARNING: The tools is compiled without enabled compiler "
           "optimisations, the performance is suboptimal.\n");
#endif /* __GNUC__ && ! __OPTIMIZE__ */
#if defined(__GNUC__) && defined (__OPTIMIZE_SIZE__)
  fprintf (stderr, "WARNING: The tools is compiled with size-optimisations, "
           "the performance is suboptimal.\n");
#endif /* __GNUC__ && ! __OPTIMIZE__ */
#if MHD_VERSION >= 0x00097701
  if (MHD_NO != MHD_is_feature_supported (MHD_FEATURE_DEBUG_BUILD))
    fprintf (stderr, "WARNING: The libmicrohttpd is compiled with "
             "debug asserts enabled, the performance is suboptimal.\n");
#endif /* MHD_VERSION >= 0x00097701 */
  flags |= MHD_USE_ERROR_LOG;
  flags |= MHD_USE_INTERNAL_POLLING_THREAD;
  if (tool_params.epoll)
    flags |= MHD_USE_EPOLL;
  else if (tool_params.poll)
    flags |= MHD_USE_POLL;
  else if (tool_params.select)
    (void) flags; /* No special additional flag */
  else
    flags |= MHD_USE_AUTO;
  if (! tool_params.date_header)
    flags |= MHD_USE_SUPPRESS_DATE_NO_CLOCK;

  if (0 != tool_params.connections)
  {
    struct MHD_OptionItem option =
    { MHD_OPTION_CONNECTION_LIMIT, (intptr_t) tool_params.connections, NULL };
    opt_arr[opt_count++] = option;
  }
  if (1 < get_num_threads ())
  {
    struct MHD_OptionItem option =
    { MHD_OPTION_THREAD_POOL_SIZE, (intptr_t) get_num_threads (), NULL };
    opt_arr[opt_count++] = option;
  }
  if (1)
  {
    struct MHD_OptionItem option =
    { MHD_OPTION_CONNECTION_TIMEOUT, (intptr_t) tool_params.timeout, NULL };
    opt_arr[opt_count++] = option;
  }
  if (1)
  {
    struct MHD_OptionItem option =
    { MHD_OPTION_END, 0, NULL };
    opt_arr[opt_count] = option;
    if (opt_count >= (sizeof(opt_arr) / sizeof(opt_arr[0])))
      abort ();
  }
  d = MHD_start_daemon (flags, mhd_port, NULL, NULL, &answer_shared_response,
                        NULL, MHD_OPTION_ARRAY, opt_arr, MHD_OPTION_END);
  if (NULL == d)
  {
    fprintf (stderr, "Error starting MHD daemon.\n");
    return 15;
  }
  d_info = MHD_get_daemon_info (d, MHD_DAEMON_INFO_FLAGS);
  if (NULL == d_info)
    abort ();
  flags = (unsigned int) d_info->flags;
  if (0 != (flags & MHD_USE_POLL))
    poll_mode = "poll()";
  else if (0 != (flags & MHD_USE_EPOLL))
    poll_mode = "epoll";
  else
    poll_mode = "select()";
  d_info = MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
  if (NULL == d_info)
    abort ();
  port = d_info->port;
  if (0 == port)
    fprintf (stderr, "Cannot detect port number. Consider specifying "
             "port number explicitly.\n");

  printf ("\nMHD is running.\n");
  printf ("  Bind port:          %u\n", (unsigned int) port);
  printf ("  Polling function:   %s\n", poll_mode);
  printf ("  Threading:          ");
  if (1 == get_num_threads ())
    printf ("one MHD thread\n");
  else
    printf ("%u MHD threads in thread pool\n", get_num_threads ());
  printf ("  Connections limit:  %u\n", get_mhd_conn_limit (d));
  printf ("  Connection timeout: %u%s\n", tool_params.timeout,
          0 == tool_params.timeout ? " (no timeout)" : "");
  printf ("  'Date:' header:     %s\n",
          tool_params.date_header ? "Yes" : "No");
  printf ("  Response size:      %s\n",
          get_mhd_response_size ());
  printf ("To test with remote client use            "
          "http://HOST_IP:%u/\n", (unsigned int) port);
  printf ("To test with client on the same host use  "
          "http://127.0.0.1:%u/\n", (unsigned int) port);
  printf ("\nPress ENTER to stop.\n");
  if (1)
  {
    char buf[10];
    (void) fgets (buf, sizeof(buf), stdin);
  }
  MHD_stop_daemon (d);
  return 0;
}


int
main (int argc, char *const *argv)
{
  int ret;
  set_self_name (argc, argv);
  ret = process_params (argc, argv);
  if (0 != ret)
    return ret;
  ret = check_apply_params ();
  if (0 > ret)
    return 0;
  if (0 != ret)
    return ret;
  ret = init_data ();
  if (0 != ret)
    return ret;
  ret = run_mhd ();
  deinit_data ();
  return ret;
}
