/* main.c
 *       Copyright (C) 2001, 2002, 2003, 2007 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * OpenCDK is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or 
 * (at your option) any later version. 
 *  
 * OpenCDK is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details. 
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

#include "opencdk.h"
#include "main.h"
#include "packet.h"


/* Set a default cipher algorithm and a digest algorithm.
   Even if AES and SHA-256 are not 'MUST' in the latest
   OpenPGP draft, AES seems to be a good choice. */
#define DEFAULT_CIPHER_ALGO GCRY_CIPHER_AES
#define DEFAULT_DIGEST_ALGO GCRY_MD_SHA256

/* The site of the secure memory which is allocated in gcrypt. */
#define SECMEM_SIZE 16384


/* Hooks to custom memory allocation functions. */
static void *(*alloc_func) (size_t n) = gcry_xmalloc;
static void *(*alloc_secure_func) (size_t n) = gcry_malloc_secure;
static void *(*realloc_func) (void *p, size_t n) = gcry_realloc;
static void *(*calloc_func) (size_t m, size_t n) = gcry_calloc;
static void (*free_func) (void *) = gcry_free;
static int malloc_hooks = 0;
static int secmem_init = 0;

/* Global settings for the logging. */
static cdk_log_fnc_t log_handler = NULL;
static void *log_handler_value = NULL;
static int log_level = CDK_LOG_NONE;


/**
 * cdk_strerror:
 * @ec: the error number
 *
 * Return an error text for the given id.
 **/
const char *
cdk_strerror (int ec)
{
  static char buf[20];

  switch (ec)
    {
    case CDK_EOF:
      return "End Of File";
    case CDK_Success:
      return "No error";
    case CDK_General_Error:
      return "General error";
    case CDK_File_Error:
      return strerror (errno);
    case CDK_Bad_Sig:
      return "Bad signature";
    case CDK_Inv_Packet:
      return "Invalid packet";
    case CDK_Inv_Algo:
      return "Invalid algorithm";
    case CDK_Not_Implemented:
      return "This is not implemented yet";
    case CDK_Armor_Error:
      return "ASCII armor error";
    case CDK_Armor_CRC_Error:
      return "ASCII armored damaged (CRC error)";
    case CDK_MPI_Error:
      return "Invalid or missformed MPI";
    case CDK_Inv_Value:
      return "Invalid parameter or value";
    case CDK_Error_No_Key:
      return "No key available or not found";
    case CDK_Chksum_Error:
      return "Check for key does not match";
    case CDK_Time_Conflict:
      return "Time conflict";
    case CDK_Zlib_Error:
      return "ZLIB error";
    case CDK_Weak_Key:
      return "Weak key was detected";
    case CDK_Out_Of_Core:
      return "Out of core!!";
    case CDK_Wrong_Seckey:
      return "Wrong secret key";
    case CDK_Wrong_Format:
      return "Data has wrong format";
    case CDK_Bad_MDC:
      return "Manipulated MDC detected";
    case CDK_Inv_Mode:
      return "Invalid mode";
    case CDK_Error_No_Keyring:
      return "No keyring available";
    case CDK_Inv_Packet_Ver:
      return "Invalid version for packet";
    case CDK_Too_Short:
      return "Buffer or object is too short";
    case CDK_Unusable_Key:
      return "Unusable public key";
    case CDK_No_Data:
      return "No data";
    case CDK_No_Passphrase:
      return "No passphrase supplied";
    case CDK_Network_Error:
      return "A network error occurred";
    default:
      sprintf (buf, "ec=%d", ec);
      return buf;
    }
  return NULL;
}


static void
out_of_core (size_t n)
{
  fprintf (stderr, "\n ** fatal error: out of memory (%d bytes) **\n", n);
}


/**
 * cdk_set_malloc_hooks: 
 * @new_alloc_func: malloc replacement
 * @new_alloc_secure_func: secure malloc replacement
 * @new_realloc_func: realloc replacement
 * @new_calloc_func: calloc replacement
 * @new_free_func: free replacement
 *
 * Set private memory hooks for the library.
 */
void
cdk_set_malloc_hooks (void *(*new_alloc_func) (size_t n),
                      void *(*new_alloc_secure_func) (size_t n),
                      void *(*new_realloc_func) (void *p, size_t n),
                      void *(*new_calloc_func) (size_t m, size_t n),
                      void (*new_free_func) (void *))
{
  alloc_func = new_alloc_func;
  alloc_secure_func = new_alloc_secure_func;
  realloc_func = new_realloc_func;
  calloc_func = new_calloc_func;
  free_func = new_free_func;
  malloc_hooks = 1;
}


/**
 * cdk_malloc_hook_initialized:
 *
 * Return if the malloc hooks are already initialized.
 **/
int
cdk_malloc_hook_initialized (void)
{
  return malloc_hooks;
}


void *
cdk_malloc (size_t size)
{
  void *p = alloc_func (size);
  if (!p)
    out_of_core (size);
  return p;
}


/**
 * cdk_calloc:
 * @n: amount of elements
 * @m: size of one element
 * 
 * Safe wrapper around the c-function calloc.
 **/
void *
cdk_calloc (size_t n, size_t m)
{
  void *p = calloc_func (n, m);
  if (!p)
    out_of_core (m);
  return p;
}


/* Things which need to  be done after the secure memory initialisation. */
static void
_secmem_finish (void)
{
  gcry_control (GCRYCTL_DROP_PRIVS);
}


/* Initialize the secure memory. */
static void
_secmem_init (size_t size)
{
  if (secmem_init == 1)
    return;
  if (size >= SECMEM_SIZE)
    size = SECMEM_SIZE;

  /* Check if no other library has already initialized gcrypt. */
  if (!gcry_control (GCRYCTL_ANY_INITIALIZATION_P))
    {
      _cdk_log_debug ("init: libgcrypt initialize.\n");
      gcry_control (GCRYCTL_INIT_SECMEM, size, 0);
      gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);
      gcry_control (GCRYCTL_DISABLE_SECMEM_WARN);
      gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL, 0);
      secmem_init = 1;
    }
}


/* Things which needs to be done to deinit the secure memory. */
static void
_secmem_end (void)
{
  gcry_control (GCRYCTL_TERM_SECMEM);
  secmem_init = 0;
}


/* The Windows system needs to startup the Winsock interface first
   before we can use any socket related function. */
#ifdef _WIN32
static void
init_sockets (void)
{
  static int initialized = 0;
  WSADATA wsdata;

  if (initialized)
    return;
  if (WSAStartup (0x202, &wsdata))
    _cdk_log_debug ("winsock init failed.\n");

  initialized = 1;
}

static void
deinit_sockets (void)
{
  WSACleanup ();
}
#else
void
init_sockets (void)
{
}
void
deinit_sockets (void)
{
}
#endif


/**
 * cdk_lib_startup:
 * 
 * Prepare the internal structures of the library.
 * This function should be called before any other CDK function.
 */
void
cdk_lib_startup (void)
{
  _secmem_init (SECMEM_SIZE);
  _secmem_finish ();
  init_sockets ();
}


/**
 * cdk_lib_shutdown:
 * 
 * Shutdown the library and free all internal and globally used
 * memory and structures. This function should be called in the
 * exit handler of the calling program.
 */
void
cdk_lib_shutdown (void)
{
  deinit_sockets ();
  _secmem_end ();
}

/**
 * cdk_salloc:
 * @size: how much bytes should be allocated.
 * @clear: shall the buffer cleared after the allocation?
 * 
 * Allocated the requested amount of bytes in 'secure' memory.
 */
void *
cdk_salloc (size_t size, int clear)
{
  void *p;

  if (!secmem_init)
    _secmem_init (SECMEM_SIZE);

  p = alloc_secure_func (size);
  if (!p)
    out_of_core (size);
  if (clear)
    memset (p, 0, size);
  return p;
}


void *
cdk_realloc (void *ptr, size_t size)
{
  void *p = realloc_func (ptr, size);
  if (!p)
    out_of_core (size);
  return p;
}


char *
cdk_strdup (const char *ptr)
{
  char *p = cdk_malloc (strlen (ptr) + 1);
  if (p)
    strcpy (p, ptr);
  return p;
}


void
cdk_free (void *ptr)
{
  if (ptr)
    free_func (ptr);
}


/* Internal logging routine. */
static void
_cdk_logv (int level, const char *fmt, va_list arg_ptr)
{

  if (log_handler)
    log_handler (log_handler_value, level, fmt, arg_ptr);
  else
    {
      if (level == CDK_LOG_NONE)
        return;
      if (level == CDK_LOG_DEBUG)
        fputs ("DBG: ", stderr);
      vfprintf (stderr, fmt, arg_ptr);
    }
}


/**
 * cdk_set_log_handler: 
 * @logfnc: the function pointer
 * @opaque: a private values for the function
 *
 * Set a custom handler for logging.
 **/
void
cdk_set_log_handler (cdk_log_fnc_t logfnc, void *opaque)
{
  log_handler = logfnc;
  log_handler_value = opaque;
}


/**
 * cdk_set_log_level: 
 * @lvl: the level
 *
 * Set the verbosity level.
 **/
void
cdk_set_log_level (int level)
{
  log_level = level;
}


/* Return the current log level of the lib. */
int
_cdk_get_log_level (void)
{
  return log_level;
}


void
_cdk_log_info (const char *fmt, ...)
{
  va_list arg;

  if (log_level == CDK_LOG_NONE)
    return;
  va_start (arg, fmt);
  _cdk_logv (CDK_LOG_INFO, fmt, arg);
  va_end (arg);
}


void
_cdk_log_debug (const char *fmt, ...)
{
  va_list arg;

  if (log_level < CDK_LOG_DEBUG)
    return;
  va_start (arg, fmt);
  _cdk_logv (CDK_LOG_DEBUG, fmt, arg);
  va_end (arg);
}


/* Use the passphrase callback in the handle HD or
   return NULL if there is no valid callback. */
char *
_cdk_passphrase_get (cdk_ctx_t hd, const char *prompt)
{
  if (!hd || !hd->passphrase_cb)
    return NULL;
  return hd->passphrase_cb (hd->passphrase_cb_value, prompt);
}


static void
handle_set_cipher (cdk_ctx_t hd, int cipher)
{
  if (!hd)
    return;
  if (gcry_cipher_test_algo (cipher))
    cipher = DEFAULT_CIPHER_ALGO;
  hd->cipher_algo = cipher;
}


static void
handle_set_digest (cdk_ctx_t hd, int digest)
{
  if (!hd)
    return;
  if (gcry_md_test_algo (digest))
    digest = DEFAULT_DIGEST_ALGO;
  hd->digest_algo = digest;
}


static void
handle_set_s2k (cdk_ctx_t hd, int mode, int digest, int cipher)
{
  if (!hd)
    return;
  if (gcry_cipher_test_algo (cipher))
    cipher = DEFAULT_CIPHER_ALGO;
  if (gcry_md_test_algo (digest))
    digest = DEFAULT_DIGEST_ALGO;
  if (mode != CDK_S2K_SIMPLE &&
      mode != CDK_S2K_SALTED && mode != CDK_S2K_ITERSALTED)
    mode = CDK_S2K_ITERSALTED;
  hd->_s2k.mode = mode;
  hd->_s2k.digest_algo = digest;
}


static void
handle_set_compress (cdk_ctx_t hd, int algo, int level)
{
  if (!hd)
    return;
  if (algo < 0 || algo > 2)
    algo = 0;
  hd->compress.algo = algo;
  if (!algo)
    hd->opt.compress = 0;
  else
    {
      if (level > 0 && level < 10)
        hd->compress.level = level;
      else
        hd->compress.level = 6;
    }
}


/**
 * cdk_handle_control:
 * @hd: session handle
 * @action: flag which indicates whether put or get is requested
 * @cmd: command id
 *
 * Perform various control operations for the current session.
 **/
int
cdk_handle_control (cdk_ctx_t hd, int action, int cmd, ...)
{
  va_list arg_ptr;
  int set = action == CDK_CTLF_SET, val = 0;

  if (!hd)
    return -1;

  if (action != CDK_CTLF_SET && action != CDK_CTLF_GET)
    return -1;
  va_start (arg_ptr, cmd);
  switch (cmd)
    {
    case CDK_CTL_ARMOR:
      if (set)
        hd->opt.armor = va_arg (arg_ptr, int);
      else
        val = hd->opt.armor;
      break;

    case CDK_CTL_CIPHER:
      if (set)
        handle_set_cipher (hd, va_arg (arg_ptr, int));
      else
        val = hd->cipher_algo;
      break;

    case CDK_CTL_DIGEST:
      if (set)
        handle_set_digest (hd, va_arg (arg_ptr, int));
      else
        val = hd->digest_algo;
      break;

    case CDK_CTL_OVERWRITE:
      if (set)
        hd->opt.overwrite = va_arg (arg_ptr, int);
      else
        val = hd->opt.overwrite;
      break;

    case CDK_CTL_COMPRESS:
      if (set)
        {
          int algo = va_arg (arg_ptr, int);
          int level = va_arg (arg_ptr, int);
          handle_set_compress (hd, algo, level);
        }
      else
        val = hd->compress.algo;
      break;

    case CDK_CTL_S2K:
      if (set)
        {
          int mode = va_arg (arg_ptr, int);
          int digest = va_arg (arg_ptr, int);
          int cipher = va_arg (arg_ptr, int);
          handle_set_s2k (hd, mode, digest, cipher);
        }
      else
        val = hd->_s2k.mode;
      break;

    case CDK_CTL_FORCE_DIGEST:
      if (set)
        hd->opt.force_digest = va_arg (arg_ptr, int);
      else
        val = hd->opt.force_digest;
      break;

    case CDK_CTL_BLOCKMODE_ON:
      if (set)
        hd->opt.blockmode = va_arg (arg_ptr, int);
      else
        val = hd->opt.blockmode;
      break;

    default:
      val = -1;
      break;
    }
  va_end (arg_ptr);
  return val;
}



/**
 * cdk_handle_new:
 * @r_ctx: context to store the handle
 *
 * create a new session handle.
 **/
cdk_error_t
cdk_handle_new (cdk_ctx_t * r_ctx)
{
  cdk_ctx_t c;

  if (!r_ctx)
    return CDK_Inv_Value;

  c = cdk_calloc (1, sizeof *c);
  if (!c)
    return CDK_Out_Of_Core;

  /* For S2K use the iterated and salted mode and use the
     default digest and cipher algorithms. Because the MDC
     feature will be used, the default cipher should use a 
     blocksize of 128 bits. */
  c->_s2k.mode = CDK_S2K_ITERSALTED;
  c->_s2k.digest_algo = DEFAULT_DIGEST_ALGO;

  c->opt.mdc = 1;
  c->opt.compress = 1;
  c->opt.armor = 0;
  c->opt.textmode = 0;

  c->digest_algo = DEFAULT_DIGEST_ALGO;
  c->cipher_algo = DEFAULT_CIPHER_ALGO;

  c->compress.algo = CDK_COMPRESS_ZIP;
  c->compress.level = 6;

  *r_ctx = c;
  return 0;
}


/**
 * cdk_handle_set_keyring:
 * @hd: session handle
 * @type: public=0 or secret=1 keyring type
 * @kringname: file name of the keyring which shall be used.
 * 
 * Convenient function to set the keyring for the current session.
 */
cdk_error_t
cdk_handle_set_keyring (cdk_ctx_t hd, int type, const char *kringname)
{
  cdk_keydb_hd_t db;
  cdk_error_t err;

  err = cdk_keydb_new_from_file (&db, type, kringname);
  if (err)
    return err;

  if (!type)
    hd->db.pub = db;
  else
    hd->db.sec = db;
  hd->db.close_db = 1;
  return 0;
}


/**
 * cdk_handle_set_keydb:
 * @hd: session handle
 * @db: the database handle
 *
 * set the key database handle.
 * the function automatically detects whether this is a public or
 * secret keyring and the right handle is set.
 **/
void
cdk_handle_set_keydb (cdk_ctx_t hd, cdk_keydb_hd_t db)
{
  if (!hd)
    return;
  if (_cdk_keydb_is_secret (db))
    hd->db.sec = db;
  else
    hd->db.pub = db;
}


/**
 * cdk_handle_get_keydb:
 * @hd: session handle
 * @type: type of the keyring
 *
 * Return the keydb handle from the session handle.
 * The caller should not free these handles.
 **/
cdk_keydb_hd_t
cdk_handle_get_keydb (cdk_ctx_t hd, int type)
{
  if (!hd)
    return NULL;
  if (type == CDK_DBTYPE_PK_KEYRING)
    return hd->db.pub;
  else if (type == CDK_DBTYPE_SK_KEYRING)
    return hd->db.sec;
  return NULL;
}


/**
 * cdk_handle_set_passphrase_cb:
 * @hd: session handle
 * @cb: callback function
 * @cb_value: the opaque value for the cb function
 *
 * set the passphrase callback.
 **/
void
cdk_handle_set_passphrase_cb (cdk_ctx_t hd,
                              char *(*cb) (void *opa, const char *prompt),
                              void *cb_value)
{
  if (!hd)
    return;
  hd->passphrase_cb = cb;
  hd->passphrase_cb_value = cb_value;
}


/**
 * cdk_handle_verify_get_result:
 * @hd: the session handle
 * 
 * Return the verify result for the current session.
 * Do not free the pointer.
 **/
cdk_verify_result_t
cdk_handle_verify_get_result (cdk_ctx_t hd)
{
  return hd->result.verify;
}


/**
 * cdk_handle_free:
 * @hd: the handle
 *
 * Release the main handle.
 **/
void
cdk_handle_free (cdk_ctx_t hd)
{
  if (!hd)
    return;
  _cdk_result_verify_free (hd->result.verify);

  /* If cdk_handle_set_keyring() were used, we need to free the key db
     handles here because the handles are not controlled by the user. */
  if (hd->db.close_db)
    {
      if (hd->db.pub)
        cdk_keydb_free (hd->db.pub);
      if (hd->db.sec)
        cdk_keydb_free (hd->db.sec);
      hd->db.pub = hd->db.sec = NULL;
    }
  cdk_free (hd->dek);
  cdk_free (hd);
}
