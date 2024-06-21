#ifndef MHD_EXTERN_
#  if ! defined(_WIN32)
#    define MHD_EXTERN_ extern
#  else /* defined(_WIN32) */
#    if ! defined(MHD_W32LIB)
#      define MHD_EXTERN_ extern
#    else /* defined(_WIN32) && efined(MHD_W32LIB) */
/* Define MHD_W32DLL when using MHD as W32 .DLL to speed up linker a little */
#      define MHD_EXTERN_ extern __declspec(dllimport)
#    endif
#  endif
#endif


#ifndef MHD_FIXED_ENUM_
#  define MHD_FIXED_ENUM_       /* empty */
#endif /* MHD_FIXED_ENUM_ */
#ifndef MHD_FLAGS_ENUM_
#  define MHD_FLAGS_ENUM_       /* empty */
#endif /* MHD_FLAGS_ENUM_ */

#ifndef MHD_FIXED_FLAGS_ENUM_
#  define MHD_FIXED_FLAGS_ENUM_ MHD_FIXED_ENUM_ MHD_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_ENUM_APP_SET_
/* The enum is set by an application to the fixed list of values */
#  define MHD_FIXED_ENUM_APP_SET_ MHD_FIXED_ENUM_
#endif

#ifndef MHD_FLAGS_ENUM_APP_SET_
/* The enum is set by an application, it is a bitmap */
#  define MHD_FLAGS_ENUM_APP_SET_ MHD_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_FLAGS_ENUM_APP_SET_
/* The enum is set by an application to the fixed bitmap values */
#  define MHD_FIXED_FLAGS_ENUM_APP_SET_ MHD_FIXED_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_ENUM_MHD_SET_
/* The enum is set by MHD to the fixed list of values */
#  define MHD_FIXED_ENUM_MHD_SET_ /* enum can be extended in next MHD versions */
#endif

#ifndef MHD_FLAGS_ENUM_MHD_SET_
/* The enum is set by MHD, it is a bitmap */
#  define MHD_FLAGS_ENUM_MHD_SET_ MHD_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_FLAGS_ENUM_MHD_SET_
/* The enum is set by MHD to the fixed bitmap values */
#  define MHD_FIXED_FLAGS_ENUM_MHD_SET_ MHD_FLAGS_ENUM_ /* enum can be extended in next MHD versions */
#endif

#ifndef MHD_FIXED_ENUM_MHD_APP_SET_
/* The enum is set by both MHD and app to the fixed list of values */
#  define MHD_FIXED_ENUM_MHD_APP_SET_ /* enum can be extended in next MHD versions */
#endif

#ifndef MHD_FLAGS_ENUM_MHD_APP_SET_
/* The enum is set by both MHD and app, it is a bitmap */
#  define MHD_FLAGS_ENUM_MHD_APP_SET_ MHD_FLAGS_ENUM_
#endif

#ifndef MHD_FIXED_FLAGS_ENUM_MHD_APP_SET_
/* The enum is set by both MHD and app to the fixed bitmap values */
#  define MHD_FIXED_FLAGS_ENUM_MHD_APP_SET_ MHD_FLAGS_ENUM_ /* enum can be extended in next MHD versions */
#endif


#ifndef MHD_FN_CONST_
#  define MHD_FN_CONST_       /* empty */
#endif /* ! MHD_FN_CONST_ */
#ifndef MHD_FN_PURE_
#  define MHD_FN_PURE_        /* empty */
#endif /* ! MHD_FN_PURE_ */
#ifndef MHD_FN_MUST_CHECK_RESULT_
#  define MHD_FN_MUST_CHECK_RESULT_   /* empty */
#endif /* ! MHD_FN_MUST_CHECK_RESULT_ */
#ifndef MHD_FN_PAR_NONNULL_
#  define MHD_FN_PAR_NONNULL_(param_num)    /* empty */
#endif /* ! MHD_FN_PAR_NONNULL_ */
#ifndef MHD_FN_PAR_NONNULL_ALL_
#  define MHD_FN_PAR_NONNULL_ALL_   /* empty */
#endif /* ! MHD_FN_PAR_NONNULL_ALL_ */
#ifndef MHD_FN_PAR_IN_
#  define MHD_FN_PAR_IN_(param_num) /* empty */
#endif /* !MHD_FN_PAR_IN_ */
#ifndef MHD_FN_PAR_IN_SIZE_
#  define MHD_FN_PAR_IN_SIZE_(param_num,size_num)   /* empty */
#endif /* !MHD_FN_PAR_IN_SIZE_ */
#ifndef MHD_FN_PAR_OUT_
#  define MHD_FN_PAR_OUT_(param_num)        /* empty */
#endif /* !MHD_FN_PAR_OUT_ */
#ifndef MHD_FN_PAR_OUT_SIZE_
#  define MHD_FN_PAR_OUT_SIZE_(param_num,size_num)  /* empty */
#endif /* !MHD_FN_PAR_OUT_SIZE_ */
#ifndef MHD_FN_PAR_INOUT_
#  define MHD_FN_PAR_INOUT_(param_num)      /* empty */
#endif /* !MHD_FN_PAR_INOUT_ */
#ifndef MHD_FN_PAR_INOUT_SIZE_
#  define MHD_FN_PAR_INOUT_SIZE_(param_num,size_num)        /* empty */
#endif /* !MHD_FN_PAR_INOUT_SIZE_ */
#ifndef MHD_FN_PAR_FD_READ_
#  define MHD_FN_PAR_FD_READ_(param_num)        /* empty */
#endif /* !MHD_FN_PAR_FD_READ_ */
#ifndef MHD_FN_PAR_CSTR_
#  define MHD_FN_PAR_CSTR_(param_num)   /* empty */
#endif /* ! MHD_FN_PAR_CSTR_ */
#ifndef MHD_FN_RETURNS_NONNULL_
#  define MHD_FN_RETURNS_NONNULL_       /* empty */
#endif /* ! MHD_FN_RETURNS_NONNULL_ */


/**
 * Which threading and polling mode should be used by MHD?
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_ThreadingPollingMode
{
  /**
   * Use an external event loop.
   * Application uses #MHD_get_watched_fds()/#MHD_get_watched_fds_update()
   * and #MHD_process_watched_fds() with level triggered sockets
   * polling (like select() or poll()).
   */
  MHD_TM_EXTERNAL_EVENT_LOOP_WFD_LEVEL = 10
  ,
  /**
   * Use an external event loop.
   * Application uses #MHD_get_watched_fds()/#MHD_get_watched_fds_update()
   * and #MHD_process_watched_fds() with edge triggered sockets polling.
   */
  MHD_TM_EXTERNAL_EVENT_LOOP_WFD_EDGE = 11
  ,
};

/* FUTURE:
   (with eventually option "number of masters")
   MHD_TM_WORKER_THREADS_WITH_MASTER_LISTENER = 3 */


// Alternative style

struct MHD_WatchedFD
{
  /**
   * The watched socket.
   * Ignored if set by application to #MHD_INVALID_SOCKET. TODO: Improve wording
   */
  MHD_Socket fd;

  /**
   * Indicates that socket should be watched for specific network state
   * (when set by #MHD_get_watched_fds(), #MHD_get_watched_fds_update())
   * / the network state of the socket (when used for
   * #MHD_process_watched_fds())
   */
  enum MHD_FdState state;
};

/**
 * Get the full list of the sockets that must be watched by application.
 *
 * The application may use this function each time to get a full list of
 * the sockets for watch or may use #MHD_get_watched_fds_update() to
 * get the incremental updates.
 *
 * // TODO: add introspection reference
 *
 * @param daemon the daemon to get the list
 * @param num_elements the number of elements in @a fds list
 * @param[out] wfds the arrays of @a num_elements of sockets to be watched
 *                  by application, the unused elements (if any) at
 *                  the end of the array are filled with
 *                  { MHD_INVALID_SOCKET, MHD_FD_STATE_NONE }
 * @param[out] max_wait the pointer to value set to maximum wait time
 *                      for the network events, in microseconds
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 * @ingroup event
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_get_watched_fds (
  struct MHD_Daemon *daemon,
  unsigned int num_elements,
  struct MHD_WatchedFD wfds[MHD_FN_PAR_DYN_ARR_SIZE_ (num_elements)],
  uint_fast64_t *max_wait)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_OUT_(3) MHD_FN_PAR_NONNULL_(3)
MHD_FN_PAR_OUT_(4) MHD_FN_PAR_NONNULL_ (4);


enum MHD_WatchedFdAction
{
  /**
   * New watched FD, to be added to the list
   */
  MHD_WFA_ADD = 1
  ,
  /**
   * Update watching interest in already watched FD
   */
  MHD_WFA_UPDATE = 2
  ,
  /**
   * Delete FD from watching list
   */
  MHD_WFA_REMOVE = 3
  ,
  /**
   * No action. Used to fill the end of the array
   * The matching FD is always #MHD_INVALID_SOCKET.
   */
  MHD_WFA_NONE = 0
};

struct MHD_WatchedFdUpdate
{
  /**
   * The required action: add/update/delete
   */
  enum MHD_WatchedFdAction action;

  /**
   * The watched FD to add, update or delete.
   */
  struct MHD_WatchedFD watched_fd;
};

/**
 * Get the update of the list of the sockets that must be watched
 * by application.
 * This function provides an update to the list of watched sockets
 * since the last call of #MHD_get_watched_fds() or
 * #MHD_get_watched_fds_update().
 * If this function is called before #MHD_get_watched_fds() then it
 * returns full list of sockets to watch with action #MHD_WFA_ADD.
 *
 * @param daemon the daemon to get the list
 * @param num_elements the number of elements in @a fds list
 * @param[out] wfdus the arrays of @a num_elements to update the list
 *                   of watched sockets,  the unused elements (if any) at
 *                   the end of the array are filled with
 *                   { MHD_WFA_NONE, { MHD_INVALID_SOCKET, MHD_FD_STATE_NONE } }
 * @param[out] max_wait the pointer to value set to maximum wait time
 *                      for the network events, in microseconds
 * @return ::MHD_SC_OK on success,
 *         error code otherwise
 * @ingroup event
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_get_watched_fds_update (
  struct MHD_Daemon *daemon,
  unsigned int num_elements,
  struct MHD_WatchedFdUpdate wfdus[MHD_FN_PAR_DYN_ARR_SIZE_ (num_elements)],
  uint_fast64_t *max_wait)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_OUT_(3) MHD_FN_PAR_NONNULL_(3)
MHD_FN_PAR_OUT_(4) MHD_FN_PAR_NONNULL_ (4);
;


/**
 * Perform round of sockets processing, including receiving, sending,
 * data processing, sockets closing and other things.
 * @param daemon the daemon to process
 * @param num_elements the number of elements in the @a fds array
 * @param fds the array of watched sockets, must be complete list of
 *            all watched sockets level sockets triggering used or
 *            could be just partial list if edge sockets triggering used
 * @return ::MHD_SC_OK on success,
 *         otherwise error code TODO: complete list of error codes
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_process_watched_fds (
  struct MHD_Daemon *daemon,
  unsigned int num_elements,
  const struct MHD_WatchedFD fds[MHD_FN_PAR_DYN_ARR_SIZE_ (num_elements)])
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_IN_(3) MHD_FN_PAR_NONNULL_ (3);


// FIXME: convert introspection
/**
 * Obtain timeout value for polling function for this daemon.
 *
 * This function set value to amount of milliseconds for which polling
 * function (`select()` or `poll()`) should at most block, not the
 * timeout value set for connections.
 * It is important to always use this function, even if connection
 * timeout is not set, as in some cases MHD may already have more
 * data to process on next turn (data pending in TLS buffers,
 * connections are already ready with epoll etc.) and returned timeout
 * will be zero.
 *
 * @param[in,out] daemon daemon to query for timeout
 * @param[out] timeout set to the timeout (in milliseconds),
 *             #MHD_WAIT_INDEFINITELY if timeouts are // FIXME: redesigned
 *             not used (or no connections exist that would
 *             necessitate the use of a timeout right now)
 * @return #MHD_SC_OK on success, otherwise
 *        an error code
 * @ingroup event
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_ext_polling_get_max_wait (struct MHD_Daemon *daemon,
                                     uint_fast64_t *timeout)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_OUT_ (2);

// FIXME: gana? table for RFC 7541...
// TODO: extract https://www.rfc-editor.org/rfc/rfc7541.html#appendix-A
enum MHD_PredefinedHeader;


/**
 * Get last occurrence of a particular header value under
 * the given @a skt.
 *
 * The pointer to the string in @a value is valid until the response
 * is queued. If the data is needed beyond this point, it should be copied.
 *
 * @param[in,out] request request to get values from
 * @param kind what kind of value are we looking for
 * @param skt the header to look for based on RFC 7541 Appendix A.
 * @param[out] value the found value, the str pointer set to
 *                   NULL if nothing is found
 * @return #MHD_SC_OK if found,
 *         error code otherwise
 * @ingroup request
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_request_lookup_value_by_static_header (struct MHD_Request *request,
                                           enum MHD_ValueKind kind,
                                           enum MHD_PredefinedHeader skt,
                                           struct MHD_StringNullable *value)
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (4); // TODO: convert like previous


/* FUTURE:
   (with eventually option "number of masters")
   MHD_TM_WORKER_THREADS_WITH_MASTER_LISTENER = 3 */


// FIXME: remove completely?
/**
 * Configure DH parameters (dh.pem) to use for the TLS key
 * exchange.
 *
 * @param daemon daemon to configure tls for
 * @param dh parameters to use
 * @return #MHD_SC_OK upon success; TODO: define failure modes
 */
MHD_EXTERN_ enum MHD_StatusCode
MHD_daemon_tls_mem_dhparams (struct MHD_Daemon *daemon,
                             const char *dh)
MHD_FN_PAR_NONNULL_ (1);
