/*
     This file is part of libmicrohttpd
     (C) 2007 Daniel Pittman

     libmicrohttpd is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     libmicrohttpd is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with libmicrohttpd; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file internal.h
 * @brief  internal shared structures
 * @author Daniel Pittman
 * @author Christian Grothoff
 * @version 0.1.0
 */

#ifndef INTERNAL_H
#define INTERNAL_H


#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdarg>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>

#include "microhttpd.h"
#include "config.h"

#define MHD_MAX_BUF_SIZE 2048



/**
 * Header or cookie in HTTP request or response.
 */
struct MHD_HTTP_Header {
  struct MHD_HTTP_Header * next;

  char * header;

  char * value;

  enum MHD_ValueKind kind;
};


struct MHD_Access_Handler {
  struct MHD_Access_Handler * next;

  char * uri_prefix;

  MHD_AccessHandlerCallback dh;

  void * dh_cls;
};


struct MHD_Daemon {

  struct MHD_Access_Handler * handlers;

  struct MHD_Access_Handler default_handler;

  struct MHD_Session * connections;
  
  MHD_AcceptPolicyCallback apc;

  void * apc_cls;

  /**
   * PID of the select thread (if we have internal select)
   */
  pthread_t pid;

  /**
   * Listen socket.
   */
  int socket_fd;

  /**
   * Are we shutting down?
   */
  int shutdown;

  /**
   * Daemon's options.
   */
  enum MHD_OPTION options;

  unsigned short port;

};


#endif
