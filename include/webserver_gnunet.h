/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)
     (C) 2002 Luis Figueiredo (stdio@netc.pt)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/webserver_gnunet.h
 * @brief public interface to libwebserver_gnunet
 *
 * @author Christian Grothoff
 * @author Luis Figueiredo
 */

struct web_server;

int web_server_init(struct web_server * handle,
		    int port,
		    int flags);

void web_server_shutdown(struct web_server *);

int web_server_addhandler(struct web_server * hande,
			  const char *,
			  void (*handler)(),
			  void * hctx);

int web_server_run(struct web_server *);

