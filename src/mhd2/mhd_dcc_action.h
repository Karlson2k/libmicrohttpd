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
 * @file src/mhd2/mhd_dcc_action.h
 * @brief  The definition of the MHD_Action and MHD_UploadAction structures
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_DCC_ACTION_H
#define MHD_DCC_ACTION_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"

struct MHD_Connection; /* forward declaration */

/**
 * The context used for Dynamic Content Creator callback
 */
struct MHD_DynamicContentCreatorContext
{
  struct MHD_Connection *connection;
};

/**
 * The type of the dynamic content creator action requested by application
 */
enum mhd_DccActionType
{
  /**
   * Action has not been set yet.
   */
  mhd_DCC_ACTION_NO_ACTION = 0
  ,
  /**
   * Send new portion of data, provided by application
   */
  mhd_DCC_ACTION_CONTINUE
  ,
  /**
   * Signal the end of the data stream.
   */
  mhd_DCC_ACTION_FINISH
  ,
  /**
   * Suspend requests (connection)
   */
  mhd_DCC_ACTION_SUSPEND
  ,
  /**
   * Hard close request with no or partial response
   */
  mhd_DCC_ACTION_ABORT
};

/**
 * Check whether provided mhd_ActionType value is valid
 */
#define mhd_DCC_ACTION_IS_VALID(act) \
        ((mhd_DCC_ACTION_CONTINUE <= (act)) && (mhd_DCC_ACTION_ABORT >= (act)))


#ifndef MHD_FREECALLBACK_DEFINED

/**
 * This method is called by libmicrohttpd when response with dynamic content
 * is being destroyed.  It should be used to free resources associated
 * with the dynamic content.
 *
 * @param[in] free_cls closure
 * @ingroup response
 */
typedef void
(*MHD_FreeCallback) (void *free_cls);

#define MHD_FREECALLBACK_DEFINED 1
#endif /* ! MHD_FREECALLBACK_DEFINED */
#ifndef MHD_DYNCONTENTZCIOVEC_DEFINED


/**
 * Structure for iov type of the response.
 * Used for zero-copy response content data.
 */
struct MHD_DynContentZCIoVec
{
  /**
   * The number of elements in @a iov
   */
  unsigned int iov_count;
  /**
   * The pointer to the array with @a iov_count elements.
   */
  const struct MHD_IoVec *iov;
  /**
   * The callback to free resources.
   * It is called once the full array of iov elements is sent.
   * No callback is called if NULL.
   */
  MHD_FreeCallback iov_fcb;
  /**
   * The parameter for @a iov_fcb
   */
  void *iov_fcb_cls;
};

#define MHD_DYNCONTENTZCIOVEC_DEFINED 1
#endif /* ! MHD_DYNCONTENTZCIOVEC_DEFINED */

/**
 * The data for DCC "continue" action
 */
struct mhd_DccActionContinueData
{
  /**
   * The size of the content data in the buffer
   */
  size_t buf_data_size;
  /**
   * Zero-copy content data data
   */
  const struct MHD_DynContentZCIoVec *iov_data;
};


/**
 * The data for the DCC application action
 */
union mhd_DccActionData
{
  /**
   * The data for the action #mhd_DCC_ACTION_CONTINUE
   */
  struct mhd_DccActionContinueData cntnue;
};


/**
 * The action type returned by Dynamic Content Creator callback
 */
struct MHD_DynamicContentCreatorAction
{
  /**
   * The action
   */
  enum mhd_DccActionType act;

  /**
   * The data for the @a act action
   */
  union mhd_DccActionData data;
};

#endif /* ! MHD_DCC_ACTION_H */
