/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * date: Sat Mar 30 14:16:05 GMT 2002
 *
 * 	DEBUG macros
 *
 */

#ifndef _DEBUG_H_
#define _DEBUG_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif         

#ifdef DEBUG
	#define IFDEBUG(x) x
#else
	#define IFDEBUG(x)
#endif


#endif
