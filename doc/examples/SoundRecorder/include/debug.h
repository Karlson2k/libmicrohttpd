/* by Luis Figueiredo (stdio@netc.pt)
 *
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
