/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * file: utils.h
 *
 * description: Header
 *
 * date: 19:50,07-50-2002
 */

#ifndef _FLOCK_H_
#define _FLOCK_H_

#include <windows.h>
#include <io.h> // this?
#include <errno.h>

#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8	

int flock (int,int);


#endif