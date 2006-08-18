/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * date: Tue 9 Sep 06:45:13 2003 GMT
 *
 * 	libwebserver error codes
 *
 */


#ifndef _ERROR_H_
#define _ERROR_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>


#define LE_MEMORY  0   // memory error
#define LE_FILESYS 1   // file error 
#define LE_NET     2   // net error

#define LWSERR(x) libws_error(x,"file: %s - line: %d\n",__FILE__, __LINE__);

void libws_error(unsigned int, const char *,...);


#endif
