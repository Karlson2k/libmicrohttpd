/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * date: Wed Oct  9 19:56:22 GMT 2002
 *
 * -- Error functions
 *
 */


#include "error.h"


const char *libws_error_table[]={
	"Memory error",
	"Filesystem error",
	"Network error"
};


void libws_error(unsigned int code, const char *fmt, ...) {
	va_list args;
	
	va_start(args,fmt);
	fprintf(stderr,"%s: ",libws_error_table[code]); 
	vfprintf(stderr,fmt,args);
	va_end(args);
	fflush(stderr);
};
