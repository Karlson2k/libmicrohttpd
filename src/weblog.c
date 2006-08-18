/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * date: Sat Mar 30 14:44:42 GMT 2002
 *
 * -- web_log operations
 *
 */



#include "weblog.h"

FILE *_logfile=NULL;
/*********************************************************************************************************/
/*
 * Open weblog file
 */
FILE *open_weblog(const char *logfile) {
	FILE *ret;
	ret=fopen(logfile,"a+");
	_logfile=ret;
	return ret;
}

/*********************************************************************************************************/
/*
 * Log to _logfile;
 */
void web_log(const char *fmt,...) {
	va_list args;
	if(_logfile) {
		va_start(args,fmt);
		vfprintf(_logfile,fmt,args);
		va_end(args);
		fflush(_logfile);
	}
}                 
