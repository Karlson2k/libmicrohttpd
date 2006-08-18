/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * date: 19:49,07-49-2002
 *
 * -- description: File lock for winnt
 *

/*********************************************************************************************************/
/* 
 * simulate a file lock, using locking region on WINNT
 */
#include "flock.h"



#define LK_ERR(f,i)	((f) ? (i = 0) : (i=-1))
#define LK_LEN		0xffff0000

int flock(int fd, int oper) {
    OVERLAPPED o;
    int i = -1;
    HANDLE fh;

    fh = (HANDLE)_get_osfhandle(fd);
    memset(&o, 0, sizeof(o));

    switch(oper) {
		case LOCK_SH:		/* shared lock */
			LK_ERR(LockFileEx(fh, 0, 0, LK_LEN, 0, &o),i);
		break;
		case LOCK_EX:		/* exclusive lock */
			LK_ERR(LockFileEx(fh, LOCKFILE_EXCLUSIVE_LOCK, 0, LK_LEN, 0, &o),i);
		break;
		case LOCK_SH|LOCK_NB:	/* non-blocking shared lock */
			LK_ERR(LockFileEx(fh, LOCKFILE_FAIL_IMMEDIATELY, 0, LK_LEN, 0, &o),i);
		break;
		case LOCK_EX|LOCK_NB:	/* non-blocking exclusive lock */
			LK_ERR(LockFileEx(fh,LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,0, LK_LEN, 0, &o),i);
		break;
		case LOCK_UN:		/* unlock lock */
			LK_ERR(UnlockFileEx(fh, 0, LK_LEN, 0, &o),i);
		break;
		default:			/* unknown */
			//errno = EINVAL; // i heard that on some versions errno is a function (win32 MT lib?)
		break;
    }
    return i;
}

#undef LK_ERR
#undef LK_LEN