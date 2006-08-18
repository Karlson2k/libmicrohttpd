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
 * -- description: utilitys
 *
 */

#include "utils.h"

/*********************************************************************************************************/
/* 
 * search a string in a string ignoring case
 */
char *__ILWS_stristr(char *str, const char *nedle) {
	char *tmp1=str;
	int ret=1;
	int snedle=strlen(nedle),sstr=strlen(str);
	if(strlen(str)<strlen(nedle))return NULL;
	while((ret=strncasecmp(tmp1,nedle,snedle) && (unsigned int)(tmp1+snedle)<=(unsigned int) (str+sstr))) {
		tmp1++;
	};
	if(strncasecmp(tmp1,nedle,snedle))
		return NULL;
	return tmp1;
};

/*********************************************************************************************************/
/* 
 * gives a new temporary path(file) name that doesn't exists
 */
char *_tmpnameprefix="";

char *__ILWS_tmpfname() {
	char *ret=NULL;
	char *tmpdir=NULL;
	char nam[TMPNAMESIZE+1];
	int i;
	struct stat foostat;
	if(tmpdir==NULL) {
		tmpdir=getenv("TEMP");
	};
	if(tmpdir==NULL) {
		tmpdir=getenv("TMP");
	};
	if(tmpdir==NULL) {
		tmpdir=getenv("TMPDIR");
	};
	if(tmpdir==NULL) {
		tmpdir=P_tmpdir;  // defined in stdio.h
	};
	IFDEBUG(fprintf(stderr,"utils.c: Allocating temporary file name: "));
	if(!(ret=__ILWS_malloc(strlen(tmpdir)+strlen(_tmpnameprefix)+TMPNAMESIZE+2))) {
		LWSERR(LE_MEMORY);
		return NULL;
	};
	srand(time(NULL)); // seed
	do {
		for(i=0;i<TMPNAMESIZE;i++) {
			
			nam[i]=(rand()%2)?(rand()%26)+'A':(rand()%26)+'a';
		}
		nam[i]=0;
		snprintf(ret,strlen(tmpdir)+strlen(_tmpnameprefix)+TMPNAMESIZE+2,"%s/%s%s",tmpdir,_tmpnameprefix,nam); // include '0'
		IFDEBUG(fprintf(stderr,"Temporary filename is: %s, stat:%d\n",ret,stat(ret,&foostat)));
	}while((stat(ret,&foostat)!=-1) && (lstat(ret,&foostat)!=-1)); // redundancy if win32 // <- race condition?
	return ret;
};



/*********************************************************************************************************/
/*
 * an date function
 */
#define DATE_MAX 100
char __ILWS_datem[DATE_MAX];

char *__ILWS_date(time_t t,const char *format) {
	struct tm *tm;
	tm=localtime(&t);
	strftime(__ILWS_datem,DATE_MAX,format,tm);
	return __ILWS_datem;
}                    

/*********************************************************************************************************/
/* 
 * wasn't me, base64decode
 */
static const unsigned char __ILWS_chtb[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};          


int __ILWS_base64decode(char *bufplain, const char *bufcoded){
    int nb;
    const unsigned char *in;
    unsigned char *out;
    int nprbytes;
 
    in = (const unsigned char *) bufcoded;
    while (__ILWS_chtb[*(in++)] <= 63);
    nprbytes = (in - (const unsigned char *) bufcoded) - 1;
    nb = ((nprbytes + 3) / 4) * 3;
 
    out = (unsigned char *) bufplain;
    in = (const unsigned char *) bufcoded;
 
    while (nprbytes > 4) {
        *(out++) =
            (unsigned char) (__ILWS_chtb[*in] << 2 | __ILWS_chtb[in[1]] >> 4);
        *(out++) =
            (unsigned char) (__ILWS_chtb[in[1]] << 4 | __ILWS_chtb[in[2]] >> 2);
        *(out++) =
            (unsigned char) (__ILWS_chtb[in[2]] << 6 | __ILWS_chtb[in[3]]);
        in += 4;
        nprbytes -= 4;
    }
    if (nprbytes > 1) {
        *(out++) =
            (unsigned char) (__ILWS_chtb[*in] << 2 | __ILWS_chtb[in[1]] >> 4);
    }
    if (nprbytes > 2) {
        *(out++) =
            (unsigned char) (__ILWS_chtb[in[1]] << 4 | __ILWS_chtb[in[2]] >> 2);
    }
    if (nprbytes > 3) {
        *(out++) =
            (unsigned char) (__ILWS_chtb[in[2]] << 6 | __ILWS_chtb[in[3]]);
    }
 
    nb -= (4 - nprbytes) & 3;
    return nb;
}                                        

