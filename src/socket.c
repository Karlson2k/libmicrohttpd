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
 * -- Basic socket operations
 *
 */


#include "socket.h"


/*********************************************************************************************************/
/*
 * socket operations
 */
int __ILWS_newdata(int sock) {
	int ret;
	struct timeval tv;
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET((unsigned)sock,&rfds);
	tv.tv_usec=2;
	tv.tv_sec=0;
	ret=select(sock+1,&rfds,NULL,NULL,&tv);
	FD_CLR((unsigned)sock,&rfds);
	return ret;
}                                                                                                                             

/*********************************************************************************************************/
/*
 * to add a listen socket
 */
int __ILWS_listensocket(short port, int saddr) {
	struct sockaddr_in sa;
	int ret;
	int sockopt=1; /* Rocco Was Here */
	sa.sin_addr.s_addr=saddr;
	sa.sin_port=htons((short)port);
	sa.sin_family=AF_INET;
	ret=socket(AF_INET,SOCK_STREAM,6); // tcp
	if(ret==-1) {
		return -1;
	};
	/* Rocco Was Here */
	setsockopt(ret,SOL_SOCKET,SO_REUSEADDR,(char *)&sockopt,sizeof(sockopt));  // why? Rocco

	if(bind(ret,(struct sockaddr *)&sa,sizeof(sa))==-1) {
		close(ret); /* Rocco Was Here */
		return -1;
	};

	if(listen(ret,512)==-1) { // 512 backlog 
		close(ret); /* Rocco Was Here */
		return -1;
	};
	IFDEBUG(fprintf(stderr,"socket.c: Listen on port %d\n",port));
	return ret;
}

/*********************************************************************************************************/
/*
 * as the read function
 */
int __ILWS_read(int sock,void *buf,size_t s) {
	return recv(sock,buf,s,0); 
}

