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
 * -- client handler functions
 *
 */


#include "client.h"
#include "outstream.h"
#include "clientinfo.h"

int WEBTIMEOUT=10000;

/*********************************************************************************************************/
/*
 * initializate (allocate) client list
 */
struct web_client *__ILWS_init_client_list() {
	struct web_client *ret;
	ret=__ILWS_malloc(sizeof(struct web_client));
	if(ret==NULL) {
		return NULL;
	};
#ifdef HAVE_OPENSSL
	ret->ssl=NULL; // ssl handler for this client
#endif
	ret->next=NULL;
	return ret;
}


/*********************************************************************************************************/
/*
 * Add a client node to client list
 */
int __ILWS_add_client(struct web_client *list, struct web_client *node) {
	struct web_client *temp=list;

#ifdef WIN32
	unsigned long t=IOC_INOUT;
#endif
	while(temp->next!=NULL)temp=temp->next; // run to last client
	temp->next=node;
	temp->next->rbuf=NULL;
	temp->next->rbufsize=0;

	if(!(temp->next->outstream=__ILWS_init_outstream_list())) {
		return 0;
	};
	if(!(temp->next->varlist=__ILWS_init_var_list())) {
		return 0;
	};
	
	temp->next->contentlength=0;
	temp->next->headersize=0;

	temp->next->wheadersize=0;
	temp->next->writelength=0;
	temp->next->readsize=0;
	temp->next->range=0;
	temp->next->skipped=0;
	temp->next->cookies=NULL;
	//temp->next->oldcl=clock();
	

	temp->next->newdata_try=0;
#ifdef WIN32
	// should be optional
	ioctlsocket(temp->next->socket,FIONBIO,&t);  //non blocking sockets for win32
#else
	fcntl(temp->next->socket,F_SETFL,O_NONBLOCK);
#endif
	temp->next->next=NULL;
	temp->next->HTTPdirective=NULL;
	temp->next->stat=1; // Add a connected client
	
	return 1;
}
/*********************************************************************************************************/



/*********************************************************************************************************/
/*
 * Delete client node 
 */
void __ILWS_delete_client(struct web_client *node) {
	int rt;
	rt=shutdown(node->socket,SHUT_RDWR);
#ifdef WIN32
	rt=closesocket(node->socket); 
#else
	rt=close(node->socket); 
#endif
	__ILWS_free(node->cookies); // (0.5.1)
	__ILWS_delete_outstream_list(node->outstream);
	__ILWS_delete_var_list(node->varlist);
#ifdef HAVE_OPENSSL
	SSL_free (node->ssl);
#endif
	__ILWS_free(node->rbuf); // free's
	__ILWS_free(node);       // free's
	
}


/*********************************************************************************************************/
/*
 * Delete next client node 
 */
void __ILWS_delete_next_client(struct web_client *node) {
	struct web_client *temp=node->next;
	node->next=node->next->next;
	__ILWS_delete_client(temp);
}

/*********************************************************************************************************/
/*
 * Delete entire client list
 */
void __ILWS_delete_client_list(struct web_client *node) {
	struct web_client *next;
	
	while(node) {
		next = node->next;
		__ILWS_free(node);
		node = next;
	}
}

/*********************************************************************************************************/
/* 
 * Read what client have to say
 */
void __ILWS_read_client(struct web_client *node) {
	int tmp,tmp1;
	char *tmp2,*tmp3=NULL;
	char readtemp[READMAX+1];
	unsigned long datasize=0;	

#ifdef HAVE_OPENSSL
	if(node->ssl!=NULL) {	
		tmp=SSL_read(node->ssl,readtemp,READMAX);		
	} else {
		tmp=__ILWS_read(node->socket,readtemp,READMAX);
	};
#else
	tmp=__ILWS_read(node->socket,readtemp,READMAX);
#endif
	//fprintf(stderr,"readed %d bytes\n",tmp);
	if(tmp<1) {
	
#ifdef WIN32
		if(WSAGetLastError()!=WSAEWOULDBLOCK) { 
#else			
		if(errno!=EAGAIN) { 
#endif
			node->stat=5;return;
		
		};
		//fprintf(stderr,"try: %d (%s)\n",node->newdata_try,node->rbuf);
		// check if it is over
		node->newdata_try++;
		//fprintf(stderr,"node->newdata_try:%d\n",node->newdata_try);
		if(node->rbufsize >0) {  //&& node->newdata_try>5) { 
			if(node->headersize==0) { // always reachs "\r\n\r\n"
				if((tmp3=strstr(node->rbuf,"\r\n\r\n"))) {
					node->headersize=(tmp3-node->rbuf);
				};
			} else {
				datasize=node->rbufsize-node->headersize;
				if(node->contentlength==0) { // well if it 0 read all at once
				  __ILWS_init_clientinfo(); // always call this?
					node->contentlength=atol(ClientInfo->Header("Content-Length"));
					// range for resuming
					if((tmp3=strstr(ClientInfo->Header("Range"),"bytes="))) { // if it is in bytes (i hope, always)
						tmp3+=6; // go to end of "bytes="
						node->range=atol(tmp3);
						//printf("Range is %d - %s - %s\n",node->range,ClientInfo->Header("Range"),tmp3);
					};
					// end range
					__ILWS_free_clientinfo();
				};
				if(node->contentlength==datasize-4) {
					//fprintf(stderr,"client (%d) all readed (%d) (try's)-%d\n",node->socket,node->curcl-node->oldcl,node->newdata_try); 
					node->newdata_try=WEBTIMEOUT; // assume done reading
					//fprintf(stderr,"Ended naturaly\n");
					
				}
			};
			if((node->newdata_try>=WEBTIMEOUT)) { // All readed
				node->rbuf[node->rbufsize]='\0';
				node->stat=2; // Next state
				//fprintf(stderr,"%s\n",node->rbuf);
				//fprintf(stderr,"%d\n",node->rbufsize);
			}
		};	
	}else {
		tmp1=node->rbufsize;
		node->rbufsize+=tmp;
		tmp2=__ILWS_realloc(node->rbuf,node->rbufsize+1);
		if(tmp2==NULL) {
			node->stat=5;
			
			return;
		}else {
			node->rbuf=tmp2;
		};
		memcpy(node->rbuf+tmp1,readtemp,tmp);
		node->newdata_try=0;
	};
}


/*********************************************************************************************************/
/*
 * Process headers w/ get handlers
 */
void __ILWS_process_client(struct web_client *node,struct gethandler *list) {
	struct gethandler *gettemp=list;
	long secs=time(NULL);
// for determining content length
#define RTMPMAX 400	
	struct outstream *tmpstream; // new on 0.5.1
	char rtmp[RTMPMAX+1];
	int rtmps=0;
	char *thead=NULL;
	char *tmpl;
///
	int tmp=0;
	int oumask=0; // old usermask
	char *tmp1=__ILWS_web_client_getreq();
	char matchbuf[MATCHMAX];	
	FILE *nfile;  // new file
	char *fname;  // new file name
	
	
	while(gettemp->next!=NULL && tmp==0) {
		gettemp=gettemp->next;
		snprintf(matchbuf,MATCHMAX,"%s",gettemp->str);
		if(!tmp1) {
			__ILWS_web_client_writef(node,"HTTP/1.1 400 Invalid request\r\n");
			__ILWS_web_client_writef(node,"Server: %s\r\n",_libwebserver_version);
			__ILWS_web_client_writef(node,"Date: %s\r\n",__ILWS_date(mktime(gmtime(&secs)),"%a, %d %b %Y %H:%M:%S GMT")); // Date header
			__ILWS_web_client_writef(node,"Content-type: text/html\r\n\r\n<HTML><title>Invalid request</title><body bgcolor=FFFFFF><font size=6>400 Invalid  request</font><BR><BR><small>Yout request doesn't match the requesits to be processed</small><BR><HR><small><i>%s</i></small></body></html>\n\r",_libwebserver_version);                                    
			tmpl=__ILWS_web_client_getreqline();
			web_log("%s - - [%s] \"%s\" 400 (invalid request)\n",inet_ntoa(node->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),tmpl); 
			__ILWS_free(tmpl);
			node->stat=5;
			return;
		};
		if(strlen(tmp1)>MAXURLSIZE) {
			__ILWS_web_client_writef(node,"HTTP/1.1 414 URL to large\r\n");
			__ILWS_web_client_writef(node,"Server: %s\r\n",_libwebserver_version);
			__ILWS_web_client_writef(node,"Date: %s\r\n",__ILWS_date(mktime(gmtime(&secs)),"%a, %d %b %Y %H:%M:%S GMT")); // Date header
			__ILWS_web_client_writef(node,"Content-type: text/html\r\n\r\n<HTML><title>URL to large</title><body bgcolor=FFFFFF><font size=6>414 Requested url to large</font><BR><BR><small>Wonder this... why is that so large?</small><BR><HR><small><i>%s</i></small></body></html>\n\r",_libwebserver_version);                                    
			tmpl=__ILWS_web_client_getreqline();
			web_log("%s - - [%s] \"%s\" 414 (url to large)\n",inet_ntoa(node->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),tmpl); 
			__ILWS_free(tmpl);
			node->stat=5;
			__ILWS_free(tmp1);
			return;
		};
		if(!fnmatch(matchbuf,tmp1,5)) {
			if((gettemp->flag & WS_LOCAL) == WS_LOCAL) {
				if(node->sa.sin_addr.s_addr!=0x0100007F) {
					__ILWS_web_client_writef(node,"HTTP/1.1 403 Forbidden\r\n");
					__ILWS_web_client_writef(node,"Server: %s\r\n",_libwebserver_version);
					__ILWS_web_client_writef(node,"Date: %s\r\n",__ILWS_date(mktime(gmtime(&secs)),"%a, %d %b %Y %H:%M:%S GMT")); // Date header
					__ILWS_web_client_writef(node,"Content-type: text/html\r\n\r\n<HTML><title>Forbidden</title><body bgcolor=FFFFFF><font size=6>403 Forbidden</font><BR><BR><small>only local host accepted</small><BR><HR><small><i>%s</i></small></body></html>\n\r",_libwebserver_version);
					tmpl=__ILWS_web_client_getreqline();
					web_log("%s - - [%s] \"%s\" 403 (Forbidden)\n",inet_ntoa(node->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),tmpl); 
					__ILWS_free(tmpl);
					node->stat=5;
					__ILWS_free(tmp1);
					return;
				};
			};                        
			tmp=1; // Was found
			node->outstream->flags=(gettemp->flag & WS_DYNVAR); // pass to outstreams
		};	
	};	
	__ILWS_free(tmp1);
	if(!tmp) { // Nothing found
		__ILWS_web_client_writef(node,"HTTP/1.1 404 Not Found\r\n");
		__ILWS_web_client_writef(node,"Server: %s\r\n",_libwebserver_version);
		__ILWS_web_client_writef(node,"Date: %s\r\n",__ILWS_date(mktime(gmtime(&secs)),"%a, %d %b %Y %H:%M:%S GMT")); // Date header
		__ILWS_web_client_writef(node,"Content-type: text/html\r\n\r\n<HTML><title>not found</title><body bgcolor=FFFFFF><font size=6>404 NOT FOUND</font><BR><BR><small>The requested content wasn't found</small><BR><HR><small><i>%s</i></small></body></html>\n\r",_libwebserver_version);                                    
		tmpl=__ILWS_web_client_getreqline();
		web_log("%s - - [%s] \"%s\" 404 (Not Found)\n",inet_ntoa(node->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),tmpl); 
		__ILWS_free(tmpl);
		node->stat=5;
	}else {
		
		// if cgi do something else, present headers
		oumask=umask(077);
		if(!(fname=__ILWS_tmpfname())) {
			libws_error(LE_FILESYS,": Error giving a temp filename\n");
			node->stat=5;
			return;
		};
		if((nfile=freopen(fname,"wb+",stdout))!=NULL) {
			flock(fileno(stdout),LOCK_EX);
			tmp=dup(fileno(stdout));
			nfile=fdopen(tmp,"wb+");
			if(!__ILWS_add_outstream(node->outstream,fname,nfile,1)) {
				node->stat=5; // (delete client)
				return; // ERROR reported by add_outstream
				
			};
// THE PROCESS
			
			// Setup Clientinfo before running function
			if(gettemp->type==GH_FUNCTION) {
				__ILWS_init_clientinfo();	 
				gettemp->hdl.func(); // changed (0.5.3) Access by named union (Hilobok Andrew (han@km.if.ua) said that wasn't compile on freeBSD)
				__ILWS_free_clientinfo();        
			};
			// new on 0.5.2
			if(gettemp->type==GH_DIRECTORY) { // as builtin function for directory listing
				__ILWS_init_clientinfo();
				if(strcmp(gettemp->str,"* /*"))ClientInfo->request+=1;  // skip '/' if not equal to "* /*" (used by default)
				__ILWS_lws_list(gettemp->hdl.path); // changed (0.5.3) Access by named union (Hilobok Andrew (han@km.if.ua) said that wasn't compile on freeBSD)
				__ILWS_free_clientinfo();
			};
			
			fflush(stdout);
			fclose(stdout); // it is a tempfile freopened 
			__ILWS_free(fname); // doesn't need anymore
#ifdef WIN32			
			freopen("con","w",stdout);
#else
			freopen("/dev/tty","w",stdout);
#endif
			if((gettemp->flag & WS_USELEN) == WS_USELEN) {
// determine writelength (for content-length: header) (new on 0.5.1)
				tmpstream=node->outstream;
				tmp=0;
				while(tmpstream->next!=NULL) { // end of header probably in the firsts outstream nodes check for that
					if(tmpstream->next->fname!=NULL) {
						if(tmpstream->next->fstream==NULL) {
							nfile=fopen(tmpstream->next->fname,"rb");
							tmpstream->next->fstream=nfile; // here (corrected on 0.5.3);
						} else {
							fflush(tmpstream->next->fstream); // <- flush tha thing
							nfile=tmpstream->next->fstream;
							fseek(nfile,0,SEEK_SET);
						};
						if(nfile!=NULL) {
							rtmps=0;
							while((!node->wheadersize) && (!feof(nfile))) { // wheadersize is 0, suposed to be fast, at least if is not malformed
								if(rtmps>0)	{tmp-=4;fseek(nfile,rtmps-4,SEEK_SET);}
								if((rtmps=fread(rtmp,1,RTMPMAX,nfile))>0) {
									rtmp[rtmps]=0;
									if((tmp1=strstr(rtmp,"\r\n\r\n"))) {
										node->wheadersize=(tmp+((tmp1+4)-rtmp));
										rtmps=((tmp1+4)-rtmp);
										
									}; 
									if(node->range>0) {
										tmp1=realloc(thead,tmp+rtmps+1);
										thead=tmp1;
										memcpy(thead+tmp,rtmp,rtmps);
										thead[tmp+rtmps]=0;
									};
									tmp+=rtmps;
								};
							};
							fseek(nfile,SEEK_END,SEEK_END);
							node->writelength+=(ftell(nfile)-2);
							//fclose(nfile); // <- don't worry they close the file later
						};
					};
					tmpstream=tmpstream->next;
					
				};
// end writelength
			} else {
				node->range=0; // no content-range
			};
			
			if(node->range>node->writelength-node->wheadersize && node->range>0) {
				__ILWS_web_client_writef(node,"HTTP/1.1 416 Requested Range Not Satisfiable\r\n");
				__ILWS_web_client_writef(node,"Server: %s\r\n",_libwebserver_version);
				__ILWS_web_client_writef(node,"Date: %s\r\n",__ILWS_date(mktime(gmtime(&secs)),"%a, %d %b %Y %H:%M:%S GMT")); // Date header
				__ILWS_web_client_writef(node,"Content-range: bytes */%d\r\n",node->writelength-node->wheadersize);
				__ILWS_web_client_writef(node,"Content-type: text/html\r\n\r\n<HTML><title>Requested Range Not Satisfiable</title><body bgcolor=FFFFFF><font size=6>416 Requested Range Not Satisfiable</font><BR><BR><small>You're trying to resume an content that is smaller than the requested range</small><BR><HR><small><i>%s</i></small></body></html>\n\r",_libwebserver_version);                                    
				tmpl=__ILWS_web_client_getreqline();
				web_log("%s - - [%s] \"%s\" 416 (Requested Range Not Satisfiable)\n",inet_ntoa(node->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),tmpl); 
				__ILWS_free(tmpl);
				node->stat=5;
				__ILWS_free(thead);
				umask(oumask);
				return;
			};
			if(node->range>0 && ((node->outstream->flags & WS_DYNVAR)==WS_DYNVAR)) { // if request range interval and dynvar on than produces not implemented
				__ILWS_web_client_writef(node,"HTTP/1.1 501 Not Implemented\r\n");
				__ILWS_web_client_writef(node,"Server: %s\r\n",_libwebserver_version);
				__ILWS_web_client_writef(node,"Date: %s\r\n",__ILWS_date(mktime(gmtime(&secs)),"%a, %d %b %Y %H:%M:%S GMT")); // Date header
				__ILWS_web_client_writef(node,"Content-type: text/html\r\n\r\n<HTML><title>Not implemented</title><body bgcolor=FFFFFF><font size=6>501 Not implemented</font><BR><BR><small>Your trying to resume an content that is not possible to resume(WS_DYNVAR fault)</small><BR><HR><small><i>%s</i></small></body></html>\n\r",_libwebserver_version);                                    
				tmpl=__ILWS_web_client_getreqline();
				web_log("%s - - [%s] \"%s\" 501 (Not Implemented)\n",inet_ntoa(node->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),tmpl); 
				__ILWS_free(tmpl);
				node->stat=5;
				__ILWS_free(thead);
				umask(oumask);
				return;
			};

		}
		node->stat=4;   
		if(node->HTTPdirective==NULL) {
			if(node->range>0) {
				__ILWS_web_client_writef(node,"HTTP/1.1 206 Partial Content\r\n");
				tmpl=__ILWS_web_client_getreqline();
				web_log("%s - - [%s] \"%s\" 206 (Partial Content)\n",inet_ntoa(node->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),tmpl); 
				__ILWS_free(tmpl);
			} else {
				__ILWS_web_client_writef(node,"HTTP/1.1 200 OK\r\n");
				tmpl=__ILWS_web_client_getreqline();
				web_log("%s - - [%s] \"%s\" 200 (OK)\n",inet_ntoa(node->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),tmpl); 
				__ILWS_free(tmpl);
			};

		} else {
			__ILWS_web_client_writef(node,"%s\r\n",node->HTTPdirective);
			tmpl=__ILWS_web_client_getreqline();
			web_log("%s - - [%s] \"%s\" XXX (User defined)\n",inet_ntoa(node->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),tmpl); 
			__ILWS_free(tmpl);
		};
		__ILWS_web_client_writef(node,"Server: %s\r\n",_libwebserver_version);
		__ILWS_web_client_writef(node,"Date: %s\r\n",__ILWS_date(mktime(gmtime(&secs)),"%a, %d %b %Y %H:%M:%S GMT")); // Date header
		__ILWS_web_client_writef(node,"Accept-Ranges: bytes\r\n");
		if((((node->writelength-node->wheadersize)-node->range)>0) && !((node->outstream->flags & WS_DYNVAR)==WS_DYNVAR))__ILWS_web_client_writef(node,"Content-length: %d\r\n",(node->writelength-node->wheadersize)-node->range);
		if(node->cookies!=NULL)__ILWS_web_client_writef(node,"%s",node->cookies); // new (0.5.1)
		if(node->range>0) {
			__ILWS_web_client_writef(node,"Content-range: bytes %d-%d/%d\r\n",node->range,(node->writelength-node->wheadersize)-1,node->writelength-node->wheadersize);
			__ILWS_web_client_writef(node,"%s",thead); // the rest of header
			__ILWS_free(thead);
		};
		umask(oumask);
		
	};

}
/*********************************************************************************************************/
/*
 * Process stream output
 */
void __ILWS_output_client(struct web_client *node) {
	struct outstream *tstream=node->outstream;
	char *tmp1,*tmp2,*tmp3;
	char writetemp[WRITEMAX+1];
	int beginsize=0;
	int endsize=0;
	int varsize=0;
	int namesize=0;
	if(tstream->next!=NULL) {
		if(tstream->next->fname!=NULL) {
			if(tstream->next->fstream==NULL) {
				if((tstream->next->fstream=fopen(tstream->next->fname,"rb"))==NULL) {
					__ILWS_delete_next_outstream(tstream);
					//node->outstream->next=tstream->next;
					return;
				} 
			};

			// read part (must always read)
			if(tstream->next->rsize==0) {  // start from 0
				fseek(tstream->next->fstream,0,SEEK_SET); 
			};
			memset(writetemp,0,WRITEMAX);
			tstream->next->rsize=fread(writetemp,1,WRITEMAX,tstream->next->fstream);
			writetemp[tstream->next->rsize]=0;
			// if read make var changes on writetemp;
			// new on 0.5.1  -- UNDERDEV                               // FIX -
			if((node->outstream->flags & WS_DYNVAR) == WS_DYNVAR) {
				
				tmp1=writetemp;
				while(((tmp1=strstr(tmp1,"$")+1)!=(char*)1) && beginsize==0) {   // check var found
					for(namesize=0;namesize<50;namesize++) {
						if(tmp1[namesize]==';') {namesize++;break;}
						if((tmp1[namesize]<'a' || tmp1[namesize]>'z') && 
						   (tmp1[namesize]<'A' || tmp1[namesize]>'Z') &&
						   (tmp1[namesize]<'1' || tmp1[namesize]>'0') &&
						   tmp1[namesize]!='_') {namesize=0;break;};
						
					};
					if(namesize>0) {
						if(namesize==1) { // this is $; for sure
							if(!(tmp3=__ILWS_malloc(2))) {
								node->stat=5;
								return;
							};
							memcpy(tmp3,"$",namesize);
							tmp3[namesize]=0;
						} else {
							if(!(tmp3=__ILWS_malloc(namesize))) {
								node->stat=5;
								return;
							};
							memcpy(tmp3,tmp1,namesize-1);
							tmp3[namesize-1]=0;
						};
						
						tmp1-=1;
						
						beginsize=tmp1-writetemp;
						tmp1+=namesize;  // get var from whateverwhere (client node probably)
												
						endsize=strlen(tmp1);	
						
						//varsize=2;
												
						if((tmp2=__ILWS_malloc(beginsize+1))) {
							memcpy(tmp2,writetemp,beginsize);
							tmp2[beginsize]=0;
							if(namesize==1) {
								varsize=strlen(tmp3);
								snprintf(writetemp,WRITEMAX,"%s%s",tmp2,tmp3);
							} else {
								varsize=strlen(__ILWS_get_var(node->varlist,tmp3));
								snprintf(writetemp,WRITEMAX,"%s%s",tmp2,__ILWS_get_var(node->varlist,tmp3));
							};
							writetemp[strlen(tmp2)+varsize]=0;
							__ILWS_free(tmp2);
							__ILWS_free(tmp3);
							tstream->next->rsize=(beginsize+varsize);
							tstream->next->varsize+=(varsize-namesize)-1;
						} else {
							__ILWS_free(tmp3);
							node->stat=5;
							return;
						};
					};
				};
			}; // dynvar 

			/* there is nothing more to read here */
			if(tstream->next->rsize<1){ // i guess rsize < 1 is eof (make sure that server writed last time)
				//only change if everything written
				if(feof(tstream->next->fstream) && (ftell(tstream->next->fstream)==tstream->next->wrotesize)) {
					//fclose(tstream->next->fstream);
					
					__ILWS_delete_next_outstream(tstream);
					//node->outstream->next=tstream->next; 
				}
				return;
			}
			node->readsize+=tstream->next->rsize;						
			if(!node->skipped && node->range>0) {
				tstream->next->wsize=tstream->next->rsize;
				tstream->next->wrotesize+=tstream->next->wsize;	
				if((node->readsize-node->wheadersize)<node->range) { // skip range bytes
					return; // do nothing
				}else {
					node->skipped=1;
					tstream->next->wrotesize-=(node->readsize-node->wheadersize)-node->range; // the right offset
					fseek(tstream->next->fstream,tstream->next->wrotesize,SEEK_SET);
					tstream->next->wsize=tstream->next->rsize;
					return;
				};
			};
			// write part

#ifdef HAVE_OPENSSL
			if(node->ssl!=NULL) {
				tstream->next->wsize=SSL_write(node->ssl,writetemp,tstream->next->rsize);
			} else {
				tstream->next->wsize=send(node->socket,writetemp,tstream->next->rsize,0);
			};
#else		
			tstream->next->wsize=send(node->socket,writetemp,tstream->next->rsize,0);
#endif
			if(tstream->next->wsize>0) {
				tstream->next->wrotesize+=tstream->next->wsize;	
				if(tstream->next->rsize!=tstream->next->wsize || beginsize>0) {	                     // FIX
					fseek(tstream->next->fstream,tstream->next->wrotesize-(tstream->next->varsize),SEEK_SET);       // FIX
				};
			};
#ifdef WIN32
			if((tstream->next->wsize<=0) && (WSAGetLastError()!=WSAEWOULDBLOCK)) {  // WIN32 only 
#else
			if(tstream->next->wsize<=0 && errno!=EAGAIN) {  // linux only // *nix i guess
#endif			
				//fclose(tstream->next->fstream);
				
				__ILWS_delete_next_outstream(tstream);
				//node->outstream->next=tstream->next; 
				return;
			}else { // broken pipe
				if(tstream->next->wsize<0) {
					fseek(tstream->next->fstream,tstream->next->wrotesize-(tstream->next->varsize),SEEK_SET);       //didn't read must back to where it was
				 };
			};
			
		}else { // filename is null
			
			__ILWS_delete_next_outstream(tstream);
			return;
		};
	}else { // End of streams
		
		current_web_client->stat=5; // done

	};
}

/*********************************************************************************************************/
/*
 * Set http directive
 */
void web_client_HTTPdirective(char *str) { 
	current_web_client->HTTPdirective=str;
}


/*********************************************************************************************************/
/*
 * GET request name
 */
char *__ILWS_web_client_getreq() {
	char *ret;
	char *tmp1=strstr(current_web_client->rbuf,"?");
	char *tmp2=strstr(current_web_client->rbuf," HTTP");
	char *tmp3=strstr(current_web_client->rbuf,"\r\n");
	int size;
	if(tmp1==NULL || tmp1>tmp2) {
		tmp1=tmp2;
	};
	if(tmp2>tmp3) {
		return NULL;
	};
	size=tmp1-current_web_client->rbuf;
	if(size<1) return NULL;
	
	if(!(ret=__ILWS_malloc(size+1))) {
		return NULL;
	};
	memcpy(ret,current_web_client->rbuf,size);
	ret[size]=0;
	return ret;

};

/*********************************************************************************************************/
/*
 * GET request line
 */
char *__ILWS_web_client_getreqline() {
	char *ret;
	char *tmp1=strstr(current_web_client->rbuf,"\r\n");
	int size=0;
	if(tmp1==NULL) return NULL;
	size=tmp1-current_web_client->rbuf;
	if(size<1) return NULL;
	
	if(!(ret=__ILWS_malloc(size+1))) {
		return NULL;
	};
	memcpy(ret,current_web_client->rbuf,size);
	ret[size]=0;
	return ret;
}


/*********************************************************************************************************/
/*
 * Add a FILE stream type to client output
 */
int web_client_addfile(char *in) {  
	int ret=__ILWS_add_outstream(current_web_client->outstream,in,NULL,0);
	int nfd=0;
	char *fname;
	FILE *nfile=NULL;
	fname=__ILWS_tmpfname();
	fflush(stdout);
	fclose(stdout); // oldstdout close it?

	if((nfile=freopen(fname,"w+b",stdout))!=NULL){ // redirect
		flock(fileno(stdout),LOCK_EX); // <- yah
		nfd=dup(fileno(stdout));
		nfile=fdopen(nfd,"wb+");
		if(!__ILWS_add_outstream(current_web_client->outstream,fname,nfile,1)) {
			return 0;
		};
	};
	__ILWS_free(fname);
	ClientInfo->outfd=fileno(nfile); 
	return ret;
}


/*********************************************************************************************************/
/*
 * Output data as gif (with width w and height h)
 */
unsigned char __ILWS_GLOBALGIFPAL[256][3];


void web_client_gifsetpalette(const char *fname) {
	int j;
	FILE *palfile;
	if(strcmp(fname,"EGA")==0) {
		static int EGApalette[16][3] = {
				{0,0,0},       {0,0,128},     {0,128,0},     {0,128,128}, 
				{128,0,0},     {128,0,128},   {128,128,0},   {200,200,200},
				{100,100,100}, {100,100,255}, {100,255,100}, {100,255,255},
				{255,100,100}, {255,100,255}, {255,255,100}, {255,255,255} };
		for (j=0; j<256; j++) {
			__ILWS_GLOBALGIFPAL[j][0] = (unsigned char)EGApalette[j&15][0];
			__ILWS_GLOBALGIFPAL[j][1] = (unsigned char)EGApalette[j&15][1];
			__ILWS_GLOBALGIFPAL[j][2] = (unsigned char)EGApalette[j&15][2];
		}
	} else {
		if(!(palfile=fopen(fname,"rb"))) {
			return;
		};
		fread(__ILWS_GLOBALGIFPAL,sizeof(__ILWS_GLOBALGIFPAL),1,palfile);
		fclose(palfile);
	};
};

int web_client_gifoutput(char *data,int w,int h,int transparencyindex) {
	int i;
	unsigned char rm[256],gm[256],bm[256];
	for(i=0;i<256;i++) {
		rm[i]=__ILWS_GLOBALGIFPAL[i][0];
		gm[i]=__ILWS_GLOBALGIFPAL[i][1];
		bm[i]=__ILWS_GLOBALGIFPAL[i][2];
	};
	
	i=__ILWS_WriteGIF(stdout,data,w,h,rm,gm,bm,256,0,transparencyindex,"libwebserver export gif (xvgifwr.c)");
	
	return i;
};            


/*********************************************************************************************************/
/*
 * an util to write with format on client_nodes
 */
void __ILWS_web_client_writef(struct web_client *node,const char *fmt,...) {
	va_list args;
	char buf[WRITEMAX];
	va_start(args,fmt);
	vsnprintf(buf,512,fmt,args);
	va_end(args);
	
#ifdef HAVE_OPENSSL        
	if(node->ssl!=NULL) {
		SSL_write(node->ssl,buf,strlen(buf));
	} else {
		send(node->socket,buf,strlen(buf),0);   
	};
#else
	send(node->socket,buf,strlen(buf),0);
#endif
}


/*********************************************************************************************************/
/* 
 * function "web_client_setcookie"  (improved on 0.5.1) to be called what ever were over handler function
 *
 *  name = Name of the cookie
 *  value = Value of the cookie
 *  timeout = Timeout in second from current time on
 *            (0 = Until end of session)
 *            (-1 = Delete cookie)
 *  path = Subset of URLs in a domain for which the cookie is valid
 *         (If the path is not specified (path == NULL), it as assumed to be
 *          the same path as the document being described by the header which
 *          contains the cookie.)
 *  domain = Domain the cookie is valid for
 *           (If the domain is not set (domain == NULL), the default value of
 *            domain is the host name of the server which generated the cookie
 *            response.)
 *  secure = If a cookie is marked secure (secure == 1), it will only be
 *           transmitted if the communications channel with the host is a
 *           secure one. Currently this means that secure cookies will only be
 *           sent to HTTPS (HTTP over SSL) servers.
 *           (If secure is not specified (secure == 0), a cookie is considered
 *            safe to be sent in the clear over unsecured channels. )
 */
void web_client_setcookie(char *name, char *value, char *timeoutf, char *path, char *domain, int secure) {
	char *tmp1=timeoutf;
	long toffset=0;
	time_t secs; // to time offset
	int timeout;
	int offset=(current_web_client->cookies!=NULL)?strlen(current_web_client->cookies):0;
	if(timeoutf==NULL) {
		timeout=0;
	} else if (!strcmp(timeoutf,"DEL")){
		timeout=-1;
	} else {
		while(*tmp1) {
			if(*tmp1=='S')toffset=1;             // seconds        
			if(*tmp1=='M')toffset=60;            // minutes
			if(*tmp1=='H')toffset=60*60;         // hours
			if(*tmp1=='d')toffset=60*60*24;      // days
			if(*tmp1=='m')toffset=60*60*24*30;   // Month
			if(*tmp1=='y')toffset=60*60*24*365;  // years
			tmp1++;
		};
		timeout=atoi(timeoutf)*toffset;
	};
	
	if (timeout < 0){
		current_web_client->cookies=__ILWS_realloc(current_web_client->cookies,offset+59+strlen(name));
		snprintf(current_web_client->cookies+offset,59+strlen(name),"Set-Cookie: %s=deleted; expires=%s", name,	__ILWS_date(time(NULL)-31536001,"%a, %d-%b-%Y %H:%M:%S GMT"));
		offset+=59+strlen(name);
	}else{
		current_web_client->cookies=__ILWS_realloc(current_web_client->cookies,offset+14+strlen(name)+strlen(value));
		snprintf(current_web_client->cookies+offset,14+strlen(name)+strlen(value),"Set-Cookie: %s=%s", name, value);
		offset+=13+strlen(name)+strlen(value);
		
		if (timeout != 0){
			//timeout += timezone; Hilobok Andrew (han@km.if.ua) removed this and use gmtime (thanks)
			// exchanged by mktime(gmtime(&secs))
			current_web_client->cookies=__ILWS_realloc(current_web_client->cookies,offset+40);
			secs=time(NULL);
			snprintf(current_web_client->cookies+offset,40,"; expires=%s", __ILWS_date(mktime(gmtime(&secs))+timeout,"%a, %d-%b-%Y %H:%M:%S GMT"));
			offset+=39;
		}
		if (path != NULL && *path!=0) {
			current_web_client->cookies=__ILWS_realloc(current_web_client->cookies,offset+8+strlen(path));
			snprintf(current_web_client->cookies+offset,8+strlen(path),"; path=%s", path);	
			offset+=7+strlen(path);
		}
		if (domain != NULL && *domain!=0){
			current_web_client->cookies=__ILWS_realloc(current_web_client->cookies,offset+10+strlen(domain));
			snprintf(current_web_client->cookies+offset,10+strlen(domain),"; domain=%s", domain);
			offset+=9+strlen(domain);
		};
		if (secure == 1) {
			current_web_client->cookies=__ILWS_realloc(current_web_client->cookies,offset+9);
			snprintf(current_web_client->cookies+offset,9,"; secure");
			offset+=8;
		};
	}
	
	current_web_client->cookies=__ILWS_realloc(current_web_client->cookies,offset+3);
	snprintf(current_web_client->cookies+offset,3,"\r\n"); // '\0' included
	offset+=2;
	// fprintf(stderr,"current_web_client->cookies=\"%s\"\n",current_web_client->cookies); // DEBUG TO REMOVE
	
	
}




/* 
 * function "web_client_deletecookie"
 *
 *  name = Name of the cookie to delete
 */
 
void web_client_deletecookie(char *name){
	web_client_setcookie(name, NULL, "DEL", NULL, NULL, 0);
}








int web_client_setvar(char *name,char *value) {
	return __ILWS_add_var(current_web_client->varlist,name,value);
};
char *web_client_getvar(char *name) {
	return __ILWS_get_var(current_web_client->varlist,name);
	
};
int web_client_delvar(char *name) {
	return __ILWS_del_var(current_web_client->varlist,name);
	
};


/***************
 * variables
 ***************/


// prepare this to work in another file var.c
struct web_var *__ILWS_init_var_list() {
	struct web_var *ret;
	if(!(ret=__ILWS_malloc(sizeof(struct web_var)))) {
		return NULL;
	};
	ret->name=NULL;
	ret->value=NULL;
	ret->next=NULL;
	return ret;
};

int __ILWS_add_var(struct web_var *list, char *name, char *value) {
	struct web_var *node=list;
	int namesize=strlen(name);
	int valuesize=strlen(value);
	while(node->next!=NULL) {
		if(!strcmp(node->next->name,name)) {
			return 0;
		};
		node=node->next;
	};
	
	if(!(node->next=__ILWS_malloc(sizeof(struct web_var)))) {
		return 0;
	};
	
	if(!(node->next->name=__ILWS_malloc(namesize+1))) {
		return 0;
	};
	memcpy(node->next->name,name,namesize);
	node->next->name[namesize]=0;

	if(!(node->next->value=__ILWS_malloc(valuesize+1))) {
		return 0;
	};
	memcpy(node->next->value,value,valuesize);
	node->next->value[valuesize]=0;
	node->next->next=NULL;  
	return 1;
};

int __ILWS_del_var(struct web_var *list, char *name) {
	struct web_var *node=list;
	struct web_var *tmp;
	while(node->next!=NULL) {
		if(!strcmp(node->next->name,name)) {
			tmp=node->next;
			node->next=node->next->next;
			__ILWS_free(tmp->name);
			__ILWS_free(tmp->value);
			__ILWS_free(tmp);
			return 1;
		};
	};
	return 0;
};			
void __ILWS_delete_var_list(struct web_var *list) {
	struct web_var *node=list;
	struct web_var *tmp;
	
	while(node->next!=NULL) {
		tmp=node->next;
		node->next=node->next->next;
		__ILWS_free(tmp->name);
		__ILWS_free(tmp->value);
		
		__ILWS_free(tmp);
	};
	__ILWS_free(node);
};


char *__ILWS_get_var(struct web_var *list , char *name) {
	struct web_var *node=list;
	while(node->next!=NULL) {
		if(!strcmp(node->next->name,name)) {
			return node->next->value;
		};
		node=node->next;
	};
	return "";
};


/****************************
 *  give mime by ext (mime file declared on server)
 */

void web_client_contenttype(char *ext) {
	FILE *mimefileh;
	char *mimedata;
	char *mimeline;
	size_t extsize;
	size_t mimesize;
	char *tmp;
    /* -- mime */
	int isok=0;
	size_t i;
	
	if(ext==NULL || current_web_server->mimefile==NULL) {
		printf("Content-type: text/plain\r\n\r\n"); // <- mime type, change this calculating mime with extension		
	} else {
		extsize=strlen(ext);
		if((mimefileh=fopen(current_web_server->mimefile,"r"))) {
			// retrieve file size
			fseek(mimefileh,SEEK_END,SEEK_END);
			mimesize=ftell(mimefileh);
			fseek(mimefileh,0,SEEK_SET);
			//
			// malloc and read data
			mimedata=__ILWS_malloc(mimesize+1);
			fread(mimedata,1,mimesize,mimefileh);
			fclose(mimefileh); // close file 
			//
			for(i=0;i<mimesize;i++)if(mimedata[i]=='\t')mimedata[i]=' '; // translate \t to 1 space
			mimedata[mimesize]=0;

			isok=0;
			mimeline=strtok(mimedata,"\n");
			while((mimeline=strtok(NULL,"\n")) && !isok) {
				if(mimeline[0]!='#') { // is not a comment
					tmp=mimeline;
					while((tmp=strstr(tmp,ext)) && !isok) {
						//fprintf(stderr,"extsize(%d),found in %s (%s) %x\n",extsize,mimeline,tmp,tmp[extsize]);
						if(tmp[-1]==' ' && (tmp[extsize]==' ' || tmp[extsize]=='\0') ) { 
							if((tmp=strchr(mimeline,' '))) { // the first space?
								tmp[0]='\0';
								//fprintf(stderr,"content is: %s\n",mimeline);
								printf("Content-type: %s\r\n\r\n",mimeline);
								isok=1;
							};
						};
						tmp+=extsize;
					};
					
				};
			};
			if(!isok) {
				printf("Content-type: text/plain\r\n\r\n");
			};
			//printf("%s\n",tmp);
			__ILWS_free(mimedata);
			
		};
	};
};


/**********************************
 * internal directory generator
 */

int __ILWS_lws_list(char *inpath) {
	/* for type directory */
	/* mime*/
	char *ext;
	struct dirent *dire;
	DIR *cd;
	struct stat cfstat;
	char *dirpath=NULL;
	char *filepath;
	char *tmp;
	char *readfile;
	float filesize;
	char filesizeu;
	////
	
	
	//printf("ClientInfo->request=<B>%s</B><BR>\n",ClientInfo->request);
	//readfile=__ILWS_malloc(strlen(ClientInfo->request)+1);
	readfile=ClientInfo->request;
	while((tmp=strstr(readfile,"./"))) { // this skip ../ also
		readfile=tmp+1;
	};
	while((tmp=strstr(readfile,"//"))) {
		readfile=tmp+1;
	};
	
	tmp=strstr(readfile,"/"); 
	if(tmp!=NULL) {
		readfile=tmp+1; // must be in the first
	};
	// skip beind dir
	if(strlen(readfile)) {
		filepath=__ILWS_malloc(strlen(inpath)+strlen(readfile)+3);
		snprintf(filepath,strlen(inpath)+strlen(readfile)+2,"%s%s%s",inpath,(inpath[strlen(inpath)-1]=='/')?"":"/",readfile);
		//printf("pum ->%s<BR>\n",filepath);
		if(readfile[strlen(readfile)-1]=='/') {
			dirpath=__ILWS_malloc(strlen(filepath)+1);
			memcpy(dirpath,filepath,strlen(filepath)+1); // the 0 included
		} else {
			if(!stat(filepath,&cfstat)) { // file must exist
				if((cfstat.st_mode & S_IFDIR) != S_IFDIR) {
				// search for mime
					ext=strrchr(filepath,'.');
					tmp=strrchr(filepath,'/');
					ext+=1;
					if(ext<=tmp) { // is not a extension
						ext=NULL;
					};
					
					//Wed, 22 Oct 2003 16:04:04 GMT
					printf("Last-Modified: %s\r\n",__ILWS_date(mktime(gmtime(&cfstat.st_mtime)),"%a, %d %b %Y %H:%M:%S GMT")); // new on 0.5.3
					web_client_contenttype(ext);
					web_client_addfile(filepath); // fopen and write, maybe?
					__ILWS_free(filepath);
					return 1;
				} else {
					web_client_HTTPdirective("HTTP/1.1 404 File Not Found");
					printf("Content-type: text/html\r\n\r\n<HTML><title>file not found</title><body bgcolor=FFFFFF><font size=6>404 FILE NOT FOUND</font><BR><BR><small>The request \"%s\" wasn't found, try this <a href='%s/'>link</a></small><BR><HR><small><i>%s</i></small></body></html>\n\r",filepath,ClientInfo->request,_libwebserver_version); 
					__ILWS_free(filepath);
					return 0;
				};
			}else {
				web_client_HTTPdirective("HTTP/1.1 404 File Not Found");
				printf("Content-type: text/html\r\n\r\n<HTML><title>file not found</title><body bgcolor=FFFFFF><font size=6>404 FILE NOT FOUND</font><BR><BR><small>The request \"%s\" wasn't found</small><BR><HR><small><i>%s</i></small></body></html>\n\r",filepath,_libwebserver_version); 
				__ILWS_free(filepath);
				return 0;
			};
		};
		__ILWS_free(filepath);
	};
	//printf("Content-type: text/html\r\n\r\n");
	//fprintf(stderr,"dirpath=%s inpath=%s\n",dirpath,inpath);
	if(dirpath==NULL) {
		dirpath=__ILWS_malloc(strlen(inpath)+1);
		memcpy(dirpath,inpath,strlen(inpath)+1);
	};
	cd=opendir(dirpath);
	if(cd!=NULL) {
		printf("Content-type: text/html\r\n\r\n");
		printf("<HTML><HEAD><TITLE>Contents of %s</TITLE></HEAD><BODY>\n",dirpath);
		printf("<h1>Contents of directory %s</h1><HR>\n",dirpath);
		printf("<form><input type=text name=match value=\"%s\"><input type=submit name='send' value='wildcard'></form>\n",strlen(ClientInfo->Query("match"))?ClientInfo->Query("match"):"*");
		printf("<PRE>\n");
		while((dire=readdir(cd))) {
			if( ((dire->d_name[0]!='.') || (strcmp(dirpath,inpath) && !strcmp(dire->d_name,".."))) && (!fnmatch(ClientInfo->Query("match"),dire->d_name,0) || !strlen(ClientInfo->Query("match"))) ) {
				filepath=__ILWS_malloc(strlen(dirpath)+strlen(dire->d_name)+2);
				snprintf(filepath,strlen(dirpath)+strlen(dire->d_name)+2,"%s%s%s",dirpath,(dirpath[strlen(dirpath)-1]=='/')?"":"/",dire->d_name);
				//fprintf(stderr,"filename=%s\n",filepath);
				if(!stat(filepath,&cfstat)) {
						if((cfstat.st_mode & S_IFDIR) == S_IFDIR) {
						printf("%s	&lt;DIR&gt;	<a href=\"%s/\">%s</a>\n",__ILWS_date(cfstat.st_mtime,"%a, %d %b %Y %H:%M"),dire->d_name,dire->d_name);
					}else {
						filesize=(float)cfstat.st_size;
						filesizeu=0;
						while(filesize>1024) {
							filesize/=1024;
							filesizeu++;
						};
						printf("%s	%.1f%c	<a href=\"%s\">%s</a>\n",__ILWS_date(cfstat.st_mtime,"%a, %d %b %Y %H:%M"),filesize,(filesizeu==2)?'M':(filesizeu==1)?'K':'b',dire->d_name,dire->d_name);
					};
				};
				__ILWS_free(filepath);
			};
		
		};
		printf("</PRE>\n");				
		printf("<HR>\n");
		printf("<address>%s</address>\n",_libwebserver_version);
		printf("</BODY></HTML>\r\n");
		__ILWS_free(dirpath);
		closedir(cd);
	} else {
		web_client_HTTPdirective("HTTP/1.1 404 File Not Found");
		printf("Content-type: text/html\r\n\r\n<HTML><title>file not found</title><body bgcolor=FFFFFF><font size=6>404 FILE NOT FOUND</font><BR><BR><small>The request \"%s\" wasn't found</small><BR><HR><small><i>%s</i></small></body></html>\n\r",dirpath,_libwebserver_version); 
		return 0;
	};
	return 1;
};




