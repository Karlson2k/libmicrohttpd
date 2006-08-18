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
 * -- core server functions
 *
 */

#include "server.h"
#include "logo.h"

#ifdef WIN32
	#define _SERVER_VERSION "libwebserver/0.5.3(win32)" // update allways when changing version (damn win)
#endif

#ifndef _SERVER_VERSION
	#define _SERVER_VERSION "libwebserver/(unknow)"
#endif

#ifdef DEBUG
	char *_libwebserver_version= _SERVER_VERSION "(debug)";
#else
	char *_libwebserver_version= _SERVER_VERSION;
#endif

struct web_server *current_web_server;


/*********************************************************************************************************/
/*
 *	Define certificate file (open_ssl)
 */
void web_server_useSSLcert(struct web_server *server,const char *file) {
#ifdef HAVE_OPENSSL
	if(!(server->cert_file=__ILWS_malloc(strlen(file)+1))) {
		LWSERR(LE_MEMORY);
		return;
	};
	memcpy(server->cert_file,file,strlen(file));
	server->cert_file[strlen(file)]=0;
#else
	printf("OpenSSL not supported in this compilation\n");
#endif
}

void web_server_useMIMEfile(struct web_server *server,const char *file) {
	if(!(server->mimefile=__ILWS_malloc(strlen(file)+1))) {
		LWSERR(LE_MEMORY);
		return;
	};
	memcpy(server->mimefile,file,strlen(file));
	server->mimefile[strlen(file)]=0;
};
/*********************************************************************************************************/
/*
 *  Handler for libwebserver logotipe
 */
void _web_server_logo() {
	printf("Content-type: image/gif\r\n\r\n");
	fwrite((char *)_logo,sizeof(_logo),1,stdout);
}        


/*********************************************************************************************************/
/*
 * Add an handler to request data
 */
int web_server_addhandler(struct web_server *server,const char *mstr,void (*func)(),int flag) {
	_logfile=server->weblog;
	// xor?
	flag ^= (server->flags & WS_LOCAL); // global flag to handler flag
	flag ^= (server->flags & WS_DYNVAR); // global flag to handler flag
	flag ^= (server->flags & WS_USELEN); // global flag to handler flag
	web_log("[%s] Adding handler %s <--%s%s%s\n",__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),mstr, ((flag & WS_LOCAL) == WS_LOCAL && !((server->flags & WS_LOCAL) == WS_LOCAL))?"[LOCAL] ":"", ((flag & WS_DYNVAR) == WS_DYNVAR)?"[DYNVAR]":"", ((flag & WS_USELEN) == WS_USELEN)?"[USELEN]":"");
	return __ILWS_add_handler((struct gethandler *)server->gethandler,mstr,func,NULL,flag,GH_FUNCTION);
}

/*********************************************************************************************************/
/*
 * Add an alias dir (new on 0.5.2)
 */
int web_server_aliasdir(struct web_server *server, const char *str, char *path,int flag) {
	char *mstr;
	int ret;
	mstr=__ILWS_malloc(strlen(str)+7);
	if(!strlen(str)) {
		snprintf(mstr,strlen(str)+7,"* /*");
	} else {
		snprintf(mstr,strlen(str)+7,"* /%s/*",str);
	};
	_logfile=server->weblog;
	flag ^= (server->flags & WS_LOCAL); // global flag to handler flag
	flag ^= (server->flags & WS_DYNVAR); // global flag to handler flag
	flag ^= (server->flags & WS_USELEN); // global flag to handler flag
	web_log("[%s] Adding directory %s <--%s%s%s\n",__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),mstr, ((flag & WS_LOCAL) == WS_LOCAL && !((server->flags & WS_LOCAL) == WS_LOCAL))?"[LOCAL] ":"", ((flag & WS_DYNVAR) == WS_DYNVAR)?"[DYNVAR]":"", ((flag & WS_USELEN) == WS_USELEN)?"[USELEN]":"");
	ret=__ILWS_add_handler((struct gethandler *)server->gethandler,mstr,NULL,path,flag,GH_DIRECTORY);
	__ILWS_free(mstr);
	return ret;
};


/*********************************************************************************************************/
/*
 *	Personal config (new on 0.5.0)
 */
char *web_server_getconf(struct web_server *server, const char *topic,const char *key) {
	char *dataconf;
	char *tmp1,*tmp2,*tmp3;
	long tmpsize=0;

	dataconf=__ILWS_stristr(server->dataconf,topic);
	if(dataconf==NULL) {
		return NULL;
	};
	dataconf+=strlen(topic);
	tmp1=__ILWS_stristr(dataconf,key);
	do {
		tmp1=__ILWS_stristr(dataconf,key);
		dataconf+=1;
		if(dataconf[0]==0) { 
			return NULL;
		};
		if(dataconf[0]=='[' && dataconf[-1]=='\n') { 
			return NULL;
		};
	}while(!(tmp1!=NULL && tmp1[-1]=='\n' && tmp1[strlen(key)]=='='));
	
	tmp1+=strlen(key)+1;
	tmp2=__ILWS_stristr(tmp1,"\n");
	if(tmp2==NULL) {
		tmp2=tmp1+strlen(tmp1);
	};
	tmpsize=tmp2-tmp1;
	if(!(tmp3=__ILWS_malloc(tmpsize+1))) {
		LWSERR(LE_MEMORY);
		return NULL;
	};
	memcpy(tmp3,tmp1,tmpsize);
	tmp3[tmpsize]=0;
	return tmp3;
};

/*********************************************************************************************************/
/*
 *	Define config file to setup server (new on 0.5.0)
 */
int web_server_setup(struct web_server *server,const char *conffile) {
	FILE *tmpf;
	char *tmp3;
	//long tmpsize=0;
	long sizec;
	struct stat statf; // tested only on win

	if(!(server->conffile=__ILWS_malloc(strlen(conffile)+1))) {
		LWSERR(LE_MEMORY);
		return 0;
	};

	memcpy(server->conffile,conffile,strlen(conffile));
	server->conffile[strlen(conffile)]=0;
	
	tmpf=fopen(server->conffile,"r");
	if(tmpf==NULL) {
		printf("no config file found\r\n");
		server->dataconf="";
		return(0);
	};
	fseek(tmpf,SEEK_SET,SEEK_END);
	sizec=ftell(tmpf);
	fseek(tmpf,0,SEEK_SET);
	if(!(server->dataconf=__ILWS_malloc(sizec+1))) {
		LWSERR(LE_MEMORY);
		return 0;
	};
	fread(server->dataconf,sizec,1,tmpf);
	server->dataconf[sizec]=0; // Hilobok Andrew (han@km.if.ua) said to remove the -9 :)
	fclose(tmpf);
	
	stat(server->conffile,&statf); // tested only on win
	server->conffiletime=statf.st_mtime; // tested only on win

	if((server->logfile=web_server_getconf(server,"LIBWEBSERVER","LOG"))) {
		web_log("\nUsing logfile [%s]\n",server->logfile);
		server->weblog=open_weblog(server->logfile);
	} else {
		web_log("\nLOG entry not found\r\n");
		server->weblog=NULL;
	};
	if((tmp3=web_server_getconf(server,"LIBWEBSERVER","PORT"))) {
		web_log("\nListen port [%s]\n",tmp3);
		server->port=atoi(tmp3);
		__ILWS_free(tmp3);
	} else {
		web_log("PORT entry not found\r\n");
		server->port=0;
	};
#ifdef HAVE_OPENSSL
	// Fetch SSL
	if((tmp3=web_server_getconf(server,"LIBWEBSERVER","USESSL"))) {
		if(tmp3[0]=='1') {
			server->flags = server->flags | WS_USESSL;
		}else if(tmp3[0]=='0') {
			server->flags = server->flags & ~WS_USESSL;
		} else {
			fprintf(stderr,"[USESSL=] argument invalid\n");
		};
		__ILWS_free(tmp3);
	} 
	// Fetch CERTFILE
	server->cert_file=web_server_getconf(server,"LIBWEBSERVER","CERTFILE");
	server->mimefile=web_server_getconf(server,"LIBWEBSERVER","MIMEFILE");
#endif
	// Fetch LOCAL
	if((tmp3=web_server_getconf(server,"LIBWEBSERVER","LOCAL"))) {
		if(tmp3[0]=='1') {
			server->flags = server->flags | WS_LOCAL;
		} else if(tmp3[0]=='0') {
			server->flags=server->flags & ~WS_LOCAL;
		}else {
			fprintf(stderr,"[LOCAL=] argument invalid\n");
		};
		__ILWS_free(tmp3);
	} 
	
	return 1;
};

/*********************************************************************************************************/
/*
 * This function initialize one web_server handler
 */
int web_server_init(struct web_server *server,int port,const char *logfile,int flags) {
#ifdef WIN32	
	unsigned long t=IOC_INOUT;
	WSADATA WSAinfo;
	WSAStartup(2,&WSAinfo); // Damn w32 sockets
#endif

	current_web_server=server;
	server->port=port;
	server->conffile=NULL;
	server->mimefile=NULL;
	server->weblog=NULL;
	server->usessl=0;
	server->flags=flags;
	server->dataconf="";
	if((flags & WS_USEEXTCONF) == WS_USEEXTCONF) {
		if(!(web_server_setup(server,logfile))) {
#ifdef WIN32		
			WSACleanup();
#endif
			return 0;
		};
		_logfile=server->weblog; // Set current log stream
		web_log("%s using config file %s\n",_libwebserver_version,logfile);
	};
	// Create a listen socket port 'port' and listen addr (0) (all interfaces)
	server->socket=__ILWS_listensocket((short)server->port,0);	
	if(server->socket==-1) {
		LWSERR(LE_NET);
#ifdef WIN32		
		WSACleanup();
#endif
		return 0;
	};
#ifdef WIN32
	ioctlsocket(server->socket,FIONBIO,&t);  //non blocking sockets for win32
#else
	fcntl(server->socket,F_SETFL,O_NONBLOCK);
#endif
	// Setup FILE structure of logfile
	if(logfile!=NULL && !((flags & WS_USEEXTCONF) == WS_USEEXTCONF)) {
		server->logfile=__ILWS_malloc(strlen(logfile)+1);
		memcpy(server->logfile,logfile,strlen(logfile));
		server->logfile[strlen(logfile)]=0;
		server->weblog=open_weblog(logfile); // Create File stream for log
	};
	
	web_log("\n[%s] Server started at port %d (%s)\n",__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"),server->port,_libwebserver_version);
	
	// Setup Flags
	
	// openssl
#ifdef HAVE_OPENSSL	
	if((server->flags & WS_USESSL) == WS_USESSL) {
		web_log("[%s] (FLAG) Using SSL in connections\n",__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"));	
		web_log("                       +-- %s certificate file\n",server->cert_file);
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms(); 	
		server->ctx=SSL_CTX_new (SSLv23_server_method());
		if (SSL_CTX_use_certificate_file(server->ctx, server->cert_file, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(3);
		}
		if (SSL_CTX_use_PrivateKey_file(server->ctx, server->cert_file, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(4);
		}                      
	 	if (SSL_CTX_check_private_key(server->ctx)<= 0)  	 {
			ERR_print_errors_fp(stderr);
			exit(4);
		};
		server->usessl=1;
	};
#endif
	if((server->flags & WS_LOCAL) == WS_LOCAL) {
		web_log("[%s] (FLAG) Accepting only local connections\n",__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z"));	
	};
	server->client=__ILWS_init_client_list();										// Initializate client list
	server->gethandler=__ILWS_init_handler_list();									// Initializate handlers list
	web_server_addhandler(server,"* /libwebserver.gif",_web_server_logo,0);	// Add logo default handler

#ifndef WIN32	
	signal(SIGPIPE,SIG_IGN);
#endif
	return 1;
}                            


/*********************************************************************************************************/
/*
 * This function shuts down a running web server, frees its allocated memory,
 * and closes its socket. If called on a struct web_server that has already
 * been shut down, this is a noop.
 */
void web_server_shutdown(struct web_server *server) {
	// free and close things in opposite order of web_server_init
	
	__ILWS_delete_handler_list(server->gethandler);
	server->gethandler = NULL;
	__ILWS_delete_client_list(server->client);
	server->client = NULL;
	
	if(server->socket > 0) {
#ifdef WIN32
		closesocket(server->socket);
#else
		close(server->socket);
#endif
		server->socket = -1;
	}
	
	if(server->weblog) {
		fclose(server->weblog);
		server->weblog = NULL;
		__ILWS_free(server->logfile);
		server->logfile = NULL;
	}
	
#ifdef WIN32
	WSACleanup();
#endif
}

/*********************************************************************************************************/
/*
 * Core function, return 2 if no client to process, 1 if some client processed, 0 if error
 */
int web_server_run(struct web_server *server) {
	struct web_client *client;
	int rt;
	int tsalen=0;
	int tsocket=0;
	struct sockaddr_in tsa;
	_logfile=server->weblog;
	current_web_server=server;
	if(server->client->next==NULL) {
		//if(__ILWS_newdata(server->socket)); // does nothing but act like usleep 
	};
// search for client		
	tsalen=sizeof(client->sa);
	tsocket=accept(server->socket,(struct sockaddr *)&tsa,&tsalen);
	if(tsocket==-1) {
#ifdef WIN32
		if(WSAGetLastError()!=WSAEWOULDBLOCK) { 
#else			
		if(errno!=EAGAIN) { 
#endif
			fprintf(stderr,"What kind of error is this?\n"); // REMOVE
			// client fucked up? warn somebody? (error or log or something?)
			return 0; // don't process nothing
		};
	} else {
		client=__ILWS_malloc(sizeof(struct web_client));
		if(client==NULL) {
			rt=shutdown(tsocket,SHUT_RDWR);
#ifdef WIN32
			rt=closesocket(tsocket); 
#else
			rt=close(tsocket); 
#endif
			LWSERR(LE_MEMORY);
			return 0;
		};
		client->salen=tsalen;
		client->socket=tsocket;
		client->sa=tsa;
#ifdef HAVE_OPENSSL
		if((server->flags & WS_USESSL) == WS_USESSL) {
			client->ssl = SSL_new(server->ctx);
			SSL_set_fd(client->ssl,client->socket);
			SSL_accept(client->ssl);
		//client->cert = SSL_get_peer_certificate (client->ssl);
		} else {
			client->ssl=NULL;
		};
#endif
		if(!__ILWS_add_client(server->client,client)) {
			fprintf(stderr,"No client?\n"); // REMOVE
			return 0;
		}else {
			web_log("%s - - [%s] Connected\n",inet_ntoa(client->sa.sin_addr),__ILWS_date(time(NULL),"%d/%b/%Y:%H:%M:%S %z")); //REMOBE			
		};
	};
	// end search for client
	client=server->client; // init list
	if(!client->next) { // think of Rocco Carbone (rocco@tecsiel.it)
		return 2; // i don't need to process the list (nothing next) returns 2 if there is no client to process
	};
	while(client->next!=NULL) { // Process the client and swap to next;
		current_web_client=client->next;
		switch(client->next->stat) {
			case 1: {
				__ILWS_read_client(current_web_client);
			};break;
            case 2: {
				__ILWS_process_client(current_web_client,server->gethandler);
			};break;
			case 4: {
				__ILWS_output_client(current_web_client);	
			};break;
			case 5: {
				__ILWS_delete_next_client(client); 
				continue;
			};break;
		};
		client=client->next;
	
	};   
	return 1;  // return 1 if something processed
}

