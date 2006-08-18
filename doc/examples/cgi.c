/* by Luis Figueiredo (stdio@netc.pt)
 *
 * This is only a example if you intend to use this, please
 * make this secure (checking file exec permissions etc.etc.)
 */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "web_server.h"
#include "debug.h"



extern struct web_client *current_web_client;
int PORT=80;

extern char **environ;
void cgi() {
	char *reqfile=ClientInfo->request+1; // Skip '/'
	char *tmp;
	FILE *instream;
	int stdo;
	int ret;
	int pid;
	int outp;
	if(!(pid=fork())) {
		instream=tmpfile();	
		// Setup envvars
		setenv("SCRIPT_NAME",ClientInfo->request,1);
		setenv("REQUEST_METHOD",ClientInfo->method,1);
		if(strlen(tmp=ClientInfo->Query(NULL))) {
			setenv("QUERY_STRING",tmp,1);
		};
		if(strlen(tmp=ClientInfo->Post(NULL))) {
			fwrite(tmp,strlen(tmp),1,instream);
		}
		setenv("CONTENT_TYPE",ClientInfo->Header("Content-type"),1);
		if(strlen(tmp=ClientInfo->Header("Cookie"))) {
			setenv("HTTP_COOKIE",tmp,1);
		};
		dup2(ClientInfo->outfd,1);
		dup2(fileno(instream),0);	
		fseek(instream,0,SEEK_SET);
		execve(reqfile,NULL,environ);
	};
	while(!(ret=waitpid(pid,&ret,0)))fprintf(stderr,"ret-%d\n",ret);;

};
void index_() {
	DIR *dir;
	struct dirent *dire;
	dir=opendir("cgi-bin");
	printf("Content-type: text/html\r\n\r\n");
	printf("<HTML>\n");
	printf("<BODY bgcolor='EFEFEF'>\n");
	printf("Browse /cgi-bin/*<BR>\n");
	while(dire=readdir(dir)) {
		if(dire->d_name[0]!='.') {
			if((int)(strstr(dire->d_name,".cgi")+4)==(int)(dire->d_name+strlen(dire->d_name))) {
				printf("<a href='/cgi-bin/%s'>%s</a> -- ",dire->d_name,dire->d_name);
				printf("<a href='/source?src=/cgi-bin/%s'>(see source)</a><BR>",dire->d_name,dire->d_name);
			};
		};
	};
	closedir(dir);
};
void source() {
	char *tmp=ClientInfo->Query("src");
	char *tmp1;	
	/* security */	
	while((tmp1=strstr(tmp,"../"))) {
		tmp=tmp1+3;
	};
	while((tmp1=strstr(tmp,"//"))) {
		tmp=tmp1+2;
	};
	tmp1=strstr(tmp,"/");
	if(tmp1==tmp) {
		tmp=tmp1+1;
	};
	/* security */	
	printf("Content-type: text/plain\r\n\r\n");
	web_client_addfile(tmp);
};
main() {
	struct web_server server;

	while(!web_server_init(&server,PORT,"cgi.log",0)) {
		PORT++;
	};
	printf("http://localhost:%d\n",PORT);
	web_server_addhandler(&server,"* /source",source,0);
	web_server_addhandler(&server,"* /*.cgi",cgi,0);
	web_server_addhandler(&server,"* /",index_,0);
	while(1) {
		web_server_run(&server);
	};
};
