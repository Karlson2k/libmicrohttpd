

#include <stdio.h>
#include <stdlib.h>


#include "web_server.h"

int PORT=80;

void index_html() {
	printf("Content-type: text/html\r\n\r\n");
	printf("<HTML>\n");
	printf("<BODY bgcolor='EFEFEF'>\n");
	printf("libwebserver Example<BR><BR>\n");
	printf("Client info structure:<BR><code>\n");	
	printf("struct ClientInfo {<BR>\n &nbsp;&nbsp;&nbsp;int outfd<BR>\n &nbsp;&nbsp;&nbsp;char *inetname<BR>\n &nbsp;&nbsp;&nbsp;char *request<BR>\n &nbsp;&nbsp;&nbsp;char *method<BR>\n &nbsp;&nbsp;&nbsp;char *user<BR>\n &nbsp;&nbsp;&nbsp;char *pass<BR>\n &nbsp;&nbsp;&nbsp;char *QueryData;<BR>\n	&nbsp;&nbsp;&nbsp;struct memrequest *mem;<BR>\n	&nbsp;&nbsp;&nbsp;char *(*Header)(char*);<BR>\n &nbsp;&nbsp;&nbsp;char *(*QueryString)(char*);<BR>\n &nbsp;&nbsp;&nbsp;char *(*Post)(char*);<BR>\n &nbsp;&nbsp;&nbsp;char *(*MultiPart)(char*);<BR>\n };<BR>\n");
	printf("ClientInfo->outfd=%d<BR>\n",ClientInfo->outfd);
	printf("ClientInfo->request=%s<BR>\n",ClientInfo->request);
	printf("ClientInfo->method=%s<BR>\n",ClientInfo->method);
	printf("ClientInfo->Header(\"Host\")=\"%s\"<BR>\n",ClientInfo->Header("Host"));
	printf("ClientInfo->Header(\"Accept\")=\"%s\"<BR>\n",ClientInfo->Header("Accept"));
	printf("ClientInfo->Query(\"teste\")=\"%s\"<BR>\n",ClientInfo->Query("teste"));
	printf("ClientInfo->Query(NULL)=\"%s\"<BR>\n",ClientInfo->Query(NULL));
	printf("ClientInfo->Post(\"dev\")=\"%s\"<BR>\n",ClientInfo->Post("dev"));
	printf("ClientInfo->MultiPart(\"teste\").data=\"%s\"<BR>\n",ClientInfo->MultiPart("teste").data);
	printf("ClientInfo->MultiPart(\"file1\").filename=\"%s\"<BR>\n",ClientInfo->MultiPart("file1").filename);
	printf("ClientInfo->MultiPart(\"file1\").size=\"%d\"<BR>\n",ClientInfo->MultiPart("file1").size);
	printf("ClientInfo->MultiPart(\"file1\").data=\"");
	fwrite(ClientInfo->MultiPart("file1").data,ClientInfo->MultiPart("file1").size,1,stdout);
	printf("\"<BR>\n");
	printf("<form action='/?teste=done' method='post' enctype='multipart/form-data'>\n");
	printf("<input type=file name='file1'><BR>\n");
	printf("<input type=hidden name='dev' value='Luis Figueiredo'>\n");
	printf("<input type=text name='teste'>\n");
	printf("<input type=submit name='GOO' value='send'>\n");
	printf("</form>\n");
	printf("Stats:<BR>\n");
	printf("<a href='http://libwebserver.sourceforge.net'><img border='0' src='/libwebserver.gif'></a><br>\n");
	printf("</BODY>\n");
	printf("</HTML>\n");
};

void logfile() {
	FILE *log;
	printf("Content-type: text/plain \r\n\r\n");
	web_client_addfile("./demo.log");
	printf("Fim do log\n");
};

int main() {
	int pid;
	struct web_server server;
	while(!web_server_init(&server,PORT,"demo.log",0)) {
		PORT++;	
	};
	printf("http://localhost:%d\n",PORT);	
	web_server_addhandler(&server,"* /",index_html,0);
	web_server_addhandler(&server,"* /log",logfile,0);
	while(1) {
		// DO whatever u want
		web_server_run(&server); // Process web_server
	};
	return 0;

};
