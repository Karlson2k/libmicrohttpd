#include "web_server.h"

#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <math.h>

#include "info.h"
#include "functions.h"
#include "examples.h"
#include "security.h"

struct web_server server;


#ifdef WIN32
#include <windows.h>
#endif


int PORT=81;


void teste1() {
	printf("Content-type: text/html\r\n\r\n");
	printf("here's location:<BR>\n");
	printf("%s\r\n",ClientInfo->Header("Location"));
	printf("NOTHING=%s\n<BR>",ClientInfo->Conf("[PERSONAL_CONF]","NOTHING"));
	printf("IP=%s\n<BR>",ClientInfo->Conf("[PERSONAL_CONF]","IP"));
	printf("MOST=%s\n<BR>",ClientInfo->Conf("[PERSONAL_CONF]","MOST"));
	printf("IP=%s\n<BR>",ClientInfo->Conf("[LIBWEBSERVER]","IP"));
	printf("Connection: %s\n",ClientInfo->Header("Connection"));
};

void varteste() {
	web_client_setvar("bg",ClientInfo->Conf("PAGE_1","background"));
	web_client_setvar("pata","#00FF00");
	printf("Content-type: text/html\r\n\r\n");
	printf("<HR>\n");
	printf("$;pata;=\"$pata;\"");
	printf("<B>&lt;$pata;BODY bgcolor=\"$pata;\"&gt;</B> $ (prototipe 0.5.1)<BR>\n");
	printf("Luis Figueiredo$pata;coninhas\r\n");
	
};
	
void teste() {
	int i=0;
	
	web_client_setcookie("caos","teste da noia",NULL,NULL,NULL,0);
		
	printf("content-type: text/html\r\n\r\n");
	printf("hal is \"%s\" hallo is \"%s\"<BR>\n",ClientInfo->Post("hal"),ClientInfo->Post("hallo"));
	printf("hal is \"%s\" hallo is \"%s\"<BR>\n",ClientInfo->Post("hal"),ClientInfo->Post("hallo"));
	printf("<form method=post>\n");
	printf("<input type=text name=hal value='%s'>\n",ClientInfo->Cookie("stdio"));
	web_client_setcookie("teste",ClientInfo->Post("hallo"),"+1m",NULL,NULL,0);
	printf("<input type=text name=hallo value='%s'>\n",ClientInfo->Cookie("teste"));
	printf("<input type=submit name=send value='POST'>\n");
	printf("</form>\n");
	
	printf("<form method=query>\n");
	for (i=0;i<5;i++) {
		printf("<input type=checkbox name=teste value='%d'>%d<BR>\n",i,i);
	};
	printf("<input type=submit name=send1 value='SEND'>\n");
	printf("</form>\n");
	printf("You choose: ");
	printf("%d numbers: \n",ClientInfo->Query("#teste"));
	for(i=0;i<(int)ClientInfo->Query("#teste");i++){
		printf("%s,",ClientInfo->Query("teste"));
	};
	web_client_setcookie("quatro","ratata","+1m","/","127.0.0.1",0);
	printf("...<BR>");
	printf("<form method=post>\n");
	for (i=0;i<5;i++) {
		printf("<input type=checkbox name=teste value='%d'>post %d<BR>\n",i,i);
	};
	printf("<input type=submit name=send1 value='SEND'>\n");
	printf("</form>\n");
	printf("You choose: ");
	web_client_setcookie("tres","ratata","+1m",NULL,NULL,0);
	printf("%d numbers: ",ClientInfo->Post("#teste"));
	for (i=0;i<(int)ClientInfo->Post("#teste");i++) {
		printf("%s,",ClientInfo->Post("teste"));
	};
	printf("...<BR>");
	web_client_deletecookie("cinco");
	printf("<form method=query>\n");
	printf("<input type=submit name=test value='pipi'><BR>\n");
	printf("</form>\n");
	printf("The value of test is '%s'<BR>\n",ClientInfo->Query("test"));
	printf("The value of test is '%s'<BR>\n",ClientInfo->Query("test"));
	printf("The value of test is '%s'<BR>\n",ClientInfo->Query("test"));
	printf("ClientInfo->Cookie(\"teste\")='%s'<BR>\n",ClientInfo->Cookie("teste"));
	printf("ClientInfo->Cookie(\"stdio\")='%s'<BR>\n",ClientInfo->Cookie("stdio"));
	printf("ClientInfo->Cookie(\"merdinha\")='%s'<BR>\n",ClientInfo->Cookie("merdinha"));
	printf("ClientInfo->Cookie(\"activo\")='%s'<BR>\n",ClientInfo->Cookie("activo"));
	printf("ClientInfo->Cookie(\"caos\")='%s'<BR>\n",ClientInfo->Cookie("caos"));
	printf("ClientInfo->Cookie(\"caos\")='%s'<BR>\n",ClientInfo->Cookie("caos"));
	printf("Method is %s\n<BR>",ClientInfo->method);
	printf("Inetaddr=%s\n<BR>",ClientInfo->inetname);
	
	for(i=0;i<10;i++) {
		printf("<BR>ClientInfo->Post(\"teste\")='%s'\n",ClientInfo->Post("teste"));
	};
	printf("<BR>ClientInfo->Cookie(NULL)=\"%s\"<BR>",ClientInfo->Cookie(NULL));
	printf("<BR>ClientInfo->Post(NULL)=\"%s\"<BR>",ClientInfo->Post(NULL));
	printf("<BR>ClientInfo->Query(NULL)=\"%s\"<BR>",ClientInfo->Query(NULL));
	printf("<BR>ClientInfo->Query(\"teste 0\")=\"%s\"<BR>",ClientInfo->Query("teste 0"));
	printf("<PRE>ClientInfo->Header(NULL)=\"%s\"</PRE>\r\n",ClientInfo->Header(NULL));
	
};


void links() {
	printf("[<a href='/'>main</a>] [<a href='/?help=info'>info</a>] [<a href='/?help=functions'>functions</a>] [<a href='/?help=examples'>examples</a>] [<a href='/?help=security'>security</a>] [<a href='/?help=Authors'>authors</a>] ");
};

void startpage(char *topic) {
	printf("Content-type: text/html\r\n\r\n");
	printf("<HTML>\n<body bgcolor='EFEFFF'>\n<CENTER>\n<TABLE><TR><TD align=center>\n<a href='http://libwebserver.sourceforge.net'><img border=0 src='/libwebserver.gif'></a>\n</TD><TR><TR><TD align=center>\n<font face='Verdana'><B>HELP<BR>(%s)</B></font>\n</TD></TR></TABLE>\n</CENTER>\n",topic);
	links();	
	printf("<HR><BR>\n");
};
void endpage() {
	printf("<HR>");
	links();	
	printf("<p align=right> <small> by Luis Figueiredo (<a href='mailto:stdio@netc.pt'>stdio@netc.pt</a>) (%s)</BODY></HTML>\n",_libwebserver_version);
};









//Johannes E. Schindelin // new on 0.4.0
void hello_world() {
	startpage("hello world example");
	printf("Hello, World!\r\n");
	endpage();
}
//


// NEW on 0.4.1
void checkbox() {
	int i=0;
	char *txt[]={"one","two","three","four","five"};
	startpage("checkbox example");
	printf("<form method=query>\n");
	for(i=0;i<5;i++) {
		printf("<input type=checkbox name=number value='%s'\n> %s<BR>",txt[i],txt[i]);
	};
	printf("<input type=submit name=send value=' SEND '>\n");
	printf("</form>\n");
	printf("You have choosen <font color='FF0000'>%d</font> numbers: \n",ClientInfo->Query("#number"));
	for(i=0;i<(int)ClientInfo->Query("#number");i++) {
		printf("<b>%s</b>,\n",ClientInfo->Query("number"));
	};
	printf("...<BR>");
	endpage();
};

	

// NEW on 0.4.0
void cookie() {
	if(strlen(ClientInfo->Post("user"))) 
		web_client_setcookie("username",ClientInfo->Post("user"),"+15M",NULL,NULL,0);
	startpage("Cookie example");
	printf("<form method='POST'>\n");
	printf("<input type=text name='user' value='%s'>\r\n<BR>",ClientInfo->Cookie("username"));
	printf("<input type=submit name='send' value=' GO! '><BR>\r\n");
	printf("</form>\n");
	endpage();
};
//

void logfile() {
	startpage("logfile");
	printf("<PRE>\n");
	web_client_addfile(server.logfile);
	printf("</PRE>\n");
	endpage();
};

struct image {
	char *data;
	size_t size;
} image={NULL,0};


void imageout() {
	if(strlen(ClientInfo->Query("img"))) {
		if(image.data!=NULL) {
			printf("Content-type: image/jpeg\r\n\r\n");
			fwrite(image.data,image.size,1,stdout);
		};
		return;
	};

	startpage("Image example");
	printf("<form action='/image' method='POST' enctype='multipart/form-data'>\n");
	printf("<input type=file name=image><BR>\n");
	printf("<input type=submit name='GOO' value='See'>\n");
	printf("</form>\n");
	if(strlen(ClientInfo->MultiPart("image").data)) {
		printf("%s<BR><img src='/image?img=%s.jpg'>\n",ClientInfo->MultiPart("image").filename,ClientInfo->MultiPart("image").filename);
		free(image.data);
		image.data=malloc(ClientInfo->MultiPart("image").size+1);
		memcpy(image.data,ClientInfo->MultiPart("image").data,ClientInfo->MultiPart("image").size);
		image.size=ClientInfo->MultiPart("image").size;
	}else {
		free(image.data);
		image.data=NULL;
	};
	endpage();
};

#define GIFSIDE 320
char gifdata[GIFSIDE*GIFSIDE];
void outgif() {
	float i;
	int x,y,xc,yc;
	char color;
	web_client_gifsetpalette("EGA");
	if(*ClientInfo->Query("img")!=0) {
		printf("Content-type: image/gif\r\n\r\n");
		if(!strcmp(ClientInfo->Query("img"),"circle")) {
			xc=atoi(ClientInfo->Query("x"))%GIFSIDE;
			yc=atoi(ClientInfo->Query("y"))%GIFSIDE;
			color=(char)(rand()%15)+1;
			for(i=0;i<6.28;i+=(float)0.01) {
				x=(int)((GIFSIDE+xc+cos(i)*10))%GIFSIDE; // Johannes E. Schindelin bugfix
				y=(int)((GIFSIDE+yc+sin(i)*10))%GIFSIDE; // Johannes E. Schindelin bugfix
				gifdata[x+(y*GIFSIDE)]=color;
			};
		};
		web_client_gifoutput(gifdata,GIFSIDE,GIFSIDE,0);
	};
	startpage("Gif example");
	printf("<center>Generated a circle (click inside the image)<BR>\n");
	printf("Pressed x=%s,y=%s<BR>\n",ClientInfo->Query("x"),ClientInfo->Query("y"));
	printf("<form><input type=image border=0 src='/gif?img=circle&x=%s&y=%s'></form></CENTER>\n",ClientInfo->Query("x"),ClientInfo->Query("y"));
	endpage();
};


void urlauthenticate() {
	if(!strlen(ClientInfo->user) || !strlen(ClientInfo->pass) &&
		strcmp(ClientInfo->user,"username") || strcmp(ClientInfo->pass,"password")) { // you can read things from a auth file
		web_client_HTTPdirective("HTTP/1.1 401 Authorization Required\r\n"
			"WWW-Authenticate: Basic realm=\"This site info\"");
		startpage("Authenticate example");
		printf("<CENTER><font color='FF0000'>Access denied</font></CENTER>\n");
		endpage();
		return;
	}
	startpage("Authenticate example");
	printf("You entered in your area\n");
	endpage();
};


void help() {
	// info
	// engine  // removed (read the source)
	// functions help
	// functionall examples
	// security
	// regards
	// authors
	if(!strlen(ClientInfo->Query("help"))) {	
		startpage("Table of contents");
		printf("<B>\n");
		printf("<ol>\n");
		printf("<li><a href='/?help=info'>libwebserver info</a></li>\n");
		printf("<ul><li><a href='/?help=info#what'>What's libwebserver for?</a></li></ul>\n");
		printf("<ul><li><a href='/?help=info#who'>Who's supposed to use libwebserver?</a></li></ul>\n"); // Johannes E. Schindelin spellcheck
		printf("<ul><li><a href='/?help=info#when'>When am i supposed to use libwebserver?</a></li></ul>\n"); // Johannes E. Schindelin spellcheck
		printf("<ul><li><a href='/?help=info#server_scripts'>Is there support for server scripts such as .php .cgi .asp?</a></li></ul>\n"); // Johannes E. Schindelin spellcheck
		printf("<li><a href='/?help=functions'>libwebserver functions</a></li>\n");	
		printf("<ul><li><a href='/?help=functions#web_server_init'>web_server_init()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_server_addhandler'>web_server_addhandler()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_server_aliasdir'>web_server_aliasdir()</a><small>(new)</small></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_server_run'>web_server_run()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_server_getconf'>web_server_getconf()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_server_useSSLcert'>web_server_useSSLcert()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_server_useMIMEfile'>web_server_useMIMEfile()</a><small>(new)</small></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_addstream'>web_client_addstream() </a><small><small>(obsolet, no longer in use in 0.3.4) use web_client_addfile instead</small></small></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_addfile'>web_client_addfile()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_gifoutput'>web_client_gifoutput()</a><small>(changed)</small></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_gifsetpalette'>web_client_gifsetpalette()</a><small>(new)</small></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_setcookie'>web_client_setcookie()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_deletecookie'>web_client_deletecookie()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_setvar'>web_client_setvar()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_getvar'>web_client_getvar()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_delvar'>web_client_delvar()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_HTTPdirective'>web_client_HTTPdirective()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_client_contenttype'>web_client_contenttype()</a><small>(new)</small></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#web_log'>web_log()</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#ClientInfo'>ClientInfo</a></li></ul>\n");	
		printf("<ul><li><a href='/?help=functions#configfile'>The config file</a></li></ul>\n");	
		printf("<li><a href='/?help=examples'>libwebserver examples</a></li>\n");
		printf("<ul><li><a href='/?help=examples#helloworld'>Hello, World!</a></li></ul>\n");
		printf("<ul><li><a href='/?help=examples#logfile'>Show's log file</a></li></ul>\n");
		printf("<ul><li><a href='/?help=examples#imageup'>Image Uploader</a></li></ul>\n");
		printf("<ul><li><a href='/?help=examples#auth'>Authentication</a></li></ul>\n");
		printf("<ul><li><a href='/?help=examples#ssl'>Openssl for (https)</a></li></ul>\n");
		printf("<ul><li><a href='/?help=examples#outgif'>Gif generator</a><small>Changed</small></li></ul>\n");
		printf("<ul><li><a href='/?help=examples#cookie'>Cookies</a></li></ul>\n");
		printf("<ul><li><a href='/?help=examples#checkbox'>checkbox</a></li></ul>\n");
		printf("<ul><li><a href='/?help=examples#confexample'>Config example</a></li></ul>\n");
		printf("<ul><li><a href='/brokenlink'>Broken link</a></li></ul>\n");
		printf("<ul><li><a href='/fs/'>aliasdir</a></li></ul>\n");
		printf("<li><a href='/?help=security'>libwebserver security</a></li>\n");
		printf("<ul><li><a href='/?help=security#safe'>It is safe to use?</a></li></ul>\n"); // Johannes E. Schindelin spellcheck
		printf("<ul><li><a href='/?help=security#certificate'>How do I create my own certificate?</a></li></ul>\n"); // Johannes E. Schindelin made
		printf("<ul><li><a href='/?help=security#racecondition'>Avoid race condition problems</a></li></ul>\n"); // Johannes E. Schindelin made
		
		printf("<li><a href='/?help=Authors'>Authors</a></li>\n");
		printf("</ol>\n");
		printf("</B>\n");
		endpage();	
		return;	
	};

	startpage(ClientInfo->Query("help"));
	if(!strcmp(ClientInfo->Query("help"),"info")) {
		fwrite(info,sizeof(info),1,stdout);
		//web_client_addfile("help.html/info.html");
	};
	if(!strcmp(ClientInfo->Query("help"),"security")) {
		fwrite(security,sizeof(security),1,stdout);
		//web_client_addfile("help.html/security.html");
	};
	if(!strcmp(ClientInfo->Query("help"),"functions")) {
		fwrite(functions,sizeof(functions),1,stdout);
		//web_client_addfile("help.html/functions.html");
	};
	if(!strcmp(ClientInfo->Query("help"),"examples")) {
		fwrite(examples,sizeof(examples),1,stdout);
		//web_client_addfile("help.html/examples.html");
	};
	if(!strcmp(ClientInfo->Query("help"),"Authors")) {
		printf("Luis Figueiredo (<a href='mailto:stdio@netc.pt'>stdio@netc.pt</a>) - Main programmer, designer<BR><BR>\n");
		printf("People who contributed:<BR>\n");
		printf("<UL>João Luis Marques (<a href='mailto:Lamego@PTLink.net'>Lamego@PTLink.net</a>)<BR>\n");
		printf("<UL>minor bug reported (redirectors, stdout)</UL></UL>\n");
		printf("<UL>'oddsock' (<a href='mailto:oddsock@oddsock.org'>oddsock@oddsock.org</a>)<BR>\n");
		printf("<UL>Licensing tip, and minor bug reported (segv in querystring)</UL></UL>\n");
		printf("<UL>Rocco Carbone (<a href='mailto:rocco@tecsiel.it'>rocco@tecsiel.it</a>)<BR>\n");
		printf("<UL>Return code for web_server_run tip</UL></UL>\n");
		printf("<UL>Johannes E. Schindelin (<a href='mailto:Johannes.Schindelin@gmx.de'>Johannes.Schindelin@gmx.de</a>)<BR>\n");
		printf("<UL>Spell checking, Makefile portability, and security 'How do I create my own certificate?'<BR>\n");
		printf("bugfixes, example 'hello world!'</UL></UL>\n");
		printf("<UL>Richard Offer (<a href='mailto:offer@sgi.com'>offer@sgi.com</a>)<BR>\n");
		printf("<UL>checkboxes, (multiple variables) tip</UL></UL>\n");
		printf("<UL>Sven Anders (<a href='mailto:anders@anduras.de'>anders@anduras.de</a>)<BR>\n");
		printf("<UL>Created a new web_client_setcookie()(i made some changes)</UL></UL>\n");
		printf("<UL>Hilobok Andrew (<a href='mailto:han@km.if.ua'>han@km.if.ua</a>)<BR>\n");
		printf("<UL>FreeBSD portability</UL></UL>\n");
	};
	endpage();	
};



void confexample() {
	startpage("confexample");
	printf("<PRE>\n");
	web_client_addfile(server.conffile);
	printf("</PRE>\n");
	printf("ClientInfo->Conf(\"PERSONAL_CONF\",\"PORT\")->%s<BR>\n",ClientInfo->Conf("PERSONAL_CONF","PORT"));
	printf("ClientInfo->Conf(\"PERSONAL_CONF\",\"IP\")->%s<BR>\n",ClientInfo->Conf("PERSONAL_CONF","IP"));
	printf("ClientInfo->Conf(\"LIBWEBSERVER\",\"PORT\")->%s<BR>\n",ClientInfo->Conf("LIBWEBSERVER","PORT"));
	endpage();

};





int main() {
	
#ifdef DEBUG	
	//FILE *err=freopen("debug.log","w",stderr);
#endif // DEBUG
	
	memset(gifdata,0,GIFSIDE*GIFSIDE);
	while(!web_server_init(&server,PORT,"help.cfg",WS_USEEXTCONF|WS_USELEN))PORT++;
	web_server_useMIMEfile(&server,"mime.types");

	//web_server_addhandler(&server,"* /",skip,0);
	web_server_addhandler(&server,"* /",help,0);
	web_server_addhandler(&server,"* /teste",teste,WS_LOCAL);
	web_server_addhandler(&server,"* /varteste",varteste,WS_DYNVAR|WS_USELEN);
	web_server_addhandler(&server,"* /teste1",teste1,WS_LOCAL);
	web_server_addhandler(&server,"* /hello",hello_world,0);
	web_server_addhandler(&server,"* /log",logfile,WS_USELEN); // turn off global flag
	web_server_addhandler(&server,"* /image",imageout,0);
	web_server_addhandler(&server,"* /gif",outgif,0);
	web_server_addhandler(&server,"* /auth",urlauthenticate,0);
	web_server_addhandler(&server,"* /cookie",cookie,0);
	web_server_addhandler(&server,"* /checkbox",checkbox,0);
	web_server_addhandler(&server,"* /confexample",confexample,0);
	
	web_server_aliasdir(&server,"fs","/",0); 
	_tmpnameprefix="lws";
	printf("http://localhost:%d\n",server.port);
	//putenv("TEMP=c:\\temp");
	for(;;) {
		web_server_run(&server);
	};


};
