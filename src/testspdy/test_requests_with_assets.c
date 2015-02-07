/*
    This file is part of libmicrospdy
    Copyright Copyright (C) 2012 Andrey Uzunov

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file requests_with_assets.c
 * @brief  tests several requests for an HTML and all its assets. For
 * 			client spdycat (from spdylay) is used. The latter uses
 * 			libxml2.
 * @author Andrey Uzunov
 */

#include "platform.h"
#include "microspdy.h"
#include "common.h"
#include <sys/wait.h>
#include <stdio.h>   /* printf, stderr, fprintf */
#include <sys/types.h> /* pid_t */
#include <unistd.h>  /* _exit, fork */
#include <stdlib.h>  /* exit */
#include <errno.h>   /* errno */
#include <sys/wait.h> /* pid_t */
#include "common.h"

#define HTML "<html>\
<head>\
<link href=\"file1.css\" rel=\"stylesheet\" type=\"text/css\" />\
<link href=\"file2.css\" rel=\"stylesheet\" type=\"text/css\" />\
<link href=\"file3.css\" rel=\"stylesheet\" type=\"text/css\" />\
</head>\
<body><b>Hi, this is libmicrospdy!</b>\
</body></html>"

#define CSS "@media all{body{font-family:verdana,arial;color:#333;background-color:#fff;margin:0;padding:0}#navcontainer ul{padding-left:0;background:#005cb9 url(http://cdn.computerhope.com/backbar.jpg) repeat-x left top;padding-bottom:0;padding-top:0;color:#fff;float:right;font-weight:700;width:100%;border-top:1px solid #333;border-bottom:1px solid #333;margin:0}#navcontainer ul li a{color:#fff;text-decoration:none;float:left;border-top:1px solid #fff;border-right:1px solid #333;border-left:1px solid #fff;border-bottom:1px solid #333;padding:.2em 1em}#navcontainer ul li a:hover{background:url(http://cdn.computerhope.com/backbar2.jpg) repeat-x left top;background-color:#9fcfff;color:#333;border-top:1px solid #333;border-right:1px solid #fff;border-left:1px solid #333;border-bottom:1px solid #fff}a:visited{color:#636}a{color:#2a70d0}#content a{text-decoration:none;border-bottom:1px solid #DBDBDB}#content a:hover,a:active,a:focus{color:#c33;border-bottom:1px solid #c33}img{border:0}#content-container1{float:left;width:100%;background:#fff url(http://cdn.computerhope.com/back.jpg) repeat-y 0}.print,.email,.edit,.share,.up,.down,.book,.folder,.issue,.driver,.history,.news,.btips,.tips,.warn,.phone,.forum,.question{background:url(chs.png) no-repeat top left}#container{padding-left:150px;padding-right:265px}#container .column{position:relative;float:left}#content{width:100%;padding:20px}#left-bar{width:150px;margin-left:-100%;left:225px;padding:10px}#container > #left-bar{left:-190px}#right-bar{width:205px;margin-right:-265px;padding:0 10px}#topad{background:#9fcfff;text-align:center;padding:35px 0 4px}#leftad{clear:both;background:inherit;height:auto;margin:15px 0 0}#content ul{position:relative;margin:10px 0 10px 10px;padding:0}#content ul li{list-style-type:none;background:url(http://cdn.computerhope.com/arrow.png) no-repeat top left;background-position:0 5px;line-height:1.5625;padding:0 0 8px 23px}ol li{margin-bottom:8px;line-height:1.5625}.print,.email,.edit,.share{padding-left:23px}.print{background-position:0 -868px;width:16px;height:16px}.email{background-position:0 -469px;width:16px;height:16px}.edit{background-position:0 -403px;width:16px;height:16px}.share{background-position:0 -1002px;width:16px;height:16px}#left-bar li.title{color:#005cb9;font-weight:700;margin:1em 0}#right-box{width:180px;border:1px solid #005cb9;border-radius:15px 15px 15px 15px;background:#ebebeb;margin:90px 0 0;padding:10px}#right-box ul.poll{margin-top:15px;font-weight:700;margin-bottom:10px}.up,.down{padding-left:20px;text-decoration:none;color:#333}.up{background-position:0 -1068px;width:16px;height:16px}.down{background-position:0 -269px;width:16px;height:16px}#right-box li.title{color:#333;font-weight:700;margin:1em 0 0}#header{background:#9fcfff}#containercol2{background-color:#d0e8ff;width:700px;overflow:hidden;margin:0 auto}#containercol2 ul.col2{width:700px;list-style:none;float:left;padding:0}#containercol2 ul.col2 li h2{border:1px solid #005cb9;background:url(http://cdn.computerhope.com/backbar.jpg) repeat-x left top;color:#fff;font-size:large;text-align:center}#containercol2 ul.col2 li{float:left;width:340px;padding:5px}#containercol2 ul li.headline{border-bottom:1px solid #327dac;background:gray}#bottomad{margin:14px 0 0}input.btn,input.bbtn{color:#333;background:#9fcfff;font-weight:700;border:1px solid #005cb9;border-top:1px solid #eee;border-left:1px solid #eee;cursor:pointer;margin:4px 0 0}input.sbar,input.bsbar{color:#333;width:110px;background:#fff}input.btn{width:115px;font-size:medium}input.sbar{font-size:medium}input.bbtn{width:110px;font-size:large}input.bsbar{width:350px;font-size:18px;margin-right:5px}h1{font-size:175%;margin-bottom:25px;border-bottom:1px solid #dadada;padding-bottom:.17em;letter-spacing:-.05em;font-weight:700}.ce{text-align:center}.tab{margin-left:40px}p{line-height:1.5625}.tabb{margin-left:40px;font-weight:700;line-height:1.4}.dtab{margin-left:80px}.dd{font-weight:700;margin-left:7px}.lb{margin-left:5px}.bld{font-weight:700}.bb{font-size:14pt;color:#005cb9;font-weight:700}.bbl{font-size:14pt;font-weight:700}.nb{color:#005cb9;font-weight:700}.rg{color:gray;font-weight:700}.sg{font-size:10pt;color:gray}.sm{font-size:small}.rb{color:#fff;font-weight:700;text-indent:.3cm}.wt{color:#fff;font-weight:700}.bwt{color:#fff;font-weight:700;font-size:14pt}.large{font-size:x-large}.red{color:red}table{clear:both}.mtable,.mtable2{border:0 solid silver;background-color:#e5e5e5;border-spacing:2px 1px;width:98%;margin-left:auto;margin-right:auto}table.mtable td,table.mtable2 td{border-spacing:5px 10px;padding:9px}table.mtable th,table.mtable2 th{background:#005cb9 url(http://cdn.computerhope.com/backbar.jpg) repeat-x left top;color:#fff;font-weight:700;padding:5px}table.mtable a{border-bottom:0!important}table.mtable tr:hover td{background-color:#eee;cursor:pointer}td{vertical-align:top}.tcb{background:#005cb9 url(http://cdn.computerhope.com/backbar.jpg) repeat-x left top}.tclb{background-color:#9fcfff}.tcllb{background-color:#d0e8ff}.tcw{background-color:#fff}.tcg{background-color:#ebebeb}.tcbl{background-color:#333}.tcy{border:1px solid #005cb9;background-color:#f1f5f9;overflow:auto;padding:15px}.icell{padding-left:15px;padding-bottom:3px}.mlb{background-color:#9fcfff;padding-left:15px;padding-bottom:3px;white-space:nowrap;width:120px;vertical-align:top}#footer{background:url(http://cdn.computerhope.com/footback.jpg) repeat-x left top;background-color:#d0e8ff;clear:both;padding:5px}#footer ul li{list-style-type:none;display:inline;background:inherit;margin:0}#footer li a{float:left;text-decoration:none;width:300px;border-bottom:1px dotted #327dac;padding:0 0 10px 10px}#footer li a:hover{background:#005cb9;color:#fff}#creditfooter{display:none}.legal{text-align:center;font-size:11px}.legal a{text-decoration:none;color:#333}.floatLeft{float:left;clear:left;margin-right:20px;margin-bottom:10px}.floatRight{float:right;margin-left:20px;margin-bottom:10px}.floatRightClear{float:right;clear:right;margin-left:20px}:first-child + html #container{overflow:hidden}.book,.folder,.issue,.driver,.history,.news,.btips,.tips,.warn,.phone,.forum,.question{padding-left:22px;font-weight:700}.book{background-position:0 0;width:17px;height:18px}.tips{background-position:0 -68px;width:17px;height:17px}.btips{background-position:0 -135px;width:17px;height:17px}.history{background-position:0 -202px;width:17px;height:17px}.driver{background-position:0 -335px;width:17px;height:18px}.folder{background-position:0 -535px;width:17px;height:16px}.issue{background-position:0 -601px;width:17px;height:18px}.news{background-position:0 -669px;width:17px;height:14px}.forum{background-position:0 -733px;width:17px;height:18px}.phone{background-position:0 -801px;width:17px;height:17px}.question{background-position:0 -934px;width:17px;height:18px}.warn{background-position:0 -1134px;width:16px;height:16px}textarea,input{border:1px solid #ccc;border-top:1px solid #8d8e90;border-left:1px solid #8d8e90}textarea:focus,input:focus{border:1px solid #005cb9}#left-bar ul,#right-box ul,#footer ul{margin:0;padding:0}#right-box li.poll,#navcontainer ul li{display:inline}#noprint{margin:1px 0 0}#left-bar ul li,#right-box ul li{margin-left:10px;list-style-type:none;padding:0}#right-box a,#left-bar a{color:#333}}@media print{#header,#navcontainer,#topad,#left-bar,#right-bar,#bottomad,#footer,#search,#buttons,#noprint{display:none!important}#content a{text-decoration:none;color:#000}#content,#container{font-family:\"Times New Roman\",Times;background:transparent!important;text-indent:0!important;width:100%!important;border:0!important;float:none!important;position:static!important;overflow:visible!important;line-height:1;margin:0!important;padding:0!important}h1{font-size:14pt;margin-bottom:5px;border-bottom:0;padding-bottom:0;letter-spacing:-.05em;font-weight:700}h2{font-size:13pt}.bb{font-size:13pt;color:#005cb9;font-weight:700}#content ul li:before{content:\"\00bb \0020\"}#content .nb,.bb{font-weight:700;color:#000}table{margin-top:30px;margin-bottom:30px;border-collapse:collapse}th,td{border:1px solid #333}}"

#define JS "var _gaq = _gaq || [];\
_gaq.push(['_setAccount', 'UA-222222222222222222222222-1']);\
_gaq.push(['_trackPageview']);\
(function() {\
var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;\
//ga.src = ('https:' == document.location.protocol ? 'ZZZhttps://ssl' : 'ZZZhttp://www') + '.google-analytics.com/ga.js';\
var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);\
})();"

int port;

#define NUM_CLIENTS 50

pid_t parent;
int html_req_count;
int html_resp_count;

int child_c;
int children_pid[NUM_CLIENTS];
int children_status[NUM_CLIENTS];

int session_closed_called;

void
new_child(pid_t pid)
{
	//todo ids overflow
	children_pid[child_c] = pid;
	children_status[child_c++] = 1;
}

int
alive_children()
{
  int i;
  int dead;
  int status;
  int ret = 0;

  for(i=NUM_CLIENTS-1;i>=0;--i)
    {
      if (1 != children_status[i])
	continue;
      dead = waitpid(children_pid[i], &status, WNOHANG);
      if (0 == dead) 
	{
	  ret = 1;
	  continue;
	}
      if (WEXITSTATUS(status) != 0)
	{
	  for (i=NUM_CLIENTS-1;i>=0;--i)
	    if (1 == children_status[i])
	      kill (children_pid[i], SIGKILL);
	  exit (WEXITSTATUS(status));
	}
      children_status[i] = 2;
    }
  return ret;
}
 
void
killchild(int pid, char *message)
{
	printf("%s\nkilling %i\n",message,pid);
	kill(pid, SIGKILL);
	exit(1);
}

void
killparent(int pid, const char *message)
{
	printf("%s\nkilling %i\n",message,pid);
	kill(pid, SIGKILL);
	_exit(1);
}

void
standard_request_handler(void *cls,
						struct SPDY_Request * request,
						uint8_t priority,
                        const char *method,
                        const char *path,
                        const char *version,
                        const char *host,
                        const char *scheme,
						struct SPDY_NameValue * headers,
            bool more)
{
	(void)cls;
	(void)request;
	(void)priority;
	(void)host;
	(void)scheme;
	(void)headers;
	(void)method;
	(void)version;
	(void)more;
  
	struct SPDY_Response *response;
	
	if(NULL != strstr(path,".css"))
	{
	response = SPDY_build_response(200,NULL,SPDY_HTTP_VERSION_1_1,NULL,CSS,strlen(CSS));
	if(strcmp("/file3.css",path)==0)++html_resp_count;
	}
	/*else if(NULL != strstr(path,".js")) 
	{
	response = SPDY_build_response(200,NULL,SPDY_HTTP_VERSION_1_1,NULL,JS,strlen(JS));
	}*/
	else
	{
	response = SPDY_build_response(200,NULL,SPDY_HTTP_VERSION_1_1,NULL,HTML,strlen(HTML));
	}
	
	if(NULL==response){
		fprintf(stdout,"no response obj\n");
		exit(3);
	}
	
	if(SPDY_queue_response(request,response,true,false,NULL,(void*)strdup(path))!=SPDY_YES)
	{
		fprintf(stdout,"queue\n");
		exit(4);
	}
	
	
}
 
void
run_spdycat()
{
	pid_t child;
	++html_req_count;
	child = fork();
	if (child == -1)
	{   
		killparent(parent,"fork failed\n");
	}

	if (child == 0)
	{
		int devnull;

		close(1);
		devnull = open("/dev/null", O_WRONLY);
		if (1 != devnull)
		{
			dup2(devnull, 1);
			close(devnull);
		}
		char *uri;
		asprintf (&uri, "https://127.0.0.1:%i/%i.html", port, html_req_count);
		execlp ("spdycat", "spdycat", "-anv", uri, NULL);
		killparent (parent, "executing spdycat failed");
	}
	else
	{
		new_child(child);
	}
}

int
parentproc()
{
	unsigned long long timeoutlong=0;
	struct timeval timeout;
	int ret;
	fd_set read_fd_set;
	fd_set write_fd_set;
	fd_set except_fd_set;
	int maxfd = -1;
	struct SPDY_Daemon *daemon;
	
	SPDY_init();
	
	daemon = SPDY_start_daemon(port,
								DATA_DIR "cert-and-key.pem",
								DATA_DIR "cert-and-key.pem",
								NULL,
								NULL,
								&standard_request_handler,
								NULL,
								NULL,
								SPDY_DAEMON_OPTION_END);
	
	if(NULL==daemon){
		printf("no daemon\n");
		return 1;
	}

	do
	{
		if(NUM_CLIENTS > html_req_count)
		{
			run_spdycat();
		}
		
		FD_ZERO(&read_fd_set);
		FD_ZERO(&write_fd_set);
		FD_ZERO(&except_fd_set);
    
		ret = SPDY_get_timeout(daemon, &timeoutlong);
		if(SPDY_NO == ret || timeoutlong > 1000)
		{
			timeout.tv_sec = 1;
      timeout.tv_usec = 0;
		}
		else
		{
			timeout.tv_sec = timeoutlong / 1000;
			timeout.tv_usec = (timeoutlong % 1000) * 1000;
		}
		
		maxfd = SPDY_get_fdset (daemon,
								&read_fd_set,
								&write_fd_set, 
								&except_fd_set);
								
		ret = select(maxfd+1, &read_fd_set, &write_fd_set, &except_fd_set, &timeout);
		
		switch(ret) {
			case -1:
				printf("select error: %i\n", errno);
				break;
			case 0:

				break;
			default:
				SPDY_run(daemon);

			break;
		}
	}
	while(alive_children());

	SPDY_stop_daemon(daemon);
	
	SPDY_deinit();
	
	return html_resp_count != html_req_count;
}

int main()
{
	parent = getpid();
	port = get_port(10123);

	int ret = parentproc();
	exit(ret);

	return 1;
}
