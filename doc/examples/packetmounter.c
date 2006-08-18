

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

typedef u_int32_t n_time;
#include <netinet/in.h>
#include <netinet/ip.h>
#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>
#include <regex.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>                

#include "web_server.h"

int PORTSSL=443;

unsigned short in_chksum(unsigned short *addr, int len) {
	register int nleft = len;
	register int sum = 0;
	u_short answer = 0;

	while (nleft > 1) {
	sum += *addr++;
	nleft -= 2;
	}

	if (nleft == 1) {
	*(unsigned char *)(&answer) = *(unsigned char  *)addr;
	sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}                           
void packetmounter() {
	char *t;
	int s;
	struct sockaddr_in to;
	int i;
	int n=10;
	char buf[128];
	int proto=1; //icmp default
	struct ip *ip=(struct ip *)buf;
	struct tcphdr *tcp=(struct tcphdr *)(buf+sizeof(*ip));
	char *tmp1=ClientInfo->user;
	char *tmp2=ClientInfo->pass;;
	if(!strlen(tmp1) || !strlen(tmp2)) {
		web_client_HTTPdirective("HTTP/1.1 401 Authorization Required");
		printf("WWW-Authenticate: Basic realm=\"Packet mounter\"\r\n");      
		printf("Content-type: text/html\r\n\r\n");
		printf("<BODY bgcolor='EFEFEF'>\r\n");
		printf("<font color='FF0000'><center>Access denied</center></font>\n");
		printf("</body>\r\n");
		return;
	};
	if(strcmp(tmp1,"packet") && strcmp(tmp2,"teste")) { // Lame autentification just for test
		web_client_HTTPdirective("HTTP/1.1 401 Authorization Required");
		printf("WWW-Authenticate: Basic realm=\"Packet mounter\"\r\n");      
		printf("Content-type: text/html\r\n\r\n");
		printf("<BODY bgcolor='EFEFEF'>\r\n");
		printf("<font color='FF0000'><center>Access denied</center></font>\n");
		printf("</body>\r\n");
		return;	
	};
	printf("Content-type: text/html\r\n\r\n");
	printf("<HTML>\n");
	printf("<body bgcolor='FFFFCC'>\n");
	printf("<center>public Packet mounter by <BR><small><TT> Luis Figueiredo (<a href=\"mailto:stdio@netc.pt\">stdio@netc.pt</a>)</tt></small><BR><i><small>Using %s</i></small><HR>\n",_libwebserver_version);	
	t=ClientInfo->Query("proto");
	printf("Pretended protocol: %s<BR>\n",t);
	if(strlen(t)) {
		proto=atoi(t);
		printf("<form method=post action='/?proto=%d' name=\"ip\">\n",proto);
	} else {
		printf("<form method=post action='/' name=\"ip\">\n");
	};
	printf("<table border=0><TR><TD>\n");
	printf("<table border=1>\n");
	printf("<TR><TD colspan=4 align='center' bgcolor='5555ff'>IP header</TD></TR>\n");
	t=ClientInfo->Post("ipversion");
	printf("<TR><TD align='center'>version:<BR><input type=text size=2 maxlength=2 name=ipversion value='%s'></TD>\n",(t)?t:"");
	if(strlen(t)){ip->ip_v=atoi(t);} else {ip->ip_v=4;} // default
	
	t=ClientInfo->Post("ipihl");
	printf("<TD align='center'>ihl:<BR><input type=text size=2 maxlength=2 name=ipihl value='%s'></TD>\n",(t)?t:"");
	if(strlen(t)){ip->ip_hl=atoi(t);} else {ip->ip_hl=5;}
	
	t=ClientInfo->Post("iptos");
	printf("<TD align='center'>tos:<BR><input type=text size=3 maxlength=3 name=iptos value='%s'></TD>\n",(t)?t:"");
	if(strlen(t)){ip->ip_tos=atoi(t);} else {ip->ip_tos=0;}

	t=ClientInfo->Post("iptotlen");
	printf("<TD align='center'>tot len:<BR><input type=text size=4 maxlength=4 name=iptotlen value='%s'></TD></TR>\n",(t)?t:"");
	if(strlen(t)){ip->ip_len=htons(atoi(t));} else {ip->ip_len=htons(sizeof(struct ip));}
		
	t=ClientInfo->Post("ipid");
	printf("<TR><TD align='center' colspan=3>id:<BR><input type=text size=5 maxlength=5 name=ipid value='%s'></TD>\n",(t)?t:"");
	if(strlen(t)){ip->ip_id=htons(atoi(t));} else {ip->ip_id=htons(37337);}

	t=ClientInfo->Post("ipfrag");
	printf("<TD align='center'>frag offset:<BR><input type=text size=4 maxlength=4 name=ipfrag value='%s'></TD></TR>\n",(t)?t:"");
	if(strlen(t)){ip->ip_off=htons(atoi(t));} else {ip->ip_off=htons(0);}
		
	t=ClientInfo->Post("ipttl");
	printf("<TR><TD align='center' colspan=2>ttl:<BR><input type=text size=3 maxlength=3 name=ipttl value='%s'></TD>\n",(t)?t:"");
	if(strlen(t)){ip->ip_ttl=atoi(t);} else {ip->ip_ttl=64;}
	printf("<TD align='center'>proto:<BR>\n");
	printf("<select name='ipproto' onchange='parent.location=(document.ip.ipproto.options[0].selected==true)?\"/?proto=1\":(document.ip.ipproto.options[1].selected==true)?\"/?proto=6\":(document.ip.ipproto.options[2].selected==true)?\"/?proto=17\":\"\"'>\n");
	printf("<option value='1' %s>icmp\n",(proto==1)?"selected":"");
	printf("<option value='6' %s>tcp\n",(proto==6)?"selected":"");
	printf("<option value='17' %s>udp\n",(proto==17)?"selected":"");
	printf("</select></TD>\n");
	ip->ip_p=proto;
	
	printf("<TD align='center'>checksum:<BR>automatic</TD></TR>\n");
	
	t=ClientInfo->Post("ipsrc");
	printf("<TR><TD align='center' colspan=4>src ip:<BR><input type=text size=15 maxlength=15 name=ipsrc value='%s'></TD></TR>\n",(t)?t:"");
	if(strlen(t)){ip->ip_src.s_addr=inet_addr(t);} else {ip->ip_src.s_addr=0;}
	
	t=ClientInfo->Post("ipdst");
	printf("<TR><TD align='center' colspan=4>dst ip:<BR><input type=text size=15 maxlength=15 name=ipdst value='%s'></TD></TR></TABLE>\n",(t)?t:"");
	if(strlen(t)){ip->ip_dst.s_addr=inet_addr(t);} else {ip->ip_dst.s_addr=0;}
	
	printf("</TD><TD>\n");
	
	if(proto==6) {   // print tcp header input
		printf("<TABLE border=1>\n");
		printf("<TR><TD colspan=4 align='center' bgcolor='5555FF'>tcp header</TD></TR>\n");	
		t=ClientInfo->Post("tcpsrcport");
		printf("<TR><TD colspan=2 align='center'>src port:<BR><input type=text size=5 maxlength=5 name=tcpsrcport value='%s'></TD>\n",(t)?t:"");	
		if(strlen(t)){tcp->th_sport=htons(atoi(t));}
		t=ClientInfo->Post("tcpdstport");
		printf("<TD colspan=2 align='center'>dst port:<BR><input type=text size=5 maxlength=5 name=tcpdstport value='%s'></TD></TR>\n",(t)?t:"");	
		if(strlen(t)){tcp->th_dport=htons(atoi(t)); }
		t=ClientInfo->Post("tcpseq");
		printf("<TR><TD colspan=4 align='center'>Seq number:<BR><input type=text size=10 maxlength=10 name=tcpseq value='%s'></TD></TR>\n",(t)?t:"");	
		if(strlen(t)){tcp->th_seq=htonl(strtoul(t,NULL,10));}
		t=ClientInfo->Post("tcpack");
		printf("<TR><TD colspan=4 align='center'>ack:<BR><input type=text size=10 maxlength=10 name=tcpack value='%s'></TD></TR>\n",(t)?t:"");	
		if(strlen(t)){tcp->th_ack=htonl(strtoul(t,NULL,10)); }else {tcp->th_ack=0;}
		
		printf("<TR><TD align='center'><small><small>data offset:<BR>(computed)</small></small></TD>\n");	
		printf("<TD align='center'><small><small>reserved:<BR>(computed)</small></small></TD>\n");	
		printf("<TD align='center'>flags:<BR>\n");
		printf("<TABLE border=0 cellspacing=0 cellpadding=0><TR>\n");
		printf("<TD><small><small>URG </small></small></TD>\n");
		printf("<TD><small><small>ACK </small></small></TD>\n");
		printf("<TD><small><small>PSH </small></small></TD>\n");
		printf("<TD><small><small>RST </small></small></TD>\n");
		printf("<TD><small><small>SYN </small></small></TD>\n");
		printf("<TD><small><small>FIN</small></small></TD></TR>\n");
		t=ClientInfo->Post("tcpfURG");
		if(strlen(t)){tcp->th_flags |= TH_URG;}else {tcp->th_flags &= ~TH_URG;}
		t=ClientInfo->Post("tcpfACK");
		if(strlen(t)){tcp->th_flags |= TH_ACK;}else {tcp->th_flags &= ~TH_ACK;}
		t=ClientInfo->Post("tcpfPSH");
		if(strlen(t)){tcp->th_flags |= TH_PUSH;}else {tcp->th_flags &= ~TH_PUSH;}
		t=ClientInfo->Post("tcpfRST");
		if(strlen(t)){tcp->th_flags |= TH_RST;}else {tcp->th_flags &= ~TH_RST;}
		t=ClientInfo->Post("tcpfSYN");
		if(strlen(t)){tcp->th_flags |= TH_SYN;}else {tcp->th_flags &= ~TH_SYN;}
		t=ClientInfo->Post("tcpfFIN");
		if(strlen(t)){tcp->th_flags |= TH_FIN;}else {tcp->th_flags &= ~TH_FIN;}
		printf("<TD><input type=checkbox name=tcpfURG %s></TD>\n",((tcp->th_flags & TH_URG)==TH_URG)?"checked":"");
		printf("<TD><input type=checkbox name=tcpfACK %s></TD>\n",((tcp->th_flags & TH_ACK)==TH_ACK)?"checked":"");
		printf("<TD><input type=checkbox name=tcpfPSH %s></TD>\n",((tcp->th_flags & TH_PUSH)==TH_PUSH)?"checked":"");
		printf("<TD><input type=checkbox name=tcpfRST %s></TD>\n",((tcp->th_flags & TH_RST)==TH_RST)?"checked":"");
		printf("<TD><input type=checkbox name=tcpfSYN %s></TD>\n",((tcp->th_flags & TH_SYN)==TH_SYN)?"checked":"");
		printf("<TD><input type=checkbox name=tcpfFIN %s></TD>\n",((tcp->th_flags & TH_FIN)==TH_FIN)?"checked":"");
		printf("</TR></TABLE></TD>\n");	
		t=ClientInfo->Post("tcpwin");	
		printf("<TD align='center'>window:<BR><input type=text size=7 maxlength=7 name=tcpwin value='%s'></TD></TR>\n",(t)?t:"");	
		if(strlen(t)) {tcp->th_win=htons(atoi(t)); } else {tcp->th_win=htons(1500);}
		printf("<TR><TD colspan=2 align='center'>checksum:<BR>automatic</TD>\n");	
		t=ClientInfo->Post("tcpurg");	
		printf("<TD colspan=2 align='center'>urgent:<BR><input type=text size=7 maxlength=7 name=tcpurg value='%s'></TD></TR>\n",(t)?t:"");	
		printf("<TR><TD align='center' colspan=4>Tcp data<BR><textarea name=data cols='30' rows='4'>%s</textarea></TD></TR>\n",ClientInfo->Post("data"));
		if(strlen(t)) {tcp->th_urp=htons(atoi(t)); } else {tcp->th_urp=0;}
		printf("</TABLE>\n");
		printf("</TABLE>\n");
		tcp->th_x2=0;
	};
	printf("</TD></TR></TABLE>\n");
	t=ClientInfo->Post("n_packets");
	printf("<input type=text size=4 maxlength=4 value='10' name=n_packets value='%s'>\n",(t)?t:"");
	if(strlen(t)){n=atoi(t); } 
	printf("<input type=submit value='send packet' name=ipsend>\n");
	t=ClientInfo->Post("data");	
	memcpy(buf+sizeof(*ip)+sizeof(*tcp),t,(strlen(t)>128)?128:strlen(t));
	
	t=ClientInfo->Post("ipsend");
	if(strlen(t)) {
		s=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
		to.sin_family=AF_INET;
		to.sin_addr.s_addr=ip->ip_dst.s_addr;
		to.sin_port=htons(tcp->th_dport);
		ip->ip_sum=in_chksum((void *)&ip,sizeof(*ip));
		tcp->th_sum=in_chksum((void *)&ip,sizeof(*ip)+sizeof(*tcp));
		for(i=0;i<n;i++) {
			sendto(s,&buf,128,0,(struct sockaddr *)&to,sizeof(to));
		};
	};
	printf("<br><a href='http://libwebserver.sourceforge.net'><img src='/libwebserver.gif' border='0'></a><BR>\n");
	printf("</body>\n");
	printf("</HTML>\n");

};

int main() {
	int pid;
	struct web_server serverSSL;
	web_server_useSSLcert(&serverSSL,"./foo-cert.pem"); // Must be here couse of initalization of openssl
	while(!web_server_init(&serverSSL,PORTSSL,"packetmounter.log",WS_USESSL)) {
		PORTSSL++;	
	};
	printf("https://localhost:%d\n",PORTSSL);
	web_server_addhandler(&serverSSL,"* /*",packetmounter,0);
	while(1) {
		// DO whatever u want
		web_server_run(&serverSSL); // Process web_server w/ SSL
	};
	return 0;

};
