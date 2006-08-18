/* by Luis Figueiredo (stdio@netc.pt)
 *
 * file: main.c
 *
 * description: Programa main
 *
 * date: 16:47,13-47-2002
 */


#include "soundcard.h"
#include "soundbuffers.h"
#include "soundmixer.h"
#include "web_server.h"
#include <signal.h>

#define ADJUST_VOLUME(s, v)     (s = (s*v)/128)

int PORT=80;
struct sound_buf *SoundBuf;

void outgif() {
	char *nam;
	struct sound_buf *sbuf=NULL;
	char gif[640*40+1];
	int x=0,y=0;
	int i,h=20;
	short d;
	nam=malloc(strlen(ClientInfo->request)-3);
	memcpy(nam,ClientInfo->request+1,strlen(ClientInfo->request)-4);
	nam[strlen(ClientInfo->request)-5]=0;
	sbuf=sbuf_select(SoundBuf,nam);
	if(sbuf!=NULL) {
		if(sbuf->data_i>_SDMAX) {
			if(gif!=NULL) {
				memset(gif,0,640*40);
				for(i=0;i<1280;i++) {
					x=i/2;
					//y=(*((unsigned short *)sbuf->data+((i*4)%640))%20)+10;
					d=((sbuf->data[((i*((sbuf->data_i-1280)/2560))*2)+1]<<8)|sbuf->data[((i*((sbuf->data_i-1280)/2560))*2)]);
					y=d/(32767/20)+20;
					//fprintf(stderr,"y=%d\n",y);
					//gif[x+y*640]=10;
					if(h>y) {
						for(h=20;h>y;h--) gif[x+h*640]=10;
					} else {
						for(h=20;h<=y;h++) gif[x+h*640]=10;
					};

				};
				printf("Cache-control: no-cache\r\n");
				printf("Content-type: image/gif\r\n\r\n");
				web_client_gifoutput(gif,640,40,0);
			};
		};
	};
	free(nam);
	return;
};
void dlbuf() {
	char *nam;
	struct sound_buf *sbuf=NULL;
	nam=malloc(strlen(ClientInfo->request)-3);
	memcpy(nam,ClientInfo->request+1,strlen(ClientInfo->request)-4);
	nam[strlen(ClientInfo->request)-5]=0;
	sbuf=sbuf_select(SoundBuf,nam);
	printf("Content-type: x-form/application\r\n\r\n");
	if(sbuf!=NULL) {
		fwrite(sbuf->data,sbuf->data_i,1,stdout);
	};

};

void index_html() {
	struct sound_buf *sbuf=NULL;
	char *id;
	char *tmp;
	int i;
	unsigned char *soundout=NULL;
	short src1,src2;
	int dst_sample;
	const int max_audioval =((1<<(16-1))-1);
	const int min_audioval =-(1<<(16-1));
	int bigger=0;
					
	printf("Cache-control: no-cache\r\n");
	printf("Content-type: text/html\r\n\r\n");
	printf("<HTML>\n");
	printf("<BODY>\n");
	printf("<center>Sound Recorder (webgui)</center>\n");
	if(*ClientInfo->Post("sbufnew")!=0) {
		if(*ClientInfo->Post("sbufname")!=0) {
			if(!sbuf_select(SoundBuf,ClientInfo->Post("sbufname"))) {
				sbuf=sbuf_add(SoundBuf,ClientInfo->Post("sbufname"));
				if(ClientInfo->MultiPart("sbufdata").size>0) {
					sbuf->data=malloc(ClientInfo->MultiPart("sbufdata").size);
					memcpy(sbuf->data,ClientInfo->MultiPart("sbufdata").data,ClientInfo->MultiPart("sbufdata").size);
					sbuf->data_i=ClientInfo->MultiPart("sbufdata").size;
				};
			} else {
				printf("<FONT color='FF0000'>Sound buffer exists</font>\n");
			};

		}else {
			printf("<FONT color='FF0000'>Sound buffer name is empty</font>\n");
		};
	};
	if(*ClientInfo->Post("sbufvol")!=0) {
		sbuf=SoundBuf->next;
		while(sbuf!=NULL) {
			tmp=malloc(strlen(sbuf->id)+5);
			snprintf(tmp,strlen(sbuf->id)+5,"%s.vol",sbuf->id);
			sbuf->volume=atoi(ClientInfo->Post(tmp))%129;
			free(tmp);
			sbuf=sbuf->next;
		}
	};
	if(*ClientInfo->Post("sbufch")!=0) {
		sbuf=SoundBuf->next;
		while(sbuf!=NULL) {
			tmp=malloc(strlen(sbuf->id)+4);
			snprintf(tmp,strlen(sbuf->id)+4,"%s.ch",sbuf->id);
			sbuf->channels=atoi(ClientInfo->Post(tmp))%3;
			free(tmp);
			sbuf=sbuf->next;
		}
	};

	printf("<form method='POST' enctype='multipart/form-data'>\n");

	printf("Sound Buffer:<BR>\n");
	printf("Name:<input type=text name='sbufname' size=5 maxlength=10><BR>\n");
	printf("Data:<input type=file name='sbufdata'><BR>\n");
	printf("<input type=submit name='sbufnew' value=' New '><BR>\n");

	printf("<table width=100%% cellpadding=2 cellspacing=0 bgcolor='AAAAAA'>\n");
	printf("<TR><TD colspan=7 align=center><font face='Helvetica' size=6 color='FFFFFF'> Sound Buffers </font></TD></TR>\n");
	sbuf=SoundBuf->next;
	i=0;
	while(sbuf!=NULL) {
		if(*ClientInfo->Post("sbufprocess")!=0) {
			if(atoi(ClientInfo->Post(sbuf->id))==5) {
				sbuf->mode=0;
				sbuf->play_i=0;
				if(sbuf->data_i>bigger) {
					bigger=sbuf->data_i;
					 soundout=realloc(soundout,bigger);
				};
				for(i=0;i<sbuf->data_i;i+=4) {
					// LEFT
					src1=((sbuf->data[i+1]<<8) | sbuf->data[i]);
					ADJUST_VOLUME(src1,sbuf->volume);
					src2=((soundout[i+1]<<8) | soundout[i]);
					dst_sample=src1+src2;
					if ( dst_sample > max_audioval ) {
						dst_sample = max_audioval;
					} else if ( dst_sample < min_audioval ) {
						dst_sample = min_audioval;
					}
					soundout[i]=dst_sample &0xFF;
					dst_sample>>=8;
					soundout[i+1]=dst_sample & 0xFF;
					// RIGHT
					src1=((sbuf->data[i+1+2]<<8) | sbuf->data[i+2]);
					ADJUST_VOLUME(src1,sbuf->volume);
					if(sbuf->channels==2) {
						src2=((soundout[i+1+2]<<8) | soundout[i+2]); // join left to right
					} else {
						src2=((soundout[i+1]<<8) | soundout[i]); // separate
					};
					dst_sample=src1+src2;
					if ( dst_sample > max_audioval ) {
						dst_sample = max_audioval;
					} else if ( dst_sample < min_audioval ) {
						dst_sample = min_audioval;
					}
					soundout[i+2]=dst_sample &0xFF;
					dst_sample>>=8;
					soundout[i+2+1]=dst_sample & 0xFF;
				};

			} else {
				sbuf->mode=atoi(ClientInfo->Post(sbuf->id));
				tmp=malloc(strlen(sbuf->id)+5);
				snprintf(tmp,strlen(sbuf->id)+5,"%s.vol",sbuf->id);
				sbuf->volume=atoi(ClientInfo->Post(tmp))%129;
				free(tmp);
				sbuf->play_i=0;
			};
		};
		if(sbuf->mode!=4) {
			printf("<TR><TD bgcolor='EFEFEF'><font face='Verdana'>%s</font></TD><TD>",sbuf->id);
			printf("<select name='%s'>",sbuf->id);
			printf("<option value='0' %s>none</option>\n",(atoi(ClientInfo->Post(sbuf->id))==0)?"selected":"");
			printf("<option value='1' %s>play</option>\n",(atoi(ClientInfo->Post(sbuf->id))==1)?"selected":"");
			printf("<option value='2' %s>record</option>\n",(atoi(ClientInfo->Post(sbuf->id))==2)?"selected":"");
			printf("<option value='3'>reset</option>\n");
			printf("<option value='4'>delete</option>\n");
			printf("<option value='5'>mixfrom</option>\n");
			printf("<option value='6'>mixto</option>\n");
			printf("</select>\n");
			printf("</TD><TD>%dm:%ds</TD>",(sbuf->data_i/44100/2/2)/60,(sbuf->data_i/44100/2/2%60));
			printf("</TD><TD>\n");
			printf("<select name='%s.ch'>\n",sbuf->id);
			printf("<option value='1' %s>Mono</option>\n",(sbuf->channels==1)?"selected":"");
			printf("<option value='2' %s>Stereo</option>\n",(sbuf->channels==2)?"selected":"");
			printf("</select></TD>");
			
			printf("</TD><TD>Volume:<BR>\n");
			printf("<input type=text name=%s.vol size=3 maxlength=3 value='%d'></TD>",sbuf->id,sbuf->volume);
			printf("<TD width=100%%> <input type=image width=100%% height=40 src='/%s.gif' border=0></TD>\n",sbuf->id);
			printf("<TD><a href='/%s.raw'>Download</a></TD></TR>\n",sbuf->id);
		}
		if(sbuf->mode==3) {
			sbuf->data_i=0;
			sbuf->play_i=0;
			free(sbuf->data);
			sbuf->data=NULL;
			sbuf->mode=0;
		};

		id=sbuf->id;	
		sbuf=sbuf->next;
		if(atoi(ClientInfo->Post(id))==4) {
			sbuf_delete(SoundBuf,id);
		}
		i++;
	};
	// mix to (6)
	sbuf=SoundBuf->next;
	while(sbuf!=NULL) {
		if(atoi(ClientInfo->Post(sbuf->id))==6) {
			free(sbuf->data); // free previous
			sbuf->data=malloc(bigger+1);
			memcpy(sbuf->data,soundout,bigger);
			sbuf->data_i=bigger;
			sbuf->mode=0;
			sbuf->play_i=0;
			sbuf->volume=128;
		};
		sbuf=sbuf->next;
	};
	if(i) printf("<TR><TD align=center valign=center>.</TD><TD><input type=submit name='sbufprocess' value=' Process '></TD><TD align=center valign=center>.</TD><TD><input type=submit name='sbufch' value='Set'></TD><TD><input type=submit name='sbufvol' value='Set'></TD><TD>.</TD><TD>.</TD></TR>\n");

	printf("</TABLE>\n");
	printf("</form>\n");






};










int main() {
	struct web_server server;
	int soundfd;
	struct soundcard_setup SoundSetup;
	signal(SIGPIPE,SIG_IGN);	
	
	SoundBuf=sbuf_init();	
	
	
	SoundSetup.rate=44100;
	SoundSetup.channels=2;
	SoundSetup.fmt=16;	
	
	soundfd=soundcard_init("/dev/dsp",&SoundSetup);
	if(soundfd<1) {
		return 0;
	};
	
	
	while(!web_server_init(&server,PORT,NULL,0))PORT++;
	printf("http://localhost:%d\n",PORT);

	web_server_addhandler(&server,"* /*.gif",outgif,WS_LOCAL);
	web_server_addhandler(&server,"* /*.raw",dlbuf,WS_LOCAL);
	web_server_addhandler(&server,"* /*",index_html,WS_LOCAL);

	while(1) {
		sound_process(soundfd,SoundBuf);
		web_server_run(&server);
	};


};
