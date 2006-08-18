/* Copyrights 2002 Luis Figueiredo (stdio@netc.pt) All rights reserved. 
 *
 * See the LICENSE file
 *
 * The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits must appear in the documentation.
 *
 * date: Wed Oct  9 19:56:22 GMT 2002
 *
 * -- parse http header into "ClientInfo"
 *
 */

#include "clientinfo.h"

/*********************************************************************************************************/
/*
 * Initialize ClientInfo structure
 */
void __ILWS_init_clientinfo(struct ClientInfo *ClientInfo) { 
	char *t;
	struct outstream *tstream=current_web_client->outstream;
	
	ClientInfo=__ILWS_malloc(sizeof(struct ClientInfo));
	if(ClientInfo==NULL) {
		return;
	};
	
	while(tstream->next!=NULL) {
		tstream=tstream->next;
	};
	
	if(tstream->fstream!=NULL) ClientInfo->outfd=fileno(tstream->fstream); //take it off?
		
	ClientInfo->mem=__ILWS_init_buffer_list(); // First thing, other fuctions use this to allocate
	
        
	ClientInfo->request=__ILWS_clientinfo_getreqname();
	
	ClientInfo->inetname=NULL;
	t=inet_ntoa(current_web_client->sa.sin_addr);
	if((ClientInfo->inetname=__ILWS_add_buffer(ClientInfo->mem,strlen(t)+1))) {
		memcpy(ClientInfo->inetname,t,strlen(t));
		ClientInfo->inetname[strlen(t)]='\0';
	};
	
	ClientInfo->method=__ILWS_clientinfo_getmethod();
	ClientInfo->user=__ILWS_clientinfo_getauthuser();
	ClientInfo->pass=__ILWS_clientinfo_getauthpass();
	
	
	
	/* Initialize List's */
	ClientInfo->HeaderList=NULL;
	ClientInfo->QueryList=NULL;
	ClientInfo->PostList=NULL;
	ClientInfo->MultiPartList=NULL;
	ClientInfo->CookieList=NULL;

	ClientInfo->Header=__ILWS_Header;
	ClientInfo->Query=__ILWS_Query;
	ClientInfo->QueryString=__ILWS_clientinfo_getquerystring();	
	ClientInfo->Post=__ILWS_Post;
	ClientInfo->PostData=__ILWS_clientinfo_getpostdata();	
	ClientInfo->MultiPart=__ILWS_MultiPart;
	ClientInfo->Cookie=__ILWS_Cookie;
	ClientInfo->Conf=__ILWS_Conf;
	ClientInfo->CookieString=__ILWS_Header("Cookie");
	
}                      

/*
 * Free ClientInfo structure
 */
void __ILWS_free_clientinfo(struct ClientInfo *ClientInfo) {
  if(ClientInfo==NULL) {	
    return;
  };
  __ILWS_delete_buffer_list(ClientInfo->mem); 
  
  __ILWS_free(ClientInfo);
  ClientInfo=NULL;
}


/*
 * Header function for ClientInfo->Header("x")
 */
char *__ILWS_Header(struct ClientInfo *ClientInfo, char *str) {
	char *tmp1,*tmp2,*tmp3,*ret;
	struct _Header *hl=ClientInfo->HeaderList;
	char *defret="";
	size_t size;
	size_t strsize;
	if(str==NULL) { // request is null return whole header
		return current_web_client->rbuf;
	};
	if(ClientInfo->HeaderList==NULL) {
		
		ClientInfo->HeaderList=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _Header));
		if(ClientInfo->HeaderList==NULL) {
			return defret;
		};
		ClientInfo->HeaderList->next=NULL;
		ClientInfo->HeaderList->data=NULL;
		ClientInfo->HeaderList->id=NULL;
		hl=ClientInfo->HeaderList;
	};
	// First search if exists
	
	while(hl->next!=NULL) {
		if(hl->next->id!=NULL) {
			if(!strcmp(hl->next->id,str)) {
				
				return hl->next->data;
			};
		};
		hl=hl->next;	
	};
	
	/* Doesn't exists	 */
	strsize=strlen(str);
	if(!(hl->next=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _Header)))) {
		return defret;
	};
	if(!(hl->next->id=__ILWS_add_buffer(ClientInfo->mem,strsize+1))) {
		return defret;
	};
	
	memcpy(hl->next->id,str,strsize);
	hl->next->id[strsize]=0;	
	hl->next->data=defret;
	hl->next->next=NULL;

	if(!(tmp3=__ILWS_malloc(strsize+3))) {
		return defret;
	};
	snprintf(tmp3,strsize+3,"%s: ",str);
	tmp1=__ILWS_stristr(current_web_client->rbuf,tmp3);
	__ILWS_free(tmp3);
	if(tmp1==NULL) {
		return defret;
	};
	
	tmp1+=strsize+2;
	if(!(tmp2=strstr(tmp1,"\r\n"))) { // Unexpected (security anyway)
		return defret;
	};
	if((size=(unsigned int)(tmp2-tmp1))<0) {
		return defret;
	};
	if(!(ret=__ILWS_add_buffer(ClientInfo->mem,size+1))) { //malloc & register
		return defret;
	};
	memcpy(ret,tmp1,size);
	ret[size]=0;
	hl->next->data=ret;
	return ret;
}                                

/*
 * Function for Querydata
 */
char *__ILWS_Query(struct ClientInfo *ClientInfo, char *handle) {
    char *tmp1,*tmp2,*tmp3,*tmp4,*ret;
	char *defret="";
	size_t strsize;
    size_t size;
	int j=0,ch;
	int seek=1;
	unsigned int i;
	unsigned int *iddb=NULL;
	unsigned int *iddb2=NULL;
	unsigned int idf=0;
	int rw=0; // 0 data 1 number of vars; (return what?)
	struct _Query *ql=ClientInfo->QueryList;
	
	
	if(handle==NULL) {
		return ClientInfo->QueryString;
	};
	if(handle[0]=='#') rw=1;
	// allocate first node from the list 
	if(ClientInfo->QueryList==NULL) {                                                              
		ClientInfo->QueryList=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _Query));                   
		if(ClientInfo->QueryList==NULL) {                                                          
			if(rw) return 0;
			return defret;
		};
		ClientInfo->QueryList->next=NULL;
		ClientInfo->QueryList->data=NULL;
		ClientInfo->QueryList->id=NULL;
		ql=ClientInfo->QueryList;
	};
	// done allocating


	// First search if exists and fetch values;
	
	idf=1;
	iddb=&idf;
	seek=1;
	
	while(ql->next!=NULL) {
		if(ql->next->id!=NULL) {
			if(!strcmp(ql->next->id,handle+rw) && *iddb >= 0) {
				if(seek==1) {
					iddb=&ql->next->index; // atribute iddb to first node
					iddb2=&ql->next->idf; // atribute iddb2 to counting
					if(rw) return (char *)*iddb2;
					if(ql->next->idf==1) {
						return ql->next->data;
					};
					j=*iddb;
					seek++;			
				};
				*iddb=*iddb-1;
				
				if(*iddb<=0) {
					*iddb=j-1;
					if(j<=1) {
						*iddb=*iddb2; // go to start if any
						//return defret; // to be null
					};
					return ql->next->data; // Return existent
				};
				
			};
		};
		ql=ql->next;	
	};
	
	
	
	/* Doesn't exists	 */
	strsize=strlen(handle+rw);
	tmp1=strstr(current_web_client->rbuf,"?"); 
	tmp3=strstr(current_web_client->rbuf," HTTP"); // End of GET header
	if(tmp1!=NULL && tmp1<tmp3) {
		tmp1+=1;
	} else {
		if(rw)return 0;
		return defret;
	}
	
	// Working here
	idf=0;
	ret=defret;
	seek=1;
	tmp4=tmp1;
	while(seek==1) {
		tmp1=tmp4;
		do {
			tmp2=strstr(tmp1,handle+rw);
			if(tmp2==NULL) { // must be nonnull
				if(iddb!=NULL && iddb2!=NULL) { // if iddb2 is null then is just one value;
					*iddb2=*iddb;
					if(!rw)*iddb=*iddb-1;
				};
				if(rw) {
					if(ret==defret) return 0;
					return (char *)*iddb2;
				} 
				return ret; // if first null return defret (ret=defret);
				
			};
			tmp1=tmp2+strsize;
		} while ((tmp2[-1]!='?' && tmp2[-1]!='&') || tmp2[strsize]!='='); // Johannes E. Schindelin Fix

		if(tmp3<tmp2) { 
			if(iddb!=NULL && iddb2!=NULL) {
				*iddb2=*iddb;
				if(!rw)*iddb=*iddb-1;
			};
			if(rw) {
				if(ret==defret) return 0;
				return (char *)*iddb2;
			}
			
			return ret;
		};
	
		tmp4=tmp1;
			// if not null, so add an node;
	
		// Working here ^
		ql->next=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _Query));
		if(ql->next==NULL) {
			if(handle[0]=='#') rw=1;
			return defret;
		};
		ql->next->id=__ILWS_add_buffer(ClientInfo->mem,strsize+1);
		if(ql->next->id==NULL) {
			if(handle[0]=='#') rw=1;
			return defret;
		};
		memcpy(ql->next->id,handle+rw,strsize);
		ql->next->id[strsize]=0;	
		if(idf==0) {
			ql->next->index=0;
			iddb=&ql->next->index;
			iddb2=&ql->next->idf; // second holds information about number of fetchs;
			
		};
		ql->next->data=defret;
		ql->next->next=NULL;

		
		tmp1=strstr(tmp2,"&"); // tmp1 goes to next '&'
		tmp2+=strsize+1;           // tmp2 goes to start of data
		tmp3=strstr(tmp2," HTTP"); // tmp3 goes to the end of Get header
		if(tmp1==NULL || ((unsigned int)tmp1>(unsigned int)tmp3)) {
			size=tmp3-tmp2; // MUST HAVE (" HTTP") else, server don't let in
		} else {
			size=tmp1-tmp2;
		};
		if(size<1) {
			if(handle[0]=='#') rw=1;
			return defret;
		};
		
		
		ql->next->data=__ILWS_add_buffer(ClientInfo->mem,size+1);
		if(ql->next->data==NULL) {
			if(handle[0]=='#') rw=1;
			return defret;
		};
		j=0;
		for(i=0;i<size;i++) { // Hex translation here
			switch (ch=tmp2[j]) {
			case '+':
				ch=' ';
				break;
			case '%':
				
				tmp1=__ILWS_malloc(3);
				if(tmp1==NULL) {
					if(rw) return 0;
					return defret;
				};
				strncpy(tmp1,&tmp2[j+1],2);
				tmp1[2]=0;
				ch=strtol(tmp1,NULL,16);
				j+=2;
				size-=2;
				
				__ILWS_free(tmp1);
				break;
			};
			ql->next->data[i]=ch;
			j++;
		};
		ql->next->data[size]='\0';
		ret=ql->next->data; // to the last
		ql=ql->next;
		*iddb=*iddb+1;
		idf++;
 	};
	return ret;
}                                                                                          

/*
 * Function for Postdata
 */
char *__ILWS_Post(struct ClientInfo *ClientInfo, char *handle) {
	char *tmp1,*tmp2,*tmp3,*ret;
	struct _Post *pl=ClientInfo->PostList;
	char *defret="";
	int *iddb=NULL,*iddb2=NULL;
	int idf;
	int seek=1;
	size_t strsize;
	size_t size;
	int j=0,ch;
	unsigned int i;
	int rw=0; //return what;
	
	tmp1=strstr(current_web_client->rbuf,"Content-type: multipart/form-data"); // multipart this post doesn't work
	if(tmp1!=NULL) {
		return ClientInfo->MultiPart(handle).data;
	};
	if(handle==NULL) {
		return ClientInfo->PostData;
	};
	if(handle[0]=='#')rw=1;
	/* Allocate the list */
	if(ClientInfo->PostList==NULL) {
		if(!(ClientInfo->PostList=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _Post)))) {
			if(rw) return 0;
			return defret;
		};
		ClientInfo->PostList->next=NULL;
		ClientInfo->PostList->data=NULL;
		ClientInfo->PostList->id=NULL;
		pl=ClientInfo->PostList;
	};
	
	// First search if exists
	idf=1;
	iddb=&idf;
	seek=1;
	while(pl->next!=NULL) {
		if(pl->next->id!=NULL) {
			if(!strcmp(pl->next->id,handle+rw) && iddb>=0) {
				if(seek==1) {
					iddb=&pl->next->index;
					iddb2=&pl->next->idf;
					if(rw) return (char *)(*iddb2);
					if(pl->next->idf==1) {
						return pl->next->data;
					};
					j=*iddb;
					seek++;
				};
				*iddb=*iddb-1;
				
				if(*iddb<=0) {
					*iddb=j-1;
					if(j<=1) {
						*iddb=*iddb2;

						//return defret;
					};
					return pl->next->data;
				};
			};
		};
		pl=pl->next;	
	};
	
	
	
	
	
	/* Doesn't exists	 */
	strsize=strlen(handle+rw);
	tmp1=strstr(current_web_client->rbuf,"\r\n\r\n"); 
	if(tmp1!=NULL)
		tmp1+=4;
	else {
		if(rw) return 0;
		return defret;
	};
	idf=0;
	ret=defret;
	seek=1;
	tmp3=tmp1;
	while(seek==1) {
		tmp1=tmp3;
		do {
			tmp2=strstr(tmp1,handle+rw);
			if(tmp2==NULL) { // mustn't be null
				if(iddb!=NULL && iddb2!=NULL) { // if iddb2 is null then is just one value;
					*iddb2=*iddb;
					if(!rw)*iddb=*iddb-1;
				};
				if(rw) {
					if(ret==defret) return 0;
					return (char *)*iddb2;
				}
				return ret; // if first null return defret (ret=defret);
				
			};
			tmp1=tmp2+strsize;
		} while ((tmp2[-1]!='\n' && tmp2[-1]!='&') || tmp2[strsize]!='='); // Johannes E. Schindelin Fix
		tmp3=tmp1;

		
		pl->next=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _Post));
		if(pl->next==NULL) {
			if(rw) return 0;
			return defret;
		};
		pl->next->id=__ILWS_add_buffer(ClientInfo->mem,strsize+1);
		if(pl->next->id==NULL) {
			if(rw) return 0;
			return defret;
		};
		memcpy(pl->next->id,handle+rw,strsize);
		pl->next->id[strsize]=0;	
		if(idf==0) {
			pl->next->index=0;
			iddb=&pl->next->index;
			iddb2=&pl->next->idf;
		};

		pl->next->data=defret;
		pl->next->next=NULL;
							
		tmp1=strstr(tmp2,"&"); // goes to the next & (end of data)
		tmp2+=strsize+1;       // tmp2 goes to start of data
		if(tmp1==NULL) {
			size=strlen(tmp2);
		} else {
			size=tmp1-tmp2;
		};
		if(size==0) {
			if(rw) return 0;
			return defret;
		};
		
		pl->next->data=__ILWS_add_buffer(ClientInfo->mem,size+1);
		if(pl->next->data==NULL) {
			return defret;
		};
		j=0;
		for(i=0;i<size;i++) { // hex translation here
			switch (ch=tmp2[j]) {
				case '+':
					ch=' ';
					break;
				case '%':
					
					tmp1=__ILWS_malloc(3);             
					if(tmp1==NULL) {
						if(rw) return 0;
						return defret;
					};
					strncpy(tmp1,&tmp2[j+1],2);
					tmp1[2]=0;
					
					ch=strtol(tmp1,NULL,16);
					j+=2;
					size-=2;
					
					__ILWS_free(tmp1);
					break;
			};
			pl->next->data[i]=ch;
			j++;
		};
		pl->next->data[size]='\0';
		ret=pl->next->data; // to the last
		*iddb=*iddb+1;
		idf++;
		pl=pl->next;
		//pl->next->data=ret;
	};
	return ret;
}                                                        

/*
 * Function for MultiPart formdata
 */
struct _MultiPart __ILWS_MultiPart(struct ClientInfo *ClientInfo, char *handle) {
	char *tmp1,*tmp2,*tmp3;	
	int i;
	char *name;
	size_t namesize;
	struct _MultiPart *ml=ClientInfo->MultiPartList;
	struct _MultiPart defret={"","",0,""};
	size_t strsize;
	char *boundary; size_t boundarysize;
	// IE C43o6Fn6Et74e65n6Et74-2DT54y79p70e65:3A 20m6Du75l6Ct74i69p70a61r72t74/2Ff66o6Fr72m6D-2Dd64a61t74a61
	// NS C43o6Fn6Et74e65n6Et74-2Dt74y79p70e65:3A 20m6Du75l6Ct74i69p70a61r72t74/2Ff66o6Fr72m6D-2Dd64a61t74a61
	tmp1=__ILWS_stristr(current_web_client->rbuf,"Content-type: multipart/form-data");	
	if(tmp1==NULL) return defret;
	if(ClientInfo->MultiPartList==NULL) {
		ClientInfo->MultiPartList=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _MultiPart));
		if(ClientInfo->MultiPartList==NULL) {
			return defret;
		};
		ClientInfo->MultiPartList->next=NULL;
		ClientInfo->MultiPartList->id=NULL;
		ClientInfo->MultiPartList->data=NULL;
		ClientInfo->MultiPartList->filename=NULL;
		ClientInfo->MultiPartList->size=0;
		ml=ClientInfo->MultiPartList;
	};
	// Check if handle exists
	while(ml->next!=NULL) {
		if(ml->next->id!=NULL) {
			if(!strcmp(ml->next->id,handle)) {
				
				return *ml->next;
			};
		};
		ml=ml->next;
	};	
	
	
	strsize=strlen(handle);
	ml->next=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _MultiPart));
	if(ml->next==NULL) {
		return defret;
	};
	ml->next->id=__ILWS_add_buffer(ClientInfo->mem,strsize+1);
	if(ml->next->id==NULL) {
		return defret;
	};
	memcpy(ml->next->id,handle,strsize);
	ml->next->id[strsize]=0;
	ml->next->data="";
	ml->next->filename="";
	ml->next->size=0;
	ml->next->next=NULL;
	
	tmp1=strstr(tmp1,"boundary=");
	if(tmp1==NULL) return defret;
	tmp1+=9;
	tmp2=strstr(tmp1,"\r\n");
	if(tmp2<tmp1 || tmp2==NULL) return defret;
	/* boundary */
	boundarysize=tmp2-tmp1;
	boundary=__ILWS_add_buffer(ClientInfo->mem,boundarysize+3);
	if(boundary==NULL) {
		return defret;
	};
	memcpy(boundary,tmp1,boundarysize);
	boundary[boundarysize]=0;
	
	
	/* handle */	
	namesize=boundarysize+41+strlen(handle);
	name=__ILWS_add_buffer(ClientInfo->mem,namesize+1);
	if(name==NULL) {
		return defret;
	};
	snprintf(name,namesize,"%s\r\nContent-Disposition: form-data; name=",boundary);	
	namesize=strlen(name);
	
	tmp1=strstr(tmp1,"\r\n\r\n"); // go to data
	if(tmp1==NULL) return defret;
	
	do {
		i=memcmp(tmp1,name,namesize);	
		if(i==0) {
			tmp1+=namesize;
			if(tmp1[0]=='\"')tmp1+=1;
			if(strncmp(tmp1,handle,strlen(handle))){
				i=1;
			}else {
				if((tmp1[strsize]!=' ') && (tmp1[strsize]!='\"') && (tmp1[strsize]!='\r') && (tmp1[strsize]!=';') ) i=1;
			};

		}else { 
			tmp1+=1;
		};
	} while(i!=0 && (tmp1+namesize<current_web_client->rbuf+current_web_client->rbufsize)); // Search init of data
	if(i!=0) return defret;
	//tmp1+=namesize;
	tmp2=strstr(tmp1,"filename="); // get filename
	if(tmp2!=NULL) {
		tmp2+=9;
		if(tmp2[0]=='\"')tmp2+=1;
		tmp3=strstr(tmp2,"\r\n");
		ml->next->filename=__ILWS_add_buffer(ClientInfo->mem,(tmp3-tmp2)+1);
		if(ml->next->filename==NULL) {
			return defret;
		};
		memcpy(ml->next->filename,tmp2,tmp3-tmp2);
		ml->next->filename[tmp3-tmp2]='\0';
		if(ml->next->filename[tmp3-tmp2-1]=='\"')
			ml->next->filename[tmp3-tmp2-1]='\0';
		
	};
	tmp2=strstr(tmp1,"\r\n\r\n"); // data init
	if(tmp2==NULL)return defret;
	tmp2+=4;
	tmp3=tmp2;
	do {	
		
		i=memcmp(tmp3,boundary,boundarysize);  
		if(i!=0)tmp3+=1;
	} while(i!=0 && (tmp3+boundarysize<current_web_client->rbuf+current_web_client->rbufsize)); // End of data
	if(i!=0) return defret;
	tmp3-=4; // back "\r\n\r\n"

	// copy data to node	
	if(!(ml->next->data=__ILWS_add_buffer(ClientInfo->mem,(tmp3-tmp2)+1))) {
		return defret;
	};
	memcpy(ml->next->data,tmp2,tmp3-tmp2);
	ml->next->data[tmp3-tmp2]='\0';
	ml->next->size=tmp3-tmp2;
	
	
	
	
	return *ml->next;

};

/*
 * Function for CookieData
 */
char *__ILWS_Cookie(struct ClientInfo *ClientInfo, char *handle) {
	char *defret="";
	char *tmp1,*tmp2,*ret;
	int size;
	int strsize;
	struct _Cookie *cl=ClientInfo->CookieList;
	
	
	tmp1=strstr(current_web_client->rbuf,"\nCookie: "); // start of cookie string
	if(tmp1==NULL) { // no cookies
		return defret;
	};
	tmp1+=8;
	if(handle==NULL) {
		return ClientInfo->CookieString;
	};
	
	if(ClientInfo->CookieList==NULL) {
		
		ClientInfo->CookieList=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _Cookie));
		if(ClientInfo->CookieList==NULL) {
			return defret;
		};
		ClientInfo->CookieList->next=NULL;
		ClientInfo->CookieList->data=NULL;
		ClientInfo->CookieList->id=NULL;
		cl=ClientInfo->CookieList;
	}
	// First search if exists
	while(cl->next!=NULL) {
		if(cl->next->id!=NULL) {
			if(!strcmp(cl->next->id,handle)) {
				
				return cl->next->data;
			};
		};
		cl=cl->next;	
	};
	
	strsize=strlen(handle);
	if(!(cl->next=__ILWS_add_buffer(ClientInfo->mem,sizeof(struct _Cookie)))) {
		return defret;
	};
	if(!(cl->next->id=__ILWS_add_buffer(ClientInfo->mem,strsize+1))) {
		return defret;
	};
	memcpy(cl->next->id,handle,strsize);
	cl->next->id[strsize]=0;
	cl->next->data=defret;
	cl->next->next=NULL;
	do {
		tmp2=strstr(tmp1,handle);
		if(tmp2==NULL) {
			return defret;
		}else if(tmp2[strsize]==';' && tmp2[-1]==' ') {
			cl->next->data=__ILWS_add_buffer(ClientInfo->mem,6);
			snprintf(cl->next->data,5,"True");
			return cl->next->data;
		};
		tmp1=tmp2+strsize;
	}while(tmp2[-1]!=' ' || tmp2[strsize]!='=');
	
	tmp1=strstr(tmp2,";"); // end of data
	tmp2+=strsize+1;     // start of data
	if(tmp1==NULL) {
		size=strstr(tmp2,"\r")-tmp2;
		
	} else {
		size=tmp1-tmp2;
	};
	if(size<1) {
		return defret;
	};
	
	ret=__ILWS_add_buffer(ClientInfo->mem,size+1);
	if(ret==NULL) {
		return defret;
	};
	
	memcpy(ret,tmp2,size);
	ret[size]='\0';
	cl->next->data=ret;
	return cl->next->data;	
};

/*
 * get whole query string
 */
char *__ILWS_clientinfo_getquerystring(struct ClientInfo *ClientInfo) {
	char *tmp1,*tmp2,*ret;
	char *defret="";
	size_t size;
        tmp1=strstr(current_web_client->rbuf,"?"); 
        tmp2=strstr(current_web_client->rbuf,"HTTP");
        if(tmp1!=NULL && tmp1<tmp2)
                tmp1+=1;
        else
                return defret;
	size=(tmp2-tmp1)-1;
	ret=__ILWS_add_buffer(ClientInfo->mem,size+1);
	if(ret==NULL) {
		return defret;
	};
	memcpy(ret,tmp1,size);
	ret[size]=0;
	return ret;
};

/*
 * get whole post data
 */ 
char *__ILWS_clientinfo_getpostdata(struct ClientInfo *ClientInfo) {
	char *tmp1,*ret;
	char *defret="";
	size_t size;
	tmp1=strstr(current_web_client->rbuf,"\r\n\r\n"); 
	if(tmp1!=NULL && (tmp1+4)<(char*)(current_web_client->rbuf+current_web_client->rbufsize))
		tmp1+=4;
	else
		return defret;
	size=(current_web_client->rbuf+current_web_client->rbufsize)-tmp1;
	ret=__ILWS_add_buffer(ClientInfo->mem,size+1);
	if(ret==NULL) {
		return defret;
	};
	memcpy(ret,tmp1,size);
	ret[size]='\0';
	return ret;
}

/*
 * get method (GET POST HEAD etc)
 */
char *__ILWS_clientinfo_getmethod(struct ClientInfo *ClientInfo) {
	char *tmp1,*ret;
	char *defret="";
	size_t size;
	tmp1=strstr(current_web_client->rbuf," "); // first space
	if(tmp1==NULL) {
		return defret;
	};
	size=tmp1-current_web_client->rbuf;
	ret=__ILWS_add_buffer(ClientInfo->mem,size+1);
	if(ret==NULL) {
		return defret;
	};
	memcpy(ret,current_web_client->rbuf,size);
	ret[size]=0;
	return ret;
}

/*
 * get request name (GET /taltal HTTP/1.0) returning /taltal
 */
char *__ILWS_clientinfo_getreqname(struct ClientInfo *ClientInfo) {
	char *ret;
	char *tmp1=strstr(current_web_client->rbuf,"/"); // Must have /
	char *tmp2=strstr(tmp1,"?");
	char *tmp3=strstr(tmp1," HTTP");
	char *defret="";
	size_t i,j;
	int ch;
	size_t size=0;
	if(tmp1==NULL || tmp3==NULL) return defret;
	if(tmp2==NULL || tmp2>tmp3) {
		tmp2=tmp3;
	};
	//tmp1+=1;
	size=tmp2-tmp1;
	if(size<1) 
		return defret;
	ret=__ILWS_add_buffer(ClientInfo->mem,size+1);
	if(ret==NULL) {
		return defret;
	};
	j=0;
	for(i=0;i<size;i++) { // hex translation here
		switch (ch=tmp1[j]) {
			case '+':
				ch=' ';
				break;
			case '%':
				
				tmp2=__ILWS_malloc(3);             
				if(tmp2==NULL) {
					return defret;
				};
				strncpy(tmp2,&tmp1[j+1],2);
				tmp2[2]=0;
				
				ch=strtol(tmp2,NULL,16);
				j+=2;
				size-=2;
				__ILWS_free(tmp2);
				break;
		};
		ret[i]=ch;
		j++;
	};
	//pl->next->data[size]='\0';
	//memcpy(ret,tmp1,size);
	ret[size]=0;
	return ret;
}         


