#include <microhttpd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PORT            8888
#define POSTBUFFERSIZE  512
#define MAXNAMESIZE     20
#define MAXANSWERSIZE   512

#define GET             0
#define POST            1

struct ConnectionInfoStruct
{
  int connectiontype;
  char *answerstring;
  struct MHD_PostProcessor *postprocessor; 
};

const char* askpage="<html><body>\
                     What's your name, Sir?<br>\
                     <form action=\"/namepost\" method=\"post\">\
                     <input name=\"name\" type=\"text\"\
                     <input type=\"submit\" value=\" Send \"></form>\
                     </body></html>";

const char* greatingpage="<html><body><h1>Welcome, %s!</center></h1></body></html>";

const char* errorpage="<html><body>This doesn't seem to be right.</body></html>";


int SendPage(struct MHD_Connection *connection, const char* page)
{
  int ret;
  struct MHD_Response *response;
  

  response = MHD_create_response_from_data(strlen(page), (void*)page, MHD_NO, MHD_NO);
  if (!response) return MHD_NO;
 
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  
  MHD_destroy_response(response);

  return ret;
}


int IteratePost(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
                const char *filename, const char *content_type,
                const char *transfer_encoding, const char *data, size_t off, size_t size)
{
  struct ConnectionInfoStruct *con_info = (struct ConnectionInfoStruct*)(coninfo_cls);
  

  if (0 == strcmp(key, "name"))
  {
    if ((size>0) && (size<=MAXNAMESIZE))
    {
      char *answerstring;
      answerstring = malloc(MAXANSWERSIZE);
      if (!answerstring) return MHD_NO;
      
      snprintf(answerstring, MAXANSWERSIZE, greatingpage, data);
      con_info->answerstring = answerstring;      
    } else con_info->answerstring=NULL;

    return MHD_NO;
  }

  return MHD_YES;
}

void RequestCompleted(void *cls, struct MHD_Connection *connection, void **con_cls,
                      enum MHD_RequestTerminationCode toe)
{
  struct ConnectionInfoStruct *con_info = (struct ConnectionInfoStruct*)(*con_cls);


  if (NULL == con_info) return;

  if (con_info->connectiontype == POST)
  {
    MHD_destroy_post_processor(con_info->postprocessor);        
    if (con_info->answerstring) free(con_info->answerstring);
  }
  
  free(con_info);      
}


int AnswerToConnection(void *cls, struct MHD_Connection *connection, const char *url, 
    const char *method, const char *version, const char *upload_data, 
    unsigned int *upload_data_size, void **con_cls)
{
  if(*con_cls==NULL) 
  {
    struct ConnectionInfoStruct *con_info;

    con_info = malloc(sizeof(struct ConnectionInfoStruct));
    if (NULL == con_info) return MHD_NO;

    if (0 == strcmp(method, "POST")) 
    {      
      con_info->postprocessor = MHD_create_post_processor(connection, POSTBUFFERSIZE, 
                                                          IteratePost, (void*)con_info);   

      if (NULL == con_info->postprocessor) 
      {
        free(con_info); 
        return MHD_NO;
      }

      con_info->connectiontype = POST;
    } else con_info->connectiontype = GET;

    *con_cls = (void*)con_info;
    return MHD_YES;
  }

  if (0 == strcmp(method, "GET")) 
  {
    return SendPage(connection, askpage);     
  } 
    
  if (0 == strcmp(method, "POST")) 
  {
    struct ConnectionInfoStruct *con_info = *con_cls;

    if (*upload_data_size != 0) 
    {
      MHD_post_process(con_info->postprocessor, upload_data, *upload_data_size);
      *upload_data_size = 0;
      return MHD_YES;
    } else return SendPage(connection, con_info->answerstring);
  } 

  return SendPage(connection, errorpage); 
}

int main ()
{
  struct MHD_Daemon *daemon;


  daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                            &AnswerToConnection, NULL, MHD_OPTION_NOTIFY_COMPLETED,
                            RequestCompleted, NULL, MHD_OPTION_END);

  if (NULL == daemon) return 1;

  getchar(); 

  MHD_stop_daemon(daemon);
  return 0;
}
