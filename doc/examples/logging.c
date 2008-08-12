#include <microhttpd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PORT 8888


int PrintOutKey(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
  printf("%s = %s\n", key, value);
  return MHD_YES;
}

int AnswerToConnection(void *cls, struct MHD_Connection *connection, const char *url, 
    const char *method, const char *version, const char *upload_data, 
    unsigned int *upload_data_size, void **con_cls)
{
  
  printf("New request %s for %s using version %s\n", method, url, version);

  MHD_get_connection_values(connection, MHD_HEADER_KIND, PrintOutKey, NULL);

  return MHD_NO;
}

int main ()
{
  struct MHD_Daemon *daemon;

  daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                            &AnswerToConnection, NULL, MHD_OPTION_END);
  if (daemon == NULL) return 1;

  getchar(); 

  MHD_stop_daemon(daemon);
  return 0;
}
