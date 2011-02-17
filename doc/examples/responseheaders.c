#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PORT 8888
#define FILENAME "picture.png"
#define MIMETYPE "image/png"

static int
answer_to_connection (void *cls, struct MHD_Connection *connection,
                      const char *url, const char *method,
                      const char *version, const char *upload_data,
                      size_t *upload_data_size, void **con_cls)
{
  struct MHD_Response *response;
  int fd;
  int ret;
  struct stat sbuf;

  if (0 != strcmp (method, "GET"))
    return MHD_NO;

  if ( (-1 == (fd = open (FILENAME, O_RDONLY))) ||
       (0 != fstat (fd, &sbuf)) )
    {
      /* error accessing file */
      if (fd != -1) close (fd);
      const char *errorstr =
        "<html><body>An internal server error has occured!\
                              </body></html>";
      response =
	MHD_create_response_from_buffer (strlen (errorstr), 
					 (void *) errorstr, 
					 MHD_RESPMEM_PERSISTENT);
      if (response)
        {
          ret =
            MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                                response);
          MHD_destroy_response (response);

          return MHD_YES;
        }
      else
        return MHD_NO;
    }
  response =
    MHD_create_response_from_fd_at_offset (sbuf.st_size, fd, 0);
  MHD_add_response_header (response, "Content-Type", MIMETYPE);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return ret;
}


int
main ()
{
  struct MHD_Daemon *daemon;

  daemon = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                             &answer_to_connection, NULL, MHD_OPTION_END);
  if (NULL == daemon)
    return 1;

  getchar ();

  MHD_stop_daemon (daemon);

  return 0;
}
