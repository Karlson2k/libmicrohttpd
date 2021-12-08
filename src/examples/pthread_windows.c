#include "pthread_windows.h"
#include <Windows.h>

struct _pthread_t
{
  HANDLE thread;
};

struct _pthread_cond_t
{
  HANDLE event;
};

struct _pthread_mutex_t
{
  HANDLE mutex;
};

struct StdCallThread
{
  void *(__cdecl *start) (void *);
  void *arg;
};

DWORD WINAPI
ThreadProc (LPVOID lpParameter)
{
  struct StdCallThread st = *((struct StdCallThread *) lpParameter);
  free (lpParameter);
  st.start (st.arg);
  return 0;
}


int
pthread_create (pthread_t *pt,
                const void *attr,
                void *(__cdecl *start)(void *),
                void *arg)
{
  pthread_t pt_ = (pthread_t) malloc (sizeof(struct _pthread_t));
  if (NULL == pt_)
    return 1;
  struct StdCallThread *sct;
  sct = (struct StdCallThread *) malloc (sizeof(struct StdCallThread));
  if (NULL == sct)
  {
    free (pt_);
    return 1;
  }

  sct->start = start;
  sct->arg   = arg;
  pt_->thread = CreateThread (NULL, 0, ThreadProc, sct, 0, NULL);
  if (NULL == pt_->thread)
  {
    free (sct);
    free (pt_);
    return 1;
  }
  *pt = pt_;

  return 0;
}


int
pthread_detach (pthread_t pt)
{
  if (pt)
  {
    CloseHandle (pt->thread);
    free (pt);
  }
  return 0;
}


int
pthread_join (pthread_t pt,
              void **value_ptr)
{
  if (NULL == pt)
    return 1;

  if (value_ptr)
  {
    *value_ptr = NULL;
  }
  WaitForSingleObject (pt->thread, INFINITE);
  CloseHandle (pt->thread);
  free (pt);

  return 0;
}


int
pthread_mutex_init (pthread_mutex_t *mutex,
                    const void *attr)
{
  pthread_mutex_t mutex_ = (pthread_mutex_t) malloc (sizeof(struct
                                                            _pthread_mutex_t));
  if (NULL == mutex_)
    return 1;
  mutex_->mutex = CreateMutex (NULL, FALSE, NULL);
  if (NULL == mutex_->mutex)
  {
    free (mutex_);
    return 1;
  }
  *mutex = mutex_;

  return 0;
}


int
pthread_mutex_destroy (pthread_mutex_t *mutex)
{
  if (NULL == mutex)
    return 1;
  if ((NULL == *mutex) || (PTHREAD_MUTEX_INITIALIZER == *mutex))
    return 0;

  CloseHandle ((*mutex)->mutex);
  free (*mutex);
  *mutex = NULL;

  return 0;
}


int
pthread_mutex_lock (pthread_mutex_t *mutex)
{
  if (NULL == mutex)
    return 1;
  if (NULL == *mutex)
    return 1;
  if (PTHREAD_MUTEX_INITIALIZER == *mutex)
  {
    int ret = pthread_mutex_init (mutex, NULL);
    if (0 != ret)
      return ret;
  }
  if (WAIT_OBJECT_0 != WaitForSingleObject ((*mutex)->mutex, INFINITE))
    return 1;
  return 0;
}


int
pthread_mutex_unlock (pthread_mutex_t *mutex)
{
  if (NULL == mutex)
    return 1;
  if ((NULL == *mutex) || (PTHREAD_MUTEX_INITIALIZER == *mutex))
    return 1;

  if (0 == ReleaseMutex ((*mutex)->mutex))
    return 1;

  return 0;
}


int
pthread_cond_init (pthread_cond_t *cond,
                   const void *attr)
{
  pthread_cond_t cond_ = (pthread_cond_t) malloc (sizeof(struct
                                                         _pthread_cond_t));
  if (NULL == cond_)
    return 1;
  cond_->event = CreateEvent (NULL, FALSE, FALSE, NULL);
  if (NULL == cond_->event)
  {
    free (cond_);
    return 1;
  }
  *cond = cond_;

  return 0;
}


int
pthread_cond_destroy (pthread_cond_t *cond)
{
  if (NULL == cond)
    return 1;
  if ((NULL == *cond) || (PTHREAD_COND_INITIALIZER == *cond))
    return 1;

  CloseHandle ((*cond)->event);
  free (*cond);

  return 0;
}


int
pthread_cond_wait (pthread_cond_t *cond,
                   pthread_mutex_t *mutex)
{
  if ((NULL == cond) || (NULL == mutex))
    return 1;
  if ((NULL == *cond) || (NULL == *mutex))
    return 1;
  if (PTHREAD_COND_INITIALIZER == *cond)
  {
    int ret = pthread_cond_init (cond, NULL);
    if (0 != ret)
      return ret;
  }
  if (PTHREAD_MUTEX_INITIALIZER == *mutex)
  {
    int ret = pthread_mutex_init (mutex, NULL);
    if (0 != ret)
      return ret;
  }
  ReleaseMutex ((*mutex)->mutex);
  if (WAIT_OBJECT_0 != WaitForSingleObject ((*cond)->event, INFINITE))
    return 1;
  if (WAIT_OBJECT_0 != WaitForSingleObject ((*mutex)->mutex, INFINITE))
    return 1;

  return 0;
}


int
pthread_cond_signal (pthread_cond_t *cond)
{
  if (NULL == cond)
    return 1;
  if ((NULL == *cond) || (PTHREAD_COND_INITIALIZER == *cond))
    return 1;

  if (0 == SetEvent ((*cond)->event))
    return 1;

  return 0;
}


int
pthread_cond_broadcast (pthread_cond_t *cond)
{
  return pthread_cond_signal (cond);
}
