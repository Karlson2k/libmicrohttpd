#ifndef pthread_windows_H
#define pthread_windows_H

struct _pthread_t;
struct _pthread_cond_t;
struct _pthread_mutex_t;

typedef struct _pthread_t *pthread_t;
typedef struct _pthread_cond_t *pthread_cond_t;
typedef struct _pthread_mutex_t *pthread_mutex_t;

#define PTHREAD_MUTEX_INITIALIZER ((pthread_mutex_t)(size_t) -1)
#define PTHREAD_COND_INITIALIZER ((pthread_cond_t)(size_t) -1)

int pthread_create (pthread_t * pt,
                    const void *attr,
                    void *(__cdecl * start)(void *),
                    void *arg);

int pthread_detach (pthread_t pt);

int pthread_join (pthread_t pt,
                  void **value_ptr);

int pthread_mutex_init (pthread_mutex_t *mutex,
                        const void *attr);

int pthread_mutex_destroy (pthread_mutex_t *mutex);

int pthread_mutex_lock (pthread_mutex_t *mutex);

int pthread_mutex_unlock (pthread_mutex_t *mutex);

int pthread_cond_init (pthread_cond_t *cond,
                       const void *attr);

int pthread_cond_destroy (pthread_cond_t *cond);

int pthread_cond_wait (pthread_cond_t *cond,
                       pthread_mutex_t *mutex);

int pthread_cond_signal (pthread_cond_t *cond);

int pthread_cond_broadcast (pthread_cond_t *cond);

#endif // !pthread_windows_H
