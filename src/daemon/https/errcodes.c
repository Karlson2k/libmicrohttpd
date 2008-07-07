#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls.h>

const char *_gnutls_strerror (int);

typedef struct
{
  char name[128];
  int error_index;
} error_name;

static int
compar (const void *_n1, const void *_n2)
{
  const error_name *n1 = (const error_name *) _n1,
    *n2 = (const error_name *) _n2;
  return strcmp (n1->name, n2->name);
}
