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

//int
//main (int argc, char *argv[])
//{
//  int i, j;
//  const char *desc;
//  const char *_name;
//  error_name names_to_sort[400];      /* up to 400 names  */
//
//  printf ("@table @code\n");
//
//  memset (names_to_sort, 0, sizeof (names_to_sort));
//  j = 0;
//  for (i = 0; i > -400; i--)
//    {
//      _name = _gnutls_strerror (i);
//      if (_name == NULL)
//      continue;
//
//      strcpy (names_to_sort[j].name, _name);
//      names_to_sort[j].error_index = i;
//      j++;
//    }
//
//  qsort (names_to_sort, j, sizeof (error_name), compar);
//
//  for (i = 0; i < j; i++)
//    {
//      _name = names_to_sort[i].name;
//      desc = gnutls_strerror (names_to_sort[i].error_index);
//      if (desc == NULL || _name == NULL)
//      continue;
//
//      printf ("@item %s:\n%s\n\n", _name, desc);
//    }
//
//  printf ("@end table\n");
//
//  return 0;
//}
