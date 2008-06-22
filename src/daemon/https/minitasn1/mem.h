#ifndef MEM_H
# define MEM_H

/* Use _asn1_afree() when calling alloca, or
 * memory leaks may occur in systems which do not
 * support alloca.
 */
#ifdef HAVE_ALLOCA
# ifdef HAVE_ALLOCA_H
#  include <alloca.h>
# endif
# define _asn1_alloca alloca
# define _asn1_afree(x)
#else
# define _asn1_alloca _asn1_malloc
# define _asn1_afree _asn1_free
#endif /* HAVE_ALLOCA */

#define _asn1_malloc malloc
#define _asn1_free free
#define _asn1_calloc calloc
#define _asn1_realloc realloc
#define _asn1_strdup strdup

#endif /* MEM_H */


