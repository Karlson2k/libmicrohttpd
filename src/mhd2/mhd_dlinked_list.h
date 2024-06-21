/*
  This file is part of libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file src/mhd2/mhd_dlinked_list.h
 * @brief  Double-linked list macros and declarations
 * @author Karlson2k (Evgeny Grin)
 *
 * Double-linked list macros help create and manage the chain of objects
 * connected via inter-object pointers (named here @a links_name), while
 * the list is held by the owner within the helper (named here @a list_name).
 */

#ifndef MHD_DLINKED_LIST_H
#define MHD_DLINKED_LIST_H 1

#include "mhd_sys_options.h"

#include "sys_null_macro.h"
#include "mhd_assert.h"


/* This header defines macros for handling double-linked lists of object.
   The pointers to the first and the last objects in the list are held in
   the "owner".
   The list member objects links to each other via "next" and "prev" links.
   Each member object can be part of several lists. For example, connections are
   maintained in "all connections" and "need to process" lists simultaneously.
   List member can be removed from the list or inserted to the list at any
   moment.
   Typically the name of the list (inside the "owner" object) is the same as
   the name of inter-links. However, it is possible to use different names.
   For example, connections can be removed from "all connections" list and
   moved the "clean up" list using the same internal links "all connections".
   As this is a double-linked list, it can be walked from begin to the end and
   in the opposite direction.
   The list is compatible only with "struct" types.
 */

/* Helpers */

#define mhd_DLNKDL_LIST_TYPE_(base_name) struct base_name ## s_list

#define mhd_DLNKDL_LINKS_TYPE_(base_name) struct base_name ## _link


/* Names */

/**
 * The name of struct that hold the list in the owner object
 */
#define mhd_DLNKDL_LIST_TYPE(base_name) mhd_DLNKDL_LIST_TYPE_ (base_name)

/**
 * The name of struct that links between the list members
 */
#define mhd_DLNKDL_LINKS_TYPE(base_name) mhd_DLNKDL_LINKS_TYPE_ (base_name)

/* Definitions of the structures */

/**
 * Template for declaration of the list helper struct
 * @param l_type the name of the struct objects that list links
 */
#define mhd_DLINKEDL_LIST_DEF(l_type) \
        mhd_DLNKDL_LIST_TYPE (l_type) { /* Holds the list in the owner */         \
          struct l_type *first; /* The pointer to the first object in the list */ \
          struct l_type *last; /* The pointer to the last object in the list */   \
        }

/**
 * Template for declaration of links helper struct
 * @param l_type the name of the struct objects that list links
 */
#define mhd_DLINKEDL_LINKS_DEF(l_type) \
        mhd_DLNKDL_LINKS_TYPE (l_type) { /* Holds the links in the members */       \
          struct l_type *prev; /* The pointer to the previous object in the list */ \
          struct l_type *next; /* The pointer to the next object in the list */     \
        }


/**
 * Template for declaration of list helper structs
 * @param l_type the name of the struct objects that list links
 */
#define mhd_DLINKEDL_STRUCTS_DEFS(l_type) \
        mhd_DLINKEDL_LIST_DEF (l_type); mhd_DLINKEDL_LINKS_DEF (l_type)

/* Declarations for the list owners and the list members */

/**
 * Declare the owner's list member
 */
#define mhd_DLNKDL_LIST(l_type,list_name) \
        mhd_DLNKDL_LIST_TYPE (l_type) list_name

/**
 * Declare the list object links member
 */
#define mhd_DLNKDL_LINKS(l_type,links_name) \
        mhd_DLNKDL_LINKS_TYPE (l_type) links_name

/* Direct work with the list */
/* These macros directly use the pointer to the list and allow using
 * names of the list object (within the owner object) different from the names
 * of link object (in the list members). */

/**
 * Initialise the double linked list pointers in the list object using
 * the directly pointer to the list
 * @param p_list the pointer to the list
 * @param l_name the name of the list
 */
#define mhd_DLINKEDL_INIT_LIST_D(p_list) \
        do {(p_list)->first = NULL; (p_list)->last = NULL;} while (0)

/**
 * Insert object into the first position in the list using direct pointer
 * to the list
 * @param p_list the pointer to the list
 * @param p_obj the pointer to the new list member object to insert to
 *              the @a l_name list
 * @param l_name the name of the list
 */
#define mhd_DLINKEDL_INS_FIRST_D(p_list,p_obj,links_name) do { \
          mhd_assert (NULL == (p_obj)->links_name.prev); \
          mhd_assert (NULL == (p_obj)->links_name.next); \
          mhd_assert (((p_list)->first) || (! ((p_list)->last)));  \
          mhd_assert ((! ((p_list)->first)) || ((p_list)->last));  \
          if (NULL != (p_list)->first)                             \
          { mhd_assert (NULL == (p_list)->first->links_name.prev); \
            (p_obj)->links_name.next = (p_list)->first;            \
            (p_obj)->links_name.next->links_name.prev = (p_obj); } else \
          { (p_list)->last = (p_obj); } \
          (p_list)->first = (p_obj);  } while (0)

/**
 * Insert object into the last position in the list using direct pointer
 * to the list
 * @param p_list the pointer to the list
 * @param p_obj the pointer to the new list member object to insert to
 *              the @a l_name list
 * @param l_name the name of the list
 */
#define mhd_DLINKEDL_INS_LAST_D(p_list,p_obj,links_name) do { \
          mhd_assert (NULL == (p_obj)->links_name.prev); \
          mhd_assert (NULL == (p_obj)->links_name.next); \
          mhd_assert (((p_list)->first) || (! ((p_list)->last))); \
          mhd_assert ((! ((p_list)->first)) || ((p_list)->last)); \
          if (NULL != (p_list)->last)                             \
          { mhd_assert (NULL == (p_list)->last->links_name.next); \
            (p_obj)->links_name.prev = (p_list)->last;            \
            (p_obj)->links_name.prev->links_name.next = (p_obj); } else \
          { (p_list)->first = (p_obj); } \
          (p_list)->last = (p_obj);  } while (0)

/**
 * Remove object from the list using direct pointer to the list
 * @param p_list the pointer to the list
 * @param p_own the pointer to the existing @a l_name list member object
 *              to remove from the list
 * @param l_name the name of the list
 */
#define mhd_DLINKEDL_DEL_D(p_list,p_obj,links_name) do { \
          mhd_assert (NULL != (p_list)->first); \
          mhd_assert (NULL != (p_list)->last);  \
          if (NULL != (p_obj)->links_name.next) \
          { mhd_assert (NULL != (p_obj)->links_name.next->links_name.prev); \
            (p_obj)->links_name.next->links_name.prev =  \
              (p_obj)->links_name.prev; } else           \
          { mhd_assert ((p_obj) == (p_list)->last);      \
            (p_list)->last = (p_obj)->links_name.prev; } \
          if (NULL != (p_obj)->links_name.prev)          \
          { mhd_assert (NULL != (p_obj)->links_name.prev->links_name.next); \
            (p_obj)->links_name.prev->links_name.next =   \
              (p_obj)->links_name.next; } else            \
          { mhd_assert ((p_obj) == (p_list)->first);      \
            (p_list)->first = (p_obj)->links_name.next; } \
          (p_obj)->links_name.prev = NULL;                \
          (p_obj)->links_name.next = NULL;  } while (0)

/**
 * Get the fist object in the list using direct pointer to the list
 */
#define mhd_DLINKEDL_GET_FIRST_D(p_list) ((p_list)->first)

/**
 * Get the last object in the list using direct pointer to the list
 */
#define mhd_DLINKEDL_GET_LAST_D(p_list) ((p_list)->last)


/* ** The main interface ** */
/* These macros use identical names for the list object itself (within the
 * owner object) and the links object (within the list members). */

/* Initialisers */

/**
 * Initialise the double linked list pointers in the owner object
 * @param p_own the pointer to the owner object with the @a l_name list
 * @param l_name the name of the list
 */
#define mhd_DLINKEDL_INIT_LIST(p_own,list_name) \
        mhd_DLINKEDL_INIT_LIST_D (&((p_own)->list_name))

/**
 * Initialise the double linked list pointers in the list member object
 * @param p_obj the pointer to the future member object of the @a l_name list
 * @param l_name the name of the list
 */
#define mhd_DLINKEDL_INIT_LINKS(p_obj,links_name) \
        do {(p_obj)->links_name.prev = NULL;      \
            (p_obj)->links_name.next = NULL;} while (0)

/* List manipulations */

/**
 * Insert object into the first position in the list
 * @param p_own the pointer to the owner object with the @a l_name list
 * @param p_obj the pointer to the new list member object to insert to
 *              the @a l_name list
 * @param l_name the same name for the list and the links
 */
#define mhd_DLINKEDL_INS_FIRST(p_own,p_obj,l_name) \
        mhd_DLINKEDL_INS_FIRST_D (&((p_own)->l_name),(p_obj),l_name)

/**
 * Insert object into the last position in the list
 * @param p_own the pointer to the owner object with the @a l_name list
 * @param p_obj the pointer to the new list member object to insert to
 *              the @a l_name list
 * @param l_name the same name for the list and the links
 */
#define mhd_DLINKEDL_INS_LAST(p_own,p_obj,l_name) \
        mhd_DLINKEDL_INS_LAST_D (&((p_own)->l_name),(p_obj),l_name)

/**
 * Remove object from the list
 * @param p_mem the pointer to the owner object with the @a l_name list
 * @param p_own the pointer to the existing @a l_name list member object
 *              to remove from the list
 * @param l_name the same name for the list and the links
 */
#define mhd_DLINKEDL_DEL(p_own,p_obj,l_name) \
        mhd_DLINKEDL_DEL_D (&((p_own)->l_name),(p_obj),l_name)

/* List iterations */

/**
 * Get the fist object in the list
 */
#define mhd_DLINKEDL_GET_FIRST(p_own,list_name) \
        mhd_DLINKEDL_GET_FIRST_D (&((p_own)->list_name))

/**
 * Get the last object in the list
 */
#define mhd_DLINKEDL_GET_LAST(p_own,list_name) \
        mhd_DLINKEDL_GET_LAST_D (&((p_own)->list_name))

/**
 * Get the next object in the list
 */
#define mhd_DLINKEDL_GET_NEXT(p_obj,links_name) ((p_obj)->links_name.next)

/**
 * Get the previous object in the list
 */
#define mhd_DLINKEDL_GET_PREV(p_obj,links_name) ((p_obj)->links_name.prev)


#endif /* ! MHD_DLINKED_LIST_H */
