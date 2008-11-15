/*
 *      Copyright (C) 2004, 2006, 2007 Free Software Foundation
 *      Copyright (C) 2002  Fabio Fiorina
 *
 * This file is part of LIBTASN1.
 *
 * The LIBTASN1 library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */


/*****************************************************/
/* File: structure.c                                 */
/* Description: Functions to create and delete an    */
/*  ASN1 tree.                                       */
/*****************************************************/


#include <int.h>
#include <structure.h>
#include "parser_aux.h"
#include <gstr.h>


extern char MHD__asn1_identifierMissing[];

static node_asn *MHD__asn1_copy_structure2 (node_asn * root,
                                            const char *source_name);



/******************************************************/
/* Function : MHD__asn1_add_node_only                     */
/* Description: creates a new NODE_ASN element.       */
/* Parameters:                                        */
/*   type: type of the new element (see TYPE_         */
/*         and CONST_ constants).                     */
/* Return: pointer to the new element.                */
/******************************************************/
node_asn *
MHD__asn1_add_node_only (unsigned int type)
{
  node_asn *punt;

  punt = (node_asn *) MHD__asn1_calloc (1, sizeof (node_asn));
  if (punt == NULL)
    return NULL;

  punt->type = type;

  return punt;
}


/******************************************************************/
/* Function : MHD__asn1_find_left                                     */
/* Description: returns the NODE_ASN element with RIGHT field that*/
/*              points the element NODE.                          */
/* Parameters:                                                    */
/*   node: NODE_ASN element pointer.                              */
/* Return: NULL if not found.                                     */
/******************************************************************/
node_asn *
MHD__asn1_find_left (node_asn * node)
{
  if ((node == NULL) || (node->left == NULL) || (node->left->down == node))
    return NULL;

  return node->left;
}



/**
  * MHD__asn1_array2tree - Creates the structures needed to manage the ASN1 definitions.
  * @array: specify the array that contains ASN.1 declarations
  * @definitions: return the pointer to the structure created by
  *   *ARRAY ASN.1 declarations
  * @errorDescription: return the error description.
  *
  * Creates the structures needed to manage the ASN.1 definitions.
  * @array is a vector created by MHD__asn1_parser2array().
  *
  * Returns:
  *
  * ASN1_SUCCESS: Structure created correctly.
  *
  * ASN1_ELEMENT_NOT_EMPTY: *@definitions not ASN1_TYPE_EMPTY.
  *
  * ASN1_IDENTIFIER_NOT_FOUND: In the file there is an identifier that
  *   is not defined (see @errorDescription for more information).
  *
  * ASN1_ARRAY_ERROR: The array pointed by @array is wrong.
  **/
MHD__asn1_retCode
MHD__asn1_array2tree (const ASN1_ARRAY_TYPE * array, ASN1_TYPE * definitions,
                      char *errorDescription)
{
  node_asn *p, *p_last = NULL;
  unsigned long k;
  int move;
  MHD__asn1_retCode result;


  if (*definitions != ASN1_TYPE_EMPTY)
    return ASN1_ELEMENT_NOT_EMPTY;

  move = UP;

  k = 0;
  while (array[k].value || array[k].type || array[k].name)
    {
      p = MHD__asn1_add_node (array[k].type & (~CONST_DOWN));
      if (array[k].name)
        MHD__asn1_set_name (p, array[k].name);
      if (array[k].value)
        MHD__asn1_set_value (p, array[k].value, strlen (array[k].value) + 1);

      if (*definitions == NULL)
        *definitions = p;

      if (move == DOWN)
        MHD__asn1_set_down (p_last, p);
      else if (move == RIGHT)
        MHD__asn1_set_right (p_last, p);

      p_last = p;

      if (array[k].type & CONST_DOWN)
        move = DOWN;
      else if (array[k].type & CONST_RIGHT)
        move = RIGHT;
      else
        {
          while (1)
            {
              if (p_last == *definitions)
                break;

              p_last = MHD__asn1_find_up (p_last);

              if (p_last == NULL)
                break;

              if (p_last->type & CONST_RIGHT)
                {
                  p_last->type &= ~CONST_RIGHT;
                  move = RIGHT;
                  break;
                }
            }                   /* while */
        }
      k++;
    }                           /* while */

  if (p_last == *definitions)
    {
      result = MHD__asn1_check_identifier (*definitions);
      if (result == ASN1_SUCCESS)
        {
          MHD__asn1_change_integer_value (*definitions);
          MHD__asn1_expand_object_id (*definitions);
        }
    }
  else
    {
      result = ASN1_ARRAY_ERROR;
    }

  if (errorDescription != NULL)
    {
      if (result == ASN1_IDENTIFIER_NOT_FOUND)
        {
          Estrcpy (errorDescription, ":: identifier '");
          Estrcat (errorDescription, MHD__asn1_identifierMissing);
          Estrcat (errorDescription, "' not found");
        }
      else
        errorDescription[0] = 0;
    }

  if (result != ASN1_SUCCESS)
    {
      MHD__asn1_delete_list_and_nodes ();
      *definitions = ASN1_TYPE_EMPTY;
    }
  else
    MHD__asn1_delete_list ();

  return result;
}

/**
  * MHD__asn1_delete_structure - Deletes the structure pointed by *ROOT.
  * @structure: pointer to the structure that you want to delete.
  *
  * Deletes the structure *@structure.  At the end, *@structure is set
  * to ASN1_TYPE_EMPTY.
  *
  * Returns:
  *
  * ASN1_SUCCESS: Everything OK.
  *
  * ASN1_ELEMENT_NOT_FOUND: *@structure was ASN1_TYPE_EMPTY.
  *
  **/
MHD__asn1_retCode
MHD__asn1_delete_structure (ASN1_TYPE * structure)
{
  node_asn *p, *p2, *p3;

  if (*structure == ASN1_TYPE_EMPTY)
    return ASN1_ELEMENT_NOT_FOUND;

  p = *structure;
  while (p)
    {
      if (p->down)
        {
          p = p->down;
        }
      else
        {                       /* no down */
          p2 = p->right;
          if (p != *structure)
            {
              p3 = MHD__asn1_find_up (p);
              MHD__asn1_set_down (p3, p2);
              MHD__asn1_remove_node (p);
              p = p3;
            }
          else
            {                   /* p==root */
              p3 = MHD__asn1_find_left (p);
              if (!p3)
                {
                  p3 = MHD__asn1_find_up (p);
                  if (p3)
                    MHD__asn1_set_down (p3, p2);
                  else
                    {
                      if (p->right)
                        p->right->left = NULL;
                    }
                }
              else
                MHD__asn1_set_right (p3, p2);
              MHD__asn1_remove_node (p);
              p = NULL;
            }
        }
    }

  *structure = ASN1_TYPE_EMPTY;
  return ASN1_SUCCESS;
}



/**
  * MHD__asn1_delete_element - Deletes the element of a structure.
  * @structure: pointer to the structure that contains the element you
  *   want to delete.
  * @element_name: element's name you want to delete.
  *
  * Deletes the element named *@element_name inside *@structure.
  *
  * Returns:
  *
  * ASN1_SUCCESS: Everything OK.
  *
  * ASN1_ELEMENT_NOT_FOUND: The name element was not found.
  *
  **/
MHD__asn1_retCode
MHD__asn1_delete_element (ASN1_TYPE structure, const char *element_name)
{
  node_asn *p2, *p3, *source_node;

  source_node = MHD__asn1_find_node (structure, element_name);

  if (source_node == ASN1_TYPE_EMPTY)
    return ASN1_ELEMENT_NOT_FOUND;

  p2 = source_node->right;
  p3 = MHD__asn1_find_left (source_node);
  if (!p3)
    {
      p3 = MHD__asn1_find_up (source_node);
      if (p3)
        MHD__asn1_set_down (p3, p2);
      else if (source_node->right)
        source_node->right->left = NULL;
    }
  else
    MHD__asn1_set_right (p3, p2);

  return MHD__asn1_delete_structure (&source_node);
}

node_asn *
MHD__asn1_copy_structure3 (node_asn * source_node)
{
  node_asn *dest_node, *p_s, *p_d, *p_d_prev;
  int move;

  if (source_node == NULL)
    return NULL;

  dest_node = MHD__asn1_add_node_only (source_node->type);

  p_s = source_node;
  p_d = dest_node;

  move = DOWN;

  do
    {
      if (move != UP)
        {
          if (p_s->name)
            MHD__asn1_set_name (p_d, p_s->name);
          if (p_s->value)
            MHD__asn1_set_value (p_d, p_s->value, p_s->value_len);
          move = DOWN;
        }
      else
        move = RIGHT;

      if (move == DOWN)
        {
          if (p_s->down)
            {
              p_s = p_s->down;
              p_d_prev = p_d;
              p_d = MHD__asn1_add_node_only (p_s->type);
              MHD__asn1_set_down (p_d_prev, p_d);
            }
          else
            move = RIGHT;
        }

      if (p_s == source_node)
        break;

      if (move == RIGHT)
        {
          if (p_s->right)
            {
              p_s = p_s->right;
              p_d_prev = p_d;
              p_d = MHD__asn1_add_node_only (p_s->type);
              MHD__asn1_set_right (p_d_prev, p_d);
            }
          else
            move = UP;
        }
      if (move == UP)
        {
          p_s = MHD__asn1_find_up (p_s);
          p_d = MHD__asn1_find_up (p_d);
        }
    }
  while (p_s != source_node);

  return dest_node;
}


static node_asn *
MHD__asn1_copy_structure2 (node_asn * root, const char *source_name)
{
  node_asn *source_node;

  source_node = MHD__asn1_find_node (root, source_name);

  return MHD__asn1_copy_structure3 (source_node);

}


static MHD__asn1_retCode
MHD__asn1_type_choice_config (node_asn * node)
{
  node_asn *p, *p2, *p3, *p4;
  int move, tlen;

  if (node == NULL)
    return ASN1_ELEMENT_NOT_FOUND;

  p = node;
  move = DOWN;

  while (!((p == node) && (move == UP)))
    {
      if (move != UP)
        {
          if ((type_field (p->type) == TYPE_CHOICE) && (p->type & CONST_TAG))
            {
              p2 = p->down;
              while (p2)
                {
                  if (type_field (p2->type) != TYPE_TAG)
                    {
                      p2->type |= CONST_TAG;
                      p3 = MHD__asn1_find_left (p2);
                      while (p3)
                        {
                          if (type_field (p3->type) == TYPE_TAG)
                            {
                              p4 = MHD__asn1_add_node_only (p3->type);
                              tlen = strlen ((const char *) p3->value);
                              if (tlen > 0)
                                MHD__asn1_set_value (p4, p3->value, tlen + 1);
                              MHD__asn1_set_right (p4, p2->down);
                              MHD__asn1_set_down (p2, p4);
                            }
                          p3 = MHD__asn1_find_left (p3);
                        }
                    }
                  p2 = p2->right;
                }
              p->type &= ~(CONST_TAG);
              p2 = p->down;
              while (p2)
                {
                  p3 = p2->right;
                  if (type_field (p2->type) == TYPE_TAG)
                    MHD__asn1_delete_structure (&p2);
                  p2 = p3;
                }
            }
          move = DOWN;
        }
      else
        move = RIGHT;

      if (move == DOWN)
        {
          if (p->down)
            p = p->down;
          else
            move = RIGHT;
        }

      if (p == node)
        {
          move = UP;
          continue;
        }

      if (move == RIGHT)
        {
          if (p->right)
            p = p->right;
          else
            move = UP;
        }
      if (move == UP)
        p = MHD__asn1_find_up (p);
    }

  return ASN1_SUCCESS;
}


static MHD__asn1_retCode
MHD__asn1_expand_identifier (node_asn ** node, node_asn * root)
{
  node_asn *p, *p2, *p3;
  char name2[MAX_NAME_SIZE + 2];
  int move;

  if (node == NULL)
    return ASN1_ELEMENT_NOT_FOUND;

  p = *node;
  move = DOWN;

  while (!((p == *node) && (move == UP)))
    {
      if (move != UP)
        {
          if (type_field (p->type) == TYPE_IDENTIFIER)
            {
              MHD__asn1_str_cpy (name2, sizeof (name2), root->name);
              MHD__asn1_str_cat (name2, sizeof (name2), ".");
              MHD__asn1_str_cat (name2, sizeof (name2),
                                 (const char *) p->value);
              p2 = MHD__asn1_copy_structure2 (root, name2);
              if (p2 == NULL)
                {
                  return ASN1_IDENTIFIER_NOT_FOUND;
                }
              MHD__asn1_set_name (p2, p->name);
              p2->right = p->right;
              p2->left = p->left;
              if (p->right)
                p->right->left = p2;
              p3 = p->down;
              if (p3)
                {
                  while (p3->right)
                    p3 = p3->right;
                  MHD__asn1_set_right (p3, p2->down);
                  MHD__asn1_set_down (p2, p->down);
                }

              p3 = MHD__asn1_find_left (p);
              if (p3)
                MHD__asn1_set_right (p3, p2);
              else
                {
                  p3 = MHD__asn1_find_up (p);
                  if (p3)
                    MHD__asn1_set_down (p3, p2);
                  else
                    {
                      p2->left = NULL;
                    }
                }

              if (p->type & CONST_SIZE)
                p2->type |= CONST_SIZE;
              if (p->type & CONST_TAG)
                p2->type |= CONST_TAG;
              if (p->type & CONST_OPTION)
                p2->type |= CONST_OPTION;
              if (p->type & CONST_DEFAULT)
                p2->type |= CONST_DEFAULT;
              if (p->type & CONST_SET)
                p2->type |= CONST_SET;
              if (p->type & CONST_NOT_USED)
                p2->type |= CONST_NOT_USED;

              if (p == *node)
                *node = p2;
              MHD__asn1_remove_node (p);
              p = p2;
              move = DOWN;
              continue;
            }
          move = DOWN;
        }
      else
        move = RIGHT;

      if (move == DOWN)
        {
          if (p->down)
            p = p->down;
          else
            move = RIGHT;
        }

      if (p == *node)
        {
          move = UP;
          continue;
        }

      if (move == RIGHT)
        {
          if (p->right)
            p = p->right;
          else
            move = UP;
        }
      if (move == UP)
        p = MHD__asn1_find_up (p);
    }

  return ASN1_SUCCESS;
}


/**
  * MHD__asn1_create_element - Creates a structure of type SOURCE_NAME.
  * @definitions: pointer to the structure returned by "parser_asn1" function
  * @source_name: the name of the type of the new structure (must be
  *   inside p_structure).
  * @element: pointer to the structure created.
  *
  * Creates a structure of type @source_name.  Example using
  *  "pkix.asn":
  *
  * rc = MHD__asn1_create_structure(cert_def, "PKIX1.Certificate",
  * certptr);
  *
  * Returns:
  *
  * ASN1_SUCCESS: Creation OK.
  *
  * ASN1_ELEMENT_NOT_FOUND: SOURCE_NAME isn't known
  **/
MHD__asn1_retCode
MHD__asn1_create_element (ASN1_TYPE definitions, const char *source_name,
                          ASN1_TYPE * element)
{
  node_asn *dest_node;
  int res;

  dest_node = MHD__asn1_copy_structure2 (definitions, source_name);

  if (dest_node == NULL)
    return ASN1_ELEMENT_NOT_FOUND;

  MHD__asn1_set_name (dest_node, "");

  res = MHD__asn1_expand_identifier (&dest_node, definitions);
  MHD__asn1_type_choice_config (dest_node);

  *element = dest_node;

  return res;
}


/**
  * MHD__asn1_number_of_elements - Counts the number of elements of a structure.
  * @element: pointer to the root of an ASN1 structure.
  * @name: the name of a sub-structure of ROOT.
  * @num: pointer to an integer where the result will be stored
  *
  * Counts the number of elements of a sub-structure called NAME with
  * names equal to "?1","?2", ...
  *
  * Returns:
  *
  *  ASN1_SUCCESS: Creation OK.
  *
  *  ASN1_ELEMENT_NOT_FOUND: NAME isn't known.
  *
  *  ASN1_GENERIC_ERROR: Pointer num equal to NULL.
  *
  **/
MHD__asn1_retCode
MHD__asn1_number_of_elements (ASN1_TYPE element, const char *name, int *num)
{
  node_asn *node, *p;

  if (num == NULL)
    return ASN1_GENERIC_ERROR;

  *num = 0;

  node = MHD__asn1_find_node (element, name);
  if (node == NULL)
    return ASN1_ELEMENT_NOT_FOUND;

  p = node->down;

  while (p)
    {
      if ((p->name) && (p->name[0] == '?'))
        (*num)++;
      p = p->right;
    }

  return ASN1_SUCCESS;
}


/**
  * MHD__asn1_find_structure_from_oid - Locate structure defined by a specific OID.
  * @definitions: ASN1 definitions
  * @oidValue: value of the OID to search (e.g. "1.2.3.4").
  *
  * Search the structure that is defined just after an OID definition.
  *
  * Returns: NULL when OIDVALUE not found, otherwise the pointer to a
  *   constant string that contains the element name defined just
  *   after the OID.
  *
  **/
const char *
MHD__asn1_find_structure_from_oid (ASN1_TYPE definitions,
                                   const char *oidValue)
{
  char definitionsName[MAX_NAME_SIZE], name[2 * MAX_NAME_SIZE + 1];
  char value[MAX_NAME_SIZE];
  ASN1_TYPE p;
  int len;
  MHD__asn1_retCode result;

  if ((definitions == ASN1_TYPE_EMPTY) || (oidValue == NULL))
    return NULL;                /* ASN1_ELEMENT_NOT_FOUND; */


  strcpy (definitionsName, definitions->name);
  strcat (definitionsName, ".");

  /* search the OBJECT_ID into definitions */
  p = definitions->down;
  while (p)
    {
      if ((type_field (p->type) == TYPE_OBJECT_ID) &&
          (p->type & CONST_ASSIGN))
        {
          strcpy (name, definitionsName);
          strcat (name, p->name);

          len = MAX_NAME_SIZE;
          result = MHD__asn1_read_value (definitions, name, value, &len);

          if ((result == ASN1_SUCCESS) && (!strcmp (oidValue, value)))
            {
              p = p->right;
              if (p == NULL)    /* reach the end of ASN1 definitions */
                return NULL;    /* ASN1_ELEMENT_NOT_FOUND; */

              return p->name;
            }
        }
      p = p->right;
    }

  return NULL;                  /* ASN1_ELEMENT_NOT_FOUND; */
}

/**
 * MHD__asn1_copy_node:
 * @dst: Destination ASN1_TYPE node.
 * @dst_name: Field name in destination node.
 * @src: Source ASN1_TYPE node.
 * @src_name: Field name in source node.
 *
 * Create a deep copy of a ASN1_TYPE variable.
 *
 * Return value: Return ASN1_SUCCESS on success.
 **/
MHD__asn1_retCode
MHD__asn1_copy_node (ASN1_TYPE dst, const char *dst_name,
                     ASN1_TYPE src, const char *src_name)
{
/* FIXME: rewrite using copy_structure().
 * It seems quite hard to do.
 */
  int result;
  ASN1_TYPE dst_node;
  void *data = NULL;
  int size = 0;

  result = MHD__asn1_der_coding (src, src_name, NULL, &size, NULL);
  if (result != ASN1_MEM_ERROR)
    return result;

  data = MHD__asn1_malloc (size);
  if (data == NULL)
    return ASN1_MEM_ERROR;

  result = MHD__asn1_der_coding (src, src_name, data, &size, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD__asn1_free (data);
      return result;
    }

  dst_node = MHD__asn1_find_node (dst, dst_name);
  if (dst_node == NULL)
    {
      MHD__asn1_free (data);
      return ASN1_ELEMENT_NOT_FOUND;
    }

  result = MHD__asn1_der_decoding (&dst_node, data, size, NULL);

  MHD__asn1_free (data);

  return result;
}
