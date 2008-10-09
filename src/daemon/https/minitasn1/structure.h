
/*************************************************/
/* File: structure.h                             */
/* Description: list of exported object by       */
/*   "structure.c"                               */
/*************************************************/

#ifndef _STRUCTURE_H
#define _STRUCTURE_H

MHD__asn1_retCode MHD__asn1_create_static_structure (node_asn * pointer,
                                            char *output_file_name,
                                            char *vector_name);

node_asn *MHD__asn1_copy_structure3 (node_asn * source_node);

node_asn *MHD__asn1_copy_structure2 (node_asn * root, const char *source_name);

node_asn *MHD__asn1_add_node_only (unsigned int type);

node_asn *MHD__asn1_find_left (node_asn * node);

#endif
