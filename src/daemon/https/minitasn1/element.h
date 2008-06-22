
#ifndef _ELEMENT_H
#define _ELEMENT_H


asn1_retCode _asn1_append_sequence_set(node_asn *node);

asn1_retCode _asn1_convert_integer(const char *value,unsigned char *value_out,
			  int value_out_size, int *len);

void _asn1_hierarchical_name(node_asn *node,char *name,int name_size);

#endif
