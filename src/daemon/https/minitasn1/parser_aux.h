
#ifndef _PARSER_AUX_H
#define _PARSER_AUX_H


/***************************************/
/*  Functions used by ASN.1 parser     */
/***************************************/
node_asn *
_asn1_add_node(unsigned int type);

node_asn *
_asn1_set_value(node_asn *node,const void *value,unsigned int len);

node_asn *
_asn1_set_name(node_asn *node,const char *name);

node_asn *
_asn1_set_right(node_asn *node,node_asn *right);

node_asn *
_asn1_get_right(node_asn *node);

node_asn *
_asn1_get_last_right(node_asn *node);

node_asn *
_asn1_set_down(node_asn *node,node_asn *down);

char *
_asn1_get_name(node_asn *node);

node_asn *
_asn1_get_down(node_asn *node);

node_asn *
_asn1_mod_type(node_asn *node,unsigned int value);

void
_asn1_remove_node(node_asn *node);

void _asn1_delete_list(void);

void _asn1_delete_list_and_nodes(void);

char * _asn1_ltostr(long v,char *str);

node_asn * _asn1_find_up(node_asn *node);

asn1_retCode _asn1_change_integer_value(ASN1_TYPE node);

asn1_retCode _asn1_expand_object_id(ASN1_TYPE node);

asn1_retCode _asn1_type_set_config(ASN1_TYPE node);

asn1_retCode _asn1_check_identifier(ASN1_TYPE node);

asn1_retCode _asn1_set_default_tag(ASN1_TYPE node);

#endif



