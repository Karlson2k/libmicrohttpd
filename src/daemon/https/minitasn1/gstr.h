void _asn1_str_cpy( char* dest, size_t dest_tot_size, const char* src);
void _asn1_str_cat( char* dest, size_t dest_tot_size, const char* src);

#define Estrcpy(x,y) _asn1_str_cpy(x,MAX_ERROR_DESCRIPTION_SIZE,y)
#define Estrcat(x,y) _asn1_str_cat(x,MAX_ERROR_DESCRIPTION_SIZE,y)
