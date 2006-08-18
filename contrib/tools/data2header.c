/*
 * by Luis Figueiredo (stdio@netc.pt)
 */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <io.h>
#endif



int main(int argc, char *argv[]) { // Johannes E. Schindelin
	unsigned char ch;
	char *vn;
	unsigned int i=0;
	if(argc<2) {
		fprintf(stderr,"Need a name for VAR\n");
		exit(1);  // Johannes E. Schindelin
	};
	vn=malloc(strlen(argv[1])+1);
	for(i=0;i<strlen(argv[1]);i++)vn[i]=toupper(argv[1][i]);
	vn[i]='\0';
	printf("/*\n * by data2header by Luis Figueiredo (stdio@netc.pt)\n */\n");
	printf("#ifndef _%s_H_\n",vn);
	printf("#define _%s_H_\n\n",vn);
	free(vn);
	i=0;
	printf("char %s[]=\"",argv[1]);
	while(read(0,&ch,1)) {
		i++;if(i>25){i=0;printf("\"\n\"");};
		printf("\\x%X",ch);
	};
	printf("\";\n\n");
	printf("#endif\n");
	return 0; // Johannes E. Schindelin
};

		 

