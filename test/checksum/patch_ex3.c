#include "stdio-common/printf.c"
//#include <stdio.h>

char checksum(char *s)
{
    int x = fopen("tmp","w");
    fprintf(x,"patched checksum\n");
	fflush(x);
    signed char sum = -1;
    while (*s != 0)
    {
        sum += *s;
        s++;
    }
   
   return 'a';
}
