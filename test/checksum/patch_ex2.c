#include "stdio-common/printf.c"
char checksum(char *s)
{
   printf("patched checksum\n");
    signed char sum = -1;
    while (*s != 0)
    {
        sum += *s;
        s++;
    }
   
   return 'a';
}
