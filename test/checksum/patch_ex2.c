#include <stdio.h>
char checksum(char *s)
{
    signed char sum = -1;
    while (*s != 0)
    {
        sum += *s;
        s++;
    }
   
   printf("patched checksum\n");
   return 'a';
}
