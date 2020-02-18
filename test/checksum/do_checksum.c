#include <stdio.h>
#include <stdlib.h>

char checksum(char *s)
{
   printf("original checksum\n");
    signed char sum = -1;
    while (*s != 0)
    {
        sum += *s;
        s++;
    }
    return sum;
}





int main(int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s <string> \n", argv[0]);
    exit(-1);
  }

  printf("checksum(%s) = %d\n", argv[1], checksum(argv[1]));
  return 0;
}

