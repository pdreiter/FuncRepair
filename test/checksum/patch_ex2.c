#include <stdlib.h>
#include <stdio.h>
char mychecksum(char *s)
{
    signed char sum = -1;
    while (*s != 0)
    {
		if (*s == '0') {
			return 0;
		}
        sum += *s;
        s++;
    }
   
   return sum;
}

char checksum(char *s) { 
   return mychecksum(s);
}


int main(int argc, char **argv) {
  //printf("do_checksum:\n");
  FILE* x=fopen("debug.text","ab");
  fflush(x);
  if (argc != 2) {
    fprintf(x,"Usage: %s <string> \n", argv[0]);
    exit(-1);
  }

  fprintf(x,"patched: checksum(%s) = %d\n", argv[1], checksum(argv[1]));
  printf("patched: checksum(%s) = %d\n", argv[1], checksum(argv[1]));
  return 0;
}

