#include <stdlib.h>
#include <stdio.h>


//int checksum(char* a0)
int mychecksum(char* a0)
{
    char s_5;
    unsigned int r;

    s_5 = 255;
    while(1)
    {
        if ((int)*(a0) & 255 != 0)
        {
            if (*(a0) != 48)
            {
                s_5 = s_5 + *(a0);
                a0 = a0 + 0x1;
            }
            else
            {
                r = 0;
                break;
            }
        }
        else
        {
            r = (int)s_5;
            break;
        }
    }
    return r;
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

