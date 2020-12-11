struct _IO_FILE;
struct _IO_FILE *_coverage_fout  ;
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef long long intmax_t;
typedef unsigned long long uintmax_t;
typedef int intptr_t;
typedef unsigned int uintptr_t;
struct __anonstruct_imaxdiv_t_1 {
   intmax_t quot ;
   intmax_t rem ;
};
typedef struct __anonstruct_imaxdiv_t_1 imaxdiv_t;
typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef long wchar_t;
typedef unsigned long blkcnt_t;
typedef unsigned long blksize_t;
typedef unsigned long clock_t;
typedef uint64_t fsblkcnt_t;
typedef uint64_t fsfilcnt_t;
typedef uint32_t dev_t;
typedef uint16_t gid_t;
typedef uint16_t mode_t;
typedef uint16_t nlink_t;
typedef uint16_t uid_t;
typedef int32_t id_t;
typedef unsigned long ino_t;
typedef int32_t key_t;
typedef int32_t pid_t;
typedef int ssize_t;
typedef long suseconds_t;
typedef long useconds_t;
typedef long time_t;
typedef long long loff_t;
typedef long long off64_t;
typedef long off_t;
typedef unsigned long long ino64_t;
typedef long long blkcnt64_t;
typedef uint32_t uid32_t;
typedef uint32_t gid32_t;
typedef int32_t clockid_t;
typedef int32_t timer_t;
typedef long fpos_t;
typedef uint32_t socklen_t;
typedef uint16_t sa_family_t;
typedef unsigned short randbuf[3];
struct __anonstruct_div_t_2 {
   int quot ;
   int rem ;
};
typedef struct __anonstruct_div_t_2 div_t;
struct __anonstruct_ldiv_t_3 {
   long quot ;
   long rem ;
};
typedef struct __anonstruct_ldiv_t_3 ldiv_t;
struct __anonstruct_lldiv_t_4 {
   long long quot ;
   long long rem ;
};
typedef struct __anonstruct_lldiv_t_4 lldiv_t;
typedef __builtin_va_list va_list;
struct __stdio_file;
typedef struct __stdio_file FILE;
extern intmax_t strtoimax(char const   *nptr , char **endptr , int base ) ;
extern uintmax_t strtoumax(char const   *nptr , char **endptr , int base ) ;
extern intmax_t imaxabs(intmax_t j )  __attribute__((__const__)) ;
extern imaxdiv_t imaxdiv(intmax_t numerator , intmax_t denominator )  __attribute__((__const__)) ;
extern  __attribute__((__nothrow__)) void *( __attribute__((__leaf__)) calloc)(size_t nmemb ,
                                                                               size_t size )  __attribute__((__malloc__)) ;
extern  __attribute__((__nothrow__)) void *( __attribute__((__leaf__)) malloc)(size_t size )  __attribute__((__malloc__)) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) free)(void *ptr ) ;
extern  __attribute__((__nothrow__)) void *( __attribute__((__leaf__)) realloc)(void *ptr ,
                                                                                size_t size )  __attribute__((__malloc__)) ;
extern  __attribute__((__nothrow__)) void *( __attribute__((__leaf__)) reallocarray)(void *ptr ,
                                                                                     size_t nmemb ,
                                                                                     size_t size )  __attribute__((__malloc__,
__alloc_size__(2,3))) ;
extern  __attribute__((__nothrow__)) char *( __attribute__((__leaf__)) getenv)(char const   *name )  __attribute__((__pure__)) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) putenv)(char const   *string ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) setenv)(char const   *name ,
                                                                             char const   *value ,
                                                                             int overwrite ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) unsetenv)(char const   *name ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) system)(char const   *string ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) atexit)(void (*function)(void) ) ;
extern  __attribute__((__nothrow__)) float ( __attribute__((__leaf__)) strtof)(char const   *nptr ,
                                                                               char **endptr ) ;
extern  __attribute__((__nothrow__)) double ( __attribute__((__leaf__)) strtod)(char const   *nptr ,
                                                                                char **endptr ) ;
extern  __attribute__((__nothrow__)) long double ( __attribute__((__leaf__)) strtold)(char const   *nptr ,
                                                                                      char **endptr ) ;
extern  __attribute__((__nothrow__)) long ( __attribute__((__leaf__)) strtol)(char const   *nptr ,
                                                                              char **endptr ,
                                                                              int base ) ;
extern  __attribute__((__nothrow__)) unsigned long ( __attribute__((__leaf__)) strtoul)(char const   *nptr ,
                                                                                        char **endptr ,
                                                                                        int base ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) __ltostr)(char *s ,
                                                                               unsigned int size ,
                                                                               unsigned long i ,
                                                                               unsigned int base ,
                                                                               int UpCase ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) __dtostr)(double d ,
                                                                               char *buf ,
                                                                               unsigned int maxlen ,
                                                                               unsigned int prec ,
                                                                               unsigned int prec2 ,
                                                                               int flags ) ;
extern  __attribute__((__nothrow__)) long long ( __attribute__((__leaf__)) strtoll)(char const   *nptr ,
                                                                                    char **endptr ,
                                                                                    int base ) ;
extern  __attribute__((__nothrow__)) unsigned long long ( __attribute__((__leaf__)) strtoull)(char const   *nptr ,
                                                                                              char **endptr ,
                                                                                              int base ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) __lltostr)(char *s ,
                                                                                unsigned int size ,
                                                                                unsigned long long i ,
                                                                                unsigned int base ,
                                                                                int UpCase ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) atoi)(char const   *nptr ) ;
extern  __attribute__((__nothrow__)) long ( __attribute__((__leaf__)) atol)(char const   *nptr ) ;
extern  __attribute__((__nothrow__)) double ( __attribute__((__leaf__)) atof)(char const   *nptr ) ;
extern long long atoll(char const   *nptr ) ;
extern  __attribute__((__nothrow__,
__noreturn__)) void ( __attribute__((__leaf__)) exit)(int status ) ;
extern  __attribute__((__nothrow__,
__noreturn__)) void ( __attribute__((__leaf__)) abort)(void) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) rand)(void) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) rand_r)(unsigned int *seed ) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) srand)(unsigned int seed ) ;
extern  __attribute__((__nothrow__)) double ( __attribute__((__leaf__)) drand48)(void) ;
extern  __attribute__((__nothrow__)) long ( __attribute__((__leaf__)) lrand48)(void) ;
extern  __attribute__((__nothrow__)) long ( __attribute__((__leaf__)) mrand48)(void) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) srand48)(long seed ) ;
extern  __attribute__((__nothrow__)) unsigned short *( __attribute__((__leaf__)) seed48)(unsigned short *buf ) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) lcong48)(unsigned short *param ) ;
extern  __attribute__((__nothrow__)) long ( __attribute__((__leaf__)) jrand48)(unsigned short *buf ) ;
extern  __attribute__((__nothrow__)) long ( __attribute__((__leaf__)) nrand48)(unsigned short *buf ) ;
extern  __attribute__((__nothrow__)) double ( __attribute__((__leaf__)) erand48)(unsigned short *buf ) ;
extern void qsort(void *base , size_t nmemb , size_t size ,
                  int (*compar)(void const   * , void const   * ) ) ;
extern void *bsearch(void const   *key , void const   *base , size_t nmemb ,
                     size_t size , int (*compar)(void const   * ,
                                                 void const   * ) ) ;
extern char **environ ;
extern  __attribute__((__nothrow__)) char *( __attribute__((__leaf__)) realpath)(char const   *path ,
                                                                                 char *resolved_path ) ;
extern int mkstemp(char *_template ) ;
extern char *mkdtemp(char *_template ) ;
extern char *mktemp(char *_template ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) abs)(int i )  __attribute__((__const__)) ;
extern  __attribute__((__nothrow__)) long ( __attribute__((__leaf__)) labs)(long i )  __attribute__((__const__)) ;
extern  __attribute__((__nothrow__)) long long ( __attribute__((__leaf__)) llabs)(long long i )  __attribute__((__const__)) ;
extern div_t div(int numerator , int denominator ) ;
extern ldiv_t ldiv(long numerator , long denominator ) ;
extern lldiv_t lldiv(long long numerator , long long denominator ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) mbtowc)(wchar_t *pwc ,
                                                                             char const   *s ,
                                                                             size_t n ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) wctomb)(char *s ,
                                                                             wchar_t wc ) ;
extern  __attribute__((__nothrow__)) size_t ( __attribute__((__leaf__)) mbstowcs)(wchar_t *dest ,
                                                                                  char const   *src ,
                                                                                  size_t n ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) mblen)(char const   *s ,
                                                                            size_t n )  __attribute__((__pure__)) ;
extern  __attribute__((__nothrow__)) size_t ( __attribute__((__leaf__)) wcstombs)(char *dest ,
                                                                                  wchar_t const   *src ,
                                                                                  size_t n ) ;
extern  __attribute__((__nothrow__)) uint32_t ( __attribute__((__leaf__)) arc4random)(void) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) arc4random_buf)(void *buf ,
                                                                                      size_t n ) ;
extern  __attribute__((__nothrow__)) uint32_t ( __attribute__((__leaf__)) arc4random_uniform)(uint32_t upper_bound ) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) arc4random_stir)(void) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) arc4random_addrandom)(unsigned char *dat ,
                                                                                            size_t datlen ) ;
extern FILE *stdin ;
extern FILE *stdout ;
extern FILE *stderr ;
extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) fopen)(char const   *path ,
                                                                              char const   *mode ) ;
extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) fdopen)(int fildes ,
                                                                               char const   *mode ) ;
extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) freopen)(char const   *path ,
                                                                                char const   *mode ,
                                                                                FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) printf)(char const   *format 
                                                                                                    , ...) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) fprintf)(FILE *stream ,
                                                                                                     char const   *format 
                                                                                                     , ...) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) sprintf)(char *str ,
                                                                                                     char const   *format 
                                                                                                     , ...) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) snprintf)(char *str ,
                                                                                                      size_t size ,
                                                                                                      char const   *format 
                                                                                                      , ...) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) asprintf)(char **ptr ,
                                                                                                      char const   *format 
                                                                                                      , ...) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) scanf)(char const   *format 
                                                                                                   , ...) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) fscanf)(FILE *stream ,
                                                                                                    char const   *format 
                                                                                                    , ...) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) sscanf)(char const   *str ,
                                                                                                    char const   *format 
                                                                                                    , ...) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) vprintf)(char const   *format ,
                                                                                                     va_list ap ) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) vfprintf)(FILE *stream ,
                                                                                                      char const   *format ,
                                                                                                      va_list ap ) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) vsprintf)(char *str ,
                                                                                                      char const   *format ,
                                                                                                      va_list ap ) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) vsnprintf)(char *str ,
                                                                                                       size_t size ,
                                                                                                       char const   *format ,
                                                                                                       va_list ap ) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) fdprintf)(int fd ,
                                                                                                      char const   *format 
                                                                                                      , ...) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) vfdprintf)(int fd ,
                                                                                                       char const   *format ,
                                                                                                       va_list ap ) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) vscanf)(char const   *format ,
                                                                                                    va_list ap ) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) vsscanf)(char const   *str ,
                                                                                                     char const   *format ,
                                                                                                     va_list ap ) ;
extern  __attribute__((__nothrow__)) int ( /* format attribute */ __attribute__((__leaf__)) vfscanf)(FILE *stream ,
                                                                                                     char const   *format ,
                                                                                                     va_list ap ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fgetc)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fgetc_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) char *( __attribute__((__leaf__)) fgets)(char *s ,
                                                                              int size ,
                                                                              FILE *stream ) ;
extern  __attribute__((__nothrow__)) char *( __attribute__((__leaf__)) fgets_unlocked)(char *s ,
                                                                                       int size ,
                                                                                       FILE *stream ) ;
extern  __attribute__((__nothrow__)) char *( __attribute__((__leaf__)) gets)(char *s ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) ungetc)(int c ,
                                                                             FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) ungetc_unlocked)(int c ,
                                                                                      FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fputc)(int c ,
                                                                            FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fputc_unlocked)(int c ,
                                                                                     FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fputs)(char const   *s ,
                                                                            FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fputs_unlocked)(char const   *s ,
                                                                                     FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) getc)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) getchar)(void) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) putchar)(int c ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) putchar_unlocked)(int c ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) puts)(char const   *s ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fseek)(FILE *stream ,
                                                                            long offset ,
                                                                            int whence ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fseek_unlocked)(FILE *stream ,
                                                                                     long offset ,
                                                                                     int whence ) ;
extern  __attribute__((__nothrow__)) long ( __attribute__((__leaf__)) ftell)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) long ( __attribute__((__leaf__)) ftell_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fseeko)(FILE *stream ,
                                                                             off_t offset ,
                                                                             int whence ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fseeko_unlocked)(FILE *stream ,
                                                                                      off_t offset ,
                                                                                      int whence ) ;
extern  __attribute__((__nothrow__)) off_t ( __attribute__((__leaf__)) ftello)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) off_t ( __attribute__((__leaf__)) ftello_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fseeko64)(FILE *stream ,
                                                                               loff_t offset ,
                                                                               int whence ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fseeko64_unlocked)(FILE *stream ,
                                                                                        loff_t offset ,
                                                                                        int whence ) ;
extern  __attribute__((__nothrow__)) loff_t ( __attribute__((__leaf__)) ftello64)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) loff_t ( __attribute__((__leaf__)) ftello64_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) rewind)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fgetpos)(FILE *stream ,
                                                                              fpos_t *pos ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fsetpos)(FILE *stream ,
                                                                              fpos_t *pos ) ;
extern  __attribute__((__nothrow__)) size_t ( __attribute__((__leaf__)) fread)(void *ptr ,
                                                                               size_t size ,
                                                                               size_t nmemb ,
                                                                               FILE *stream ) ;
extern  __attribute__((__nothrow__)) size_t ( __attribute__((__leaf__)) fread_unlocked)(void *ptr ,
                                                                                        size_t size ,
                                                                                        size_t nmemb ,
                                                                                        FILE *stream ) ;
extern  __attribute__((__nothrow__)) size_t ( __attribute__((__leaf__)) fwrite)(void const   *ptr ,
                                                                                size_t size ,
                                                                                size_t nmemb ,
                                                                                FILE *stream ) ;
extern  __attribute__((__nothrow__)) size_t ( __attribute__((__leaf__)) fwrite_unlocked)(void const   *ptr ,
                                                                                         size_t size ,
                                                                                         size_t nmemb ,
                                                                                         FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fflush)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fflush_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fclose)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fclose_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) feof)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) feof_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) ferror)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) ferror_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fileno)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) fileno_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) clearerr)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) clearerr_unlocked)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) remove)(char const   *pathname ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) rename)(char const   *oldpath ,
                                                                             char const   *newpath ) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) perror)(char const   *s ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) setvbuf)(FILE *stream ,
                                                                              char *buf ,
                                                                              int mode ,
                                                                              size_t size ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) setvbuf_unlocked)(FILE *stream ,
                                                                                       char *buf ,
                                                                                       int mode ,
                                                                                       size_t size ) ;
extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) popen)(char const   *command ,
                                                                              char const   *type ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) pclose)(FILE *stream ) ;
extern  __attribute__((__nothrow__)) char *( __attribute__((__leaf__)) tmpnam)(char *s ) ;
extern char *tempnam(char *dir , char *_template ) ;
extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) tmpfile)(void) ;
extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) tmpfile_unlocked)(void) ;
extern char *ctermid(char *s ) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) flockfile)(FILE *f ) ;
extern  __attribute__((__nothrow__)) void ( __attribute__((__leaf__)) funlockfile)(FILE *f ) ;
extern  __attribute__((__nothrow__)) int ( __attribute__((__leaf__)) ftrylockfile)(FILE *__stream ) ;
char mychecksum(char *s ) 
{ 
  signed char sum ;

  {
  {
  if (_coverage_fout == 0) {
    {
    _coverage_fout = fopen("/home/bss-lab-1/FunctionRepair/FuncRepair/test/checksum/./coverage.path",
                           "ab");
    }
  }
  }
  {
  fprintf(_coverage_fout, "1\n");
  fflush(_coverage_fout);
  }
  sum = (signed char)-1;
  {
  fprintf(_coverage_fout, "2\n");
  fflush(_coverage_fout);
  }
  while (1) {
    {
    fprintf(_coverage_fout, "3\n");
    fflush(_coverage_fout);
    }
    if ((int )*s != 0) {
      {
      fprintf(_coverage_fout, "4\n");
      fflush(_coverage_fout);
      }

    } else {
      break;
    }
    {
    fprintf(_coverage_fout, "6\n");
    fflush(_coverage_fout);
    }
    if ((int )*s == 48) {
      {
      fprintf(_coverage_fout, "7\n");
      fflush(_coverage_fout);
      }
      return ((char)0);
    } else {
      {
      fprintf(_coverage_fout, "8\n");
      fflush(_coverage_fout);
      }

    }
    {
    fprintf(_coverage_fout, "9\n");
    fflush(_coverage_fout);
    }
    sum = (signed char )((int )sum + (int )*s);
    {
    fprintf(_coverage_fout, "10\n");
    fflush(_coverage_fout);
    }
    s ++;
  }
  {
  fprintf(_coverage_fout, "11\n");
  fflush(_coverage_fout);
  }
  return ((char )sum);
}
}
char checksum(char *s ) 
{ 
  char tmp ;

  {
  tmp = mychecksum(s);
  return (tmp);
}
}
int main(int argc , char **argv ) 
{ 
  FILE *x ;
  FILE *tmp ;
  char tmp___0 ;
  char tmp___1 ;

  {
  {
  if (_coverage_fout == 0) {
    {
    _coverage_fout = fopen("/home/bss-lab-1/FunctionRepair/FuncRepair/test/checksum/./coverage.path",
                           "ab");
    }
  }
  }
  {
  fprintf(_coverage_fout, "14\n");
  fflush(_coverage_fout);
  }
  tmp = fopen("debug.text", "ab");
  {
  fprintf(_coverage_fout, "15\n");
  fflush(_coverage_fout);
  }
  x = tmp;
  {
  fprintf(_coverage_fout, "16\n");
  fflush(_coverage_fout);
  }
  fflush(x);
  {
  fprintf(_coverage_fout, "17\n");
  fflush(_coverage_fout);
  }
  if (argc != 2) {
    {
    fprintf(_coverage_fout, "18\n");
    fflush(_coverage_fout);
    }
    fprintf(x, "Usage: %s <string> \n", *(argv + 0));
    {
    fprintf(_coverage_fout, "19\n");
    fflush(_coverage_fout);
    }
    exit(-1);
  } else {
    {
    fprintf(_coverage_fout, "20\n");
    fflush(_coverage_fout);
    }

  }
  {
  fprintf(_coverage_fout, "21\n");
  fflush(_coverage_fout);
  }
  tmp___0 = checksum(*(argv + 1));
  {
  fprintf(_coverage_fout, "22\n");
  fflush(_coverage_fout);
  }
  fprintf(x, "patched: checksum(%s) = %d\n", *(argv + 1), (int )tmp___0);
  {
  fprintf(_coverage_fout, "23\n");
  fflush(_coverage_fout);
  }
  tmp___1 = checksum(*(argv + 1));
  {
  fprintf(_coverage_fout, "24\n");
  fflush(_coverage_fout);
  }
  printf("patched: checksum(%s) = %d\n", *(argv + 1), (int )tmp___1);
  {
  fprintf(_coverage_fout, "25\n");
  fflush(_coverage_fout);
  }
  return (0);
}
}
