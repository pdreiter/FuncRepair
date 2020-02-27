/* Copyright (C) 1991-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

 #include <stdarg.h>
 #include <stddef.h>

#define stdout 1

// Write syscall
// =============
static long _write(long fd, const char* buf, unsigned long len) {

  register long ret asm ("rax");
  register long _fd asm ("rdi") = fd;
  register const char* _buf asm ("rsi") = buf;
  register unsigned long _len asm ("rdx") = len;
  register int sys_write asm ("rax") = 1;
  asm volatile (
      "syscall;"
      : "=r" (ret)
      : "r" (_fd), "r" (_buf), "r" (_len), "r" (sys_write)
      :
  );
  return ret;
}


// exit syscall
// =============
static long _exit(int errcode) {

  register long ret asm ("rax");
  register int _errcode asm ("rdi") = errcode;
  register int sys_exit asm ("rax") = 60;
  asm volatile (
      "syscall;"
      : "=r" (ret)
      : "r" (_errcode), "r" (sys_exit)
      :
  );
  return ret;
}



static inline char *convert(unsigned int num, int base)
{
	static char Representation[]= "0123456789ABCDEF";
	static char buffer[50];
	char *ptr;

	ptr = &buffer[49];
	*ptr = '\0';

	do
	{
		*--ptr = Representation[num%base];
		num /= base;
	}while(num != 0);

	return(ptr);
}

static inline int vfprintf(long fd, const char *format, va_list arg) {
    char *traverse;
	unsigned int i;
	char *s;
	static char buffer;
	for(traverse = format; *traverse != '\0'; traverse++) 
	{ 
		while( (*traverse != '%') && (*traverse !='\0') )
		{ 
			buffer=*traverse;
			_write(fd,traverse,1);
			traverse++; 
		} 
		if (*traverse == '\0'){
		   break;
		}
		// skip over %
		traverse++; 
		
		//Module 2: Fetching and executing arguments
		switch(*traverse) 
		{ 
			case 'c' : i = va_arg(arg,int);		//Fetch char argument
						_write(fd,i,1);
						break; 
						
			case 'd' : i = va_arg(arg,int); 		//Fetch Decimal/Integer argument
						s = convert(i,10);
						if(i<0) 
						{ 
							i = -i;
							_write(fd,'-',1); 
						} 
						_write(fd,s,sizeof(s));
						break; 
						
			case 'o': i = va_arg(arg,unsigned int); //Fetch Octal representation
			          s= convert(i,8);
						_write(fd,s,sizeof(s));
						break; 
						
			case 's': s = va_arg(arg,char *); 		//Fetch string
						_write(fd,s,sizeof(s)); 
						break; 
						
			case 'x': i = va_arg(arg,unsigned int); //Fetch Hexadecimal representation
						s=convert(i,16);
						_write(fd,s,sizeof(s)); 
						break; 
		}	
	} 
}

#undef printf

/* Write formatted output to stdout from the format string FORMAT.  */
/* VARARGS1 */
static inline int
printf (const char *format, ...)
{
  va_list arg;
  int done;

  va_start (arg, format);
  done = vfprintf (stdout, format, arg);
  va_end (arg);

  return done;
}


/*
int main()
{
printf("printf test message\n");
_write(stdout,"_write Hello world!",10);
return 0;
}
*/
