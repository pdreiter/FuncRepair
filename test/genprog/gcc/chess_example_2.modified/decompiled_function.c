#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <testbed.h>

#define PORT 8082

#define FALSE 0
#define TRUE 1

#define BUFFER_SIZE 64

#define SERVER_HELLO "Enter Command (CHECKSUM or ECHO:<message size>:<message>):\n"
#define DELIMETER ":"
#define CHECKSUM_CMD "CHECKSUM"
#define ECHO_CMD "ECHO:"
#define R_INVALID_COMMAND "Invalid command.\n"

#define MSG_SMALL 100
#define MSG_LARGE 200
#define MSG_OK 300

#define R_MSG_SMALL "Message is too small!\n"
#define R_MSG_LARGE "Message is too large!\n"

//int server_fd, new_client;
//struct sockaddr_in address;
//char FLAG[21];
static inline long int strlen(const char* src){
    char *save=src;
	long int count=0;
	while(*save++!= '\0'){count=count+1;}
	return count;
}

static inline char* strcpy(char* dest, const char* src){
    char *save=dest;
	char *cp=src;
	while(*dest++=*cp++);
	return save;
}

static inline char checksum(char *s)
{
    signed char sum = -1;
    while (*s != 0)
    {
        sum += *s;
        s++;
    }
    return sum;
}
static inline int runCheckSum(char *input_buffer,const char* myFLAG)
{
    char copy_buffer[21];
    strcpy(copy_buffer, myFLAG);
    int gap = BUFFER_SIZE - strlen(copy_buffer);
    int i;
    for (i = 0; i < BUFFER_SIZE; i++)
    {
        if (i < gap)
            input_buffer[i] = '*';
        else
            input_buffer[i] = copy_buffer[i - gap];
    }
    return checksum(input_buffer);
}
