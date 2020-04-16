#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

static char checksum(char *s)
{
    signed char sum = -1;
    while (*s != 0)
    {
        sum += *s;
        s++;
    }
    return sum;
}
static int runCheckSum(char *input_buffer,const char* myFLAG)
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
static int validateEchoCommand(char *input_buffer,int new_client)
{
    // Validate echo message
    int parts = 0;
    int size = 0;
    const char *message;
    char *pt;

    pt = strtok(input_buffer, DELIMETER);
    while (pt != NULL)
    {
        if (parts == 1)
            size = atoi(pt);
        else if (parts == 2)
            message = pt;
        else if (parts > 2)
            break;
        pt = strtok(NULL, DELIMETER);
        parts++;
    }

    int offset = message - input_buffer;

    if (size < 1)
        return MSG_SMALL;
    else if (strlen(message) < 2)
        return MSG_SMALL;
    else if (size > BUFFER_SIZE - offset)
        return MSG_LARGE;
    send(new_client, message, strlen(message), 0);
    return MSG_OK;
}

int runServer(int *server_fd_ptr, struct sockaddr_in *address_ptr,const char *FLAG )
{
    char buffer[BUFFER_SIZE];

	int new_client;
	int server_fd = *server_fd_ptr;
	struct sockaddr_in address = *address_ptr;

    int addrlen = sizeof(address);
    printf("in patched function runServer");
    while (1)
    {
        listen(server_fd, 10);
        new_client = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        send(new_client, SERVER_HELLO, strlen(SERVER_HELLO), 0);

        // Read and process input
        recv(new_client, buffer, 1024, 0);
        printf("Processing Input: %s\n", buffer);

        // Check if user requested checksum
        if (!strncmp(buffer, CHECKSUM_CMD, strlen(CHECKSUM_CMD)))
        {
            int checksum_result = runCheckSum(buffer,FLAG);
            // Send checksum result
            char checksum_str[strlen("CHECKSUM=\n") + 10];
            sprintf(checksum_str, "CHECKSUM=%d\n", checksum_result);
            send(new_client, checksum_str, strlen(checksum_str), 0);
            // ** Suggested patch reset buffer before next read
            // memset(buffer, 0, sizeof buffer);
        }
        else if (!strncmp(buffer, ECHO_CMD, strlen(ECHO_CMD)))
        {
            // Expected format: ECHO:<echo message size>:<message>
            int echo_result = validateEchoCommand(buffer,new_client);
            if (echo_result == MSG_SMALL)
                send(new_client, R_MSG_SMALL, strlen(R_MSG_SMALL), 0);
            else if (echo_result == MSG_LARGE)
                send(new_client, R_MSG_LARGE, strlen(R_MSG_LARGE), 0);
            memset(buffer, 0, sizeof buffer);
        }
        else
        {
            send(new_client, R_INVALID_COMMAND, strlen(R_INVALID_COMMAND), 0);
            memset(buffer, 0, sizeof buffer);
        }
        close(new_client);
        printf("Response Sent\n");
    }
    return 1;
}

#ifdef _TRY_DL_START_
extern void _start(void);

unsigned int INITIALIZED=0;

int runServer_entry(int *server_fd_ptr, struct sockaddr_in *address_ptr,const char *FLAG ){
 if (!INITIALIZED){ 
	_start();
    INITIALIZED=1;
 }
 return runServer(server_fd_ptr, address_ptr,FLAG );
}

#else

void main(){

}

#endif
