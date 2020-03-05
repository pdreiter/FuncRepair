#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
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

int server_fd, new_client;
struct sockaddr_in address;
char FLAG[21];

char checksum(char *s)
{
    signed char sum = -1;
    while (*s != 0)
    {
        sum += *s;
        s++;
    }
    return sum;
}
int runCheckSum(char *input_buffer,const char* myFLAG)
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
int validateEchoCommand(char *input_buffer)
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
int setupServer()
{
    int opt = 1; // reuse address

    // create socket file descriptor, attach to 8082
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
        return FALSE;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)))
        return FALSE;

    printf("Listening on port %i...\n", PORT);
    return TRUE;
}
int runServer()
{
    char buffer[BUFFER_SIZE];

    int addrlen = sizeof(address);

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
            int echo_result = validateEchoCommand(buffer);
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
int main(int argc, char **argv)
{
    // Assert that we are running on the testbed
    //assert_execution_on_testbed();

    if (argc != 2)
    {
        printf("Usage: ./example_2.bin <flag (1-20 characters)>\n");
    }
    if (strlen(argv[1]) > 20)
    {
        printf("Usage: ./example_2.bin <flag (1-20 characters)>\n");
    }

    strcpy(FLAG, argv[1]);

    if (setupServer() != 1)
    {
        printf("Server not started\n");
        return -1;
    }
    runServer();
    return 0;
}
