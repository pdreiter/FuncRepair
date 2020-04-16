#include <stdio.h>
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
