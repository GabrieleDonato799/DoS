#include "common.h"
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <math.h>

int Recv(int sockfd, void *buf, size_t len, int flags){
    int moved;
    if ((moved = recv(sockfd, buf, len, flags)) < 0) {
        die("recv");
    }
    return moved;
}

int Send(int sockfd, void *buf, size_t len, int flags){
    int moved;
    if ((moved = send(sockfd, buf, len, flags)) < 0) {
        die("send");
    }
    return moved;
}

void die(const char *syscallName) {
    logger(syscallName, "Died!\n");
    perror("");
    exit(EXIT_FAILURE);
}

void logger(const char * functionName, const char * fmt, ...){
    static char * msg = NULL;
    va_list args;

    msg = (char *)malloc(sizeof(char)*8192 +1);

    // format the message like needed
    va_start( args, fmt );
    vsnprintf(msg, 8192, fmt, args);
    va_end( args );

    printf("[%20s][pid: %5d, ppid: %5d] %s", functionName, getpid(), getppid(), msg);

    free(msg);
}

char * itoa(int n){
    char * str = NULL;
    
    if(n<0) return NULL;

    str = (char *)malloc(12); // enough to handle a 32 bit integer with sign
    if(str)
        sprintf(str, "%d", n);

    return str;
}