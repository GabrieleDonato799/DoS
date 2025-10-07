#include "common.h"
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <math.h>

/**
 * @brief Returns an heap allocated, null terminated copy of the string.
 * The returned string is N + 1 characters long.
 * For the behaviour see strncpy.
 * 
 * @param s 
 * @return char* 
 */
char * StringNCopy(const char * const s, const int N){
    char * copy = NULL;
    
    if(!s || N < 0) die("StringNCopy");
    copy = MallocString(N);
    if(copy)
        strncpy(copy, s, N);
    
    return copy;
}

/**
 * @brief Returns an heap allocated, null terminated copy of the string.
 * 
 * @param s 
 * @return char* 
 */
char * StringCopy(const char * const s){
    char * copy = NULL;
    
    if(!s) die("StringCopy");
    copy = MallocString(strlen(s));
    if(copy)
        strncpy(copy, s, strlen(s));
    
    return copy;
}

/**
 * @brief Allocates and returns a NULL terminated unitialized string.
 * If the calling code doesn't go past the terminator, it doesn't have to be set manually.
 * 
 * @param strContentSize 
 * @return char* 
 */
char * MallocString(const int strContentSize){
    char * res;
    if ((res = (char *)malloc(sizeof(char)*(strContentSize + 1))) == NULL) {
        die("malloc");
    }
    res[strContentSize] = '\0';
    return res;
}

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

void _logger(const char * functionName, const char * fmt, ...){
    static char msg[8192];
    va_list args;
    
    // format the message like needed
    va_start( args, fmt );
    vsnprintf(msg, 8192, fmt, args);
    va_end( args );

    printf("[%20s][pid: %5d, ppid: %5d] %s", functionName, getpid(), getppid(), msg);
}

char * itoa(int n){
    char * str = NULL;
    
    if(n<0) return NULL;

    str = MallocString(12); // enough to handle a 32 bit integer with sign
    if(str)
        sprintf(str, "%d", n);

    return str;
}