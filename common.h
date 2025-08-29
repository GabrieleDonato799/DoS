#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>

// takes the syscall' name to show its errno message
void die(const char *);

int Recv(int sockfd, void *buf, size_t len, int flags);

int Send(int sockfd, void *buf, size_t len, int flags);

/**
 * @brief Takes a message and logs it to the specified file
 * 
 */
void logger(const char *, const char *, ...);

/**
 * @brief Takes a integer and returns the equivalente ASCII representation.
 * 
 * @return char* 
 */
char * itoa(int);

#endif // COMMON_H