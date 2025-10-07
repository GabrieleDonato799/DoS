#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>

#define logger(fmt, ...) _logger(__func__, fmt, ##__VA_ARGS__)

// takes the syscall' name to show its errno message
void die(const char *);

int Recv(int, void *, size_t, int);

int Send(int, void *, size_t, int);

char * MallocString(const int);

char * StringCopy(const char *);

char * StringNCopy(const char *, const int);

/**
 * @brief Takes a message and logs it to the specified file
 * 
 */
void _logger(const char *, const char *, ...);

/**
 * @brief Takes a integer and returns the equivalente ASCII representation.
 * 
 * @return char* 
 */
char * itoa(int);

#endif // COMMON_H