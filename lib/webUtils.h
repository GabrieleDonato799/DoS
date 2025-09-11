#ifndef WEBUTILS_H
#define WEBUTILS_H

#include <lib/httpproto/httpproto.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#define MAX_PATH_LENGTH 255
#define MIN(x,y) x < y ? x : y

char * URLPath2AbsFilePath(const char *, const char *);

char * getFileContentType(const char *);

HTTPResponse_t * createErrorResponse(const int);

time_t getLastModDate(const char *);

#endif // WEBUTILS_H