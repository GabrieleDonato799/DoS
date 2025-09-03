#ifndef WEBUTILS_H
#define WEBUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#define MAX_PATH_LENGTH 255
#define MIN(x,y) x < y ? x : y

char * URLPath2AbsFilePath(const char *, const char *);

char * getFileContentType(const char *);

#endif // WEBUTILS_H