#ifndef PATH_H
#define PATH_H

/**
 * @file path.c
 * @author Gabriele Donato
 * @brief An ADT to work on Linux paths. Works with absolute and relative paths.
 * @version 0.1
 * @date 2025-09-11
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

bool PathSetPath(const char *);

char * PathGetPath();

int PathGetNumRemovedComp();

bool PathGetLastRemComp(char **);

bool PathRemLastComp();

#endif // PATH_H