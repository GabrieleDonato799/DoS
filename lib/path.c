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

static char * _path = NULL;
// last removed component
static char * last = NULL;
// tells if we reached the root ("/") when removing a path component
static bool reachedStart = false;
static int numRemComp = 0;

/**
 * @brief Sets the path to work on. Replaces the old one.
 * Returns whether it succeded or not.
 * 
 * @param path 
 */
bool PathSetPath(const char * const path){
    if(path){
        _path = (char *)malloc(sizeof(char)*(strlen(path) +1));
        if(_path)
            strcpy(_path, path);
        else
            return false;
    }
    if(!_path) return false;
    return true;
}

/**
 * @brief Returns the currently set path or NULL if unitialized.
 * 
 * @return char* 
 */
char * PathGetPath(){
    return _path;
}

int PathGetNumRemovedComp(){
    return numRemComp;
}

/**
 * @brief Optionally takes a string pointer to store the last removed path component.
 * Returns whether the code reached the start of the path (the root "/").
 * If out points to an allocated data, the function tries to free it first.
 * 
 * @param out 
 * @return bool 
 */
bool PathGetLastRemComp(char ** out){
    if(out){
        if(reachedStart){
            *out = NULL;
        }
        else{
            if(last){
                if(*out) free(*out);
                *out = (char *)malloc(sizeof(char)*(strlen(last) +1));
                strcpy(*out, last);
            }
            else{
                *out = NULL;
            }
        }
    }

    return reachedStart;
}

/**
 * @brief Removes the last component of the currently set file path.
 * When it removes the root "/", it will leave an empty string "".
 * Returns whether it reached the start of the path (no more components).
 * NOTE: use PathGetLastRemComp to get the removed component.
 * 
 * @param str 
 * @return char* 
 */
bool PathRemLastComp(){
    // static char * sCpy = NULL;

    char * end = _path + strlen(_path); // point to string terminator
    
    while(end > _path){
        // printf("from end: %s\n", end);
        end--;

        if(*end == '/'){
            if(last) free(last);
            last = (char *)malloc(sizeof(char)*(strlen(end) +1));
            strcpy(last, end);
            last[strlen(end)] = '\0';

            // printf("found: %c, component: %s\n", *end, last);
            *end = '\0';
            numRemComp++;
            break;
        }
    }
    if(end == _path)
        reachedStart = true;
    return reachedStart;
}

// int main(){
//     char * str = "/test/1/235/..//";
//     char * l = NULL;

//     PathSetPath(str);
//     while(!PathRemLastComp()){
//         printf("str = %s\n", PathGetPath());
//         PathGetLastRemComp(&l);
//         printf("last remove component = %s\n", l);
//     }
// }