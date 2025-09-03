#include "webUtils.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief Takes a relative URL path and for the first call, the base directory for public file content.
 * Returns a string with the absolute filesystem path of the resource.
 * Successive calls that want to use the same base directory must set it to NULL.
 *
 * @test URLPath2AbsFilePath("/../../../../../../etc/passwd", "./");
 *  
 * @param URLPath 
 * @param baseDir 
 * @return char* 
 */
char * URLPath2AbsFilePath(const char * const URLPath, const char * const baseDir){
    static char * _baseDir = NULL;
    char fullFsPath[MAX_PATH_LENGTH] = {};
    char * canonicalFullFsPath = NULL;

    if(!URLPath) return NULL;

    if(baseDir){
        // use the absolute path
        _baseDir = realpath(baseDir, NULL);
    }
    // check if the path has been set at least once
    if(!_baseDir){
        logger("URLPath2AbsFilePath", "realpath\n"); perror("");
        return NULL;
    }

    if(strlen(_baseDir)+strlen(URLPath) > MAX_PATH_LENGTH){
        logger("URLPath2AbsFilePath", "File path is too large\n"); perror("");
        return NULL;
    }

    strcat(fullFsPath, _baseDir);
    strcat(fullFsPath, URLPath);

    // check if it is a path traversal
    canonicalFullFsPath = realpath(fullFsPath, NULL);
    logger("URLPath2AbsFilePath", "canonicalFullFsPath: %s\n", canonicalFullFsPath);
    if(!canonicalFullFsPath){
        logger("URLPath2AbsFilePath", "Invalid canonical absolute path, does the resource exists?\n"); perror("");
        return NULL;
    }
    if(strlen(canonicalFullFsPath) > MAX_PATH_LENGTH){
        logger("URLPath2AbsFilePath", "Canonical absolute file path is too large\n"); perror("");
        return NULL;
    }
    if(
        memcmp(canonicalFullFsPath, _baseDir,
        MIN(strlen(canonicalFullFsPath), strlen(_baseDir)))
    )
    {
        logger("URLPath2AbsFilePath", "Path traversal detected!\n"); perror("memcmp or strlen\n");
        logger("URLPath2AbsFilePath", "fullFsPath: %s\n", fullFsPath);
        return NULL;
    }

    return canonicalFullFsPath;
}

/**
 * @brief Takes a filename and returns its content type.
 * 
 * @return char *
 */
char * getFileContentType(const char * const filename){
    // regex match
}