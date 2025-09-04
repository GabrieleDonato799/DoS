#include "webUtils.h"
#include <common.h>
#include <lib/path.h>
#include <lib/httpproto/httpproto.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>

/**
 * @brief Frees the allocated memory, returns the canonicalFullFsPath if returnCan is true.
 * 
 * @param fullFsPath 
 * @param lastComp 
 * @param canonicalFullFsPath 
 * @param returnCan 
 * @return void* 
 */
static void * finishCorrectly(char *fullFsPath, char *lastComp, char *canonicalFullFsPath, bool returnCan){
    if(fullFsPath) free(fullFsPath);
    if(lastComp) free(lastComp);
    if(returnCan == true)
        return canonicalFullFsPath;
    else if(canonicalFullFsPath)
        free(canonicalFullFsPath);
    return NULL;
}

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
    char * fullFsPath = NULL;
    char * lastComp = NULL; // last removed component temporary storage
    char * canonicalFullFsPath = NULL;
    int requiredLen = 0;

    if(!URLPath) return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);

    if(baseDir){
        // use the absolute path
        _baseDir = realpath(baseDir, NULL);
    }
    // check if the path has been set at least once and if it is not too long
    if(!_baseDir){
        logger("URLPath2AbsFilePath", "realpath\n"); perror("");
        return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);
    }
    requiredLen = strlen(_baseDir) + strlen(URLPath) +1;
    if(requiredLen > MAX_PATH_LENGTH){
        logger("URLPath2AbsFilePath", "File path is too large\n"); perror("");
        return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);
    }

    // concatenate the base and URL to build the full filesystem path
    fullFsPath = (char *)malloc(sizeof(char)*(requiredLen)); fullFsPath[0] = '\0';
    strcat(fullFsPath, _baseDir);
    strcat(fullFsPath, URLPath);

    // -- check if it is a path traversal --
    PathSetPath(fullFsPath);
    // remove components from the path as long as realpath tells us that the path doesn't exist
    while((canonicalFullFsPath = realpath(fullFsPath, NULL)) == NULL){
        if(errno == ENOENT){ // File doesn't exist
            PathRemLastComp();
            fullFsPath = PathGetPath();
        }
        else{ // Unknown error
            logger("URLPath2AbsFilePath", "Unknown realpath(fullFsPath, NULL) error\n"); perror("");
            return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);
        }
    }

    logger("URLPath2AbsFilePath", "canonicalFullFsPath: %s\n", canonicalFullFsPath);
    if(!canonicalFullFsPath){
        logger("URLPath2AbsFilePath", "Invalid canonical absolute path, does the resource exists?\n"); perror("");
        return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);
    }
    if(strlen(canonicalFullFsPath) > MAX_PATH_LENGTH){
        logger("URLPath2AbsFilePath", "Canonical absolute file path is too large\n"); perror("");
        return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);
    }
    if(
        memcmp(canonicalFullFsPath, _baseDir,
        MIN(strlen(canonicalFullFsPath), strlen(_baseDir)))
    )
    {
        logger("URLPath2AbsFilePath", "Path traversal detected!\n"); perror("memcmp or strlen\n");
        logger("URLPath2AbsFilePath", "fullFsPath: %s\n", fullFsPath);
        return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);
    }

    // Add the last removed component if any, because a service (request handler) needs
    // to be able to create a file if it doesn't exists.
    // We don't handle the creation of missing directories, so at most one removed component is allowed.
    // First check if the component contains "./" "../" to block it.
    if(PathGetNumRemovedComp() > 1){ 
        return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);
    }
    if(PathGetNumRemovedComp() == 1){
        PathGetLastRemComp(&lastComp);
        if(lastComp == NULL) return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);

        if(strstr(lastComp, "./")) return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);

        requiredLen = strlen(canonicalFullFsPath) + strlen(lastComp) +1;
        canonicalFullFsPath = realloc(canonicalFullFsPath, requiredLen);
        if(!canonicalFullFsPath) return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, false);
        strcat(canonicalFullFsPath, lastComp);
        canonicalFullFsPath[requiredLen -1] = '\0';
    }
    logger("URLPath20AbsFilePath", "canonicalFullFsPath: %s\n", canonicalFullFsPath);

    return finishCorrectly(fullFsPath, lastComp, canonicalFullFsPath, true);
}

/**
 * @brief Takes a filename and returns its content type.
 * 
 * @return char *
 */
char * getFileContentType(const char * const filename){
    // regex match
}

/**
 * @brief Takes an error code and returns an error response.
 * 
 * @return HTTPResponse_t *
 */
HTTPResponse_t * createErrorResponse(const int errorCode){
    HTTPResponse_t * res = NULL;
    HTTPResponseLine_t * resLine = (HTTPResponseLine_t *)calloc(1, sizeof(HTTPResponseLine_t));
    HTTPBody_t * body = (HTTPBody_t *)calloc(1, sizeof(HTTPBody_t));
    char * text = (char *)malloc(500*sizeof(char));
    int rc = 0;
    
    logger("createErrorResponse", "Entering\n");

    if(!resLine || !body || !text){
        logger("createErrorResponse", "Out of memory\n");
        die("malloc");
    }

    initResponse(&res);

    // prepare response line
    if(!ResponseLineSetProtocol(resLine, HTTP_VERSION_1_1))
        logger("createErrorResponse", "Couldn't set the response' protocol version\n");
    if(!ResponseLineSetStatusCode(resLine, errorCode))
        logger("createErrorResponse", "Couldn't set the response' status code\n");
    if(!ResponseSetResLine(res, resLine))
        logger("createErrorResponse", "Couldn't set the response' status line\n");

    rc = snprintf(text, 500, "<html><head><title>Dos</title></head><body><p>%s %s</p></body></html>\0", itoa(errorCode), getStatusMessage(errorCode));
    
    if(rc < 0)
        logger("createErrorResponse", "Couldn't create the error response page\n");
    
    // headers
    if(!ResponseAddHeader(res, "Content-Length", itoa(rc)))
        logger("createErrorResponse", "Couldn't add the response header Content-Length\n");
    if(!ResponseAddHeader(res, "Content-Type", "text/html"))
        logger("createErrorResponse", "Couldn't add the response header Content-Type\n");
    if(!ResponseAddHeader(res, "Server", "Donato's web Server"))
        logger("createErrorResponse", "Couldn't add the response header Server\n");
    if(!ResponseAddHeader(res, "Date", generateDateRFC7231()))
        logger("createErrorResponse", "Couldn't add the response header Date\n");
    if(!ResponseAddHeader(res, "Connection", "Close"))
        logger("createErrorResponse", "Couldn't add the response header Connection\n");

    // set body
    if(!BodySetData(body, text, rc))
        logger("createErrorResponse", "Couldn't set the response' body data\n");
    if(!ResponseAddBody(res, body))
        logger("createErrorResponse", "Couldn't add the body to the response\n");

    logger("createErrorResponse", "Exiting\n");

    return res;
}

/**
 * @brief Takes a file and returns its last modified date as a time_t value.
 * 
 */
time_t getLastModDate(const char * const filename){
    struct stat attr;
    if (stat(filename, &attr) == -1) {
        perror("stat");
        return NULL;
    }

    // Modification time
    return attr.st_mtime;
}