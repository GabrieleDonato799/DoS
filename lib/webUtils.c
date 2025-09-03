#include "webUtils.h"
#include "common.h"
#include <lib/httpproto/httpproto.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

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