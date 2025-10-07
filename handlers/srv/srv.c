#include "srv.h"
#include <common.h>
#include <lib/webUtils.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEF_CACHING_TIME 3600

/**
 * @brief Frees the response and the endpoint, returns a response with the specified status code.
 * It is meant to be used for alternative return paths like when handling a 404 error.
 * 
 * @param res 
 * @param ep 
 * @param epMethodName
 * @param statusCode 
 * @return HTTPResponse_t* 
 */
static HTTPResponse_t * finishCorrectly(HTTPRequest_t *res, Endpoint_t *ep, char * epMethodName, int statusCode){
    free(res);
    free(ep);
    free(epMethodName);
    res = createErrorResponse(statusCode);
    return res;
}

HTTPResponse_t * baseWebServer(HTTPRequest_t * req){
    Endpoint_t * ep = NULL;
    char * epMethodName = NULL;
    HTTPHeader_t * ck = NULL; // cookie of the authenticated user, used to show the capabilities of the server
    HTTPResponse_t * res = NULL;
    HTTPResponseLine_t * resLine = (HTTPResponseLine_t *)calloc(1, sizeof(HTTPResponseLine_t));
    HTTPBody_t * body = NULL;
    char * text = NULL;
    char * reqDoc = NULL; // requested document canonical absolute path
    FILE * reqDocFile = NULL;
    int reqDocSz = 0;
    bool fileExists = false;
    struct stat pathStat; // needed to check if it is a directory
    
    logger("Entering\n");

    initResponse(&res);

    // prepare response line
    if(!ResponseLineSetProtocol(resLine, HTTP_VERSION_1_1))
        logger("Couldn't set the response' protocol version\n");
    if(!ResponseLineSetStatusCode(resLine, 200))
        logger("Couldn't set the response' status code\n");
    if(!ResponseSetResLine(res, resLine))
        logger("Couldn't set the response' status line\n");

    // handle file operation
    ep = RequestGetEndpoint(req);
    if(!ep){
        logger("Invalid endpoint\n");
        return finishCorrectly(res, ep, epMethodName, 404);
    }
    // sanitize the endpoint' path
    reqDoc = URLPath2AbsFilePath(EndpointGetPath(ep), "/content");
    if(reqDoc == NULL){
        logger("Invalid file path\n");
        return finishCorrectly(res, ep, epMethodName, 404);
    }

    if (stat(reqDoc, &pathStat) == 0) {
        // check if it is a regular file
        if (S_ISDIR(pathStat.st_mode)) {
            return finishCorrectly(res, ep, epMethodName, 404); // directories are not supported
        } else if(S_ISREG(pathStat.st_mode)){
            ; // fine
        } else{ // special files are not meant to be manageable
            return finishCorrectly(res, ep, epMethodName, 404);
        }
    }

    epMethodName = EndpointGetMethod(ep);

    // per method behaviour
    if(strcmp(epMethodName, "POST") == 0){
        body = RequestGetBody(req);

        reqDocFile = fopen(reqDoc, "wb");
        if(!reqDocFile){
            logger("Couldn't open the requested file\n"); perror("fopen");
            return finishCorrectly(res, ep, epMethodName, 500);
        }
        if(body)
            fwrite(body->data, sizeof(char), body->size, reqDocFile);
        fclose(reqDocFile);
    }
    else if(strcmp(epMethodName, "HEAD") == 0 || strcmp(epMethodName, "GET") == 0){
        // Check if the If-Modified-Since request header is present
        time_t lastModDateRFC7231 = getLastModDate(reqDoc);
        HTTPHeader_t * ifModSince = RequestFindHeader(req, "If-Modified-Since");
        HTTPHeader_t * lastModDate = HeaderCreate("Last-Modified", timetToDateRFC7231(lastModDateRFC7231));

        // browser caching
        if(ifModSince && compareDateRFC7231(lastModDate, ifModSince) <= 0){
            return finishCorrectly(res, ep, epMethodName, 304);
        }

        // open the file
        reqDocFile = fopen(reqDoc, "rb");
        if(!reqDocFile){
            logger("Couldn't open the requested file\n"); perror("fopen");
            return finishCorrectly(res, ep, epMethodName, 404);
        }
        
        // get file size
        fseek(reqDocFile, 0L, SEEK_END);
        reqDocSz = ftell(reqDocFile);
        rewind(reqDocFile);
        
        if(reqDocSz > MAX_RESPONSE_BODY_SIZE){
            logger("Request file is too big\n");
            return NULL;
        }
        
        // GET specific behaviour 
        if(strcmp(epMethodName, "GET") == 0){
            // set body
            text = MallocString(reqDocSz);
            int read = 0;
            if((read = fread(text, sizeof(char), reqDocSz, reqDocFile)) != reqDocSz){
                if(ferror(reqDoc)){
                    logger("Couldn't read the request file\n");
                    return finishCorrectly(res, ep, epMethodName, 500);
                }
            }
            logger("read: %d\n", read);
            body = (HTTPBody_t *)calloc(1, sizeof(HTTPBody_t));

            if(!BodySetData(body, text, reqDocSz))
                logger("Couldn't set the response' body data\n");
            if(!ResponseAddBody(res, body))
                logger("Couldn't add the body to the response\n");
            
            fclose(reqDocFile);
        }
        else{
            reqDocSz = 0;
        }

        // file specific headers
        if(!ResponseAddHeader(res, "Content-Length", itoa(reqDocSz)))
            logger("Couldn't add the response header Content-Length\n");
        if(!ResponseAddHeader(res, "Last-Modified", HeaderGetValue(lastModDate)));
            logger("Couldn't add the response header Last-Modified\n");
        if(!ResponseAddHeader(res, "Expires", 
            timetToDateRFC7231(lastModDateRFC7231+DEF_CACHING_TIME)))
            logger("Couldn't add the response header Expires\n");
        if(!ResponseAddHeader(res, "Cache-Control", "max-age=3600"))
            logger("Couldn't add the response header Cache-Control\n");
    }
    else if(strcmp(epMethodName, "PUT") == 0){
        body = RequestGetBody(req);

        // first check if the file exists, then open it
        reqDocFile = fopen(reqDoc, "rb");
        if(!reqDocFile){
            logger("Couldn't open the requested file in read mode\n"); perror("fopen");
            return finishCorrectly(res, ep, epMethodName, 404);
        }
        reqDocFile = freopen(reqDoc, "wb", reqDocFile);
        if(!reqDocFile){
            logger("Couldn't open the requested file in write mode\n"); perror("fopen");
            return finishCorrectly(res, ep, epMethodName, 500);
        }
        if(body)
            fwrite(body->data, sizeof(char), body->size, reqDocFile);
        fclose(reqDocFile);

        if(!ResponseAddHeader(res, "Content-Length", 0))
            logger("Couldn't add the response header Content-Length\n");
    }
    else if(strcmp(epMethodName, "DELETE") == 0){
        if(unlink(reqDoc) < 0){
            perror("unlink");
            logger("Couldn't delete the file: %s\n", reqDoc);

            return finishCorrectly(res, ep, epMethodName, 404);
        }
    }
    
    // headers
    if(!ResponseAddHeader(res, "Content-Type", "text/html"))
        logger("Couldn't add the response header Content-Type\n");
    if(!ResponseAddHeader(res, "Server", "Donato's web Server"))
        logger("Couldn't add the response header Server\n");
    if(!ResponseAddHeader(res, "Date", generateDateRFC7231()))
        logger("Couldn't add the response header Date\n");
    if(!ResponseAddHeader(res, "Connection", "Close"))
        logger("Couldn't add the response header Connection\n");

    // show that the server can work with cookies
    if(ck = RequestFindHeader(req, "Cookie"))
        if(!ResponseAddHeader(res, "Biscuit", HeaderGetValue(ck)))
            logger("Couldn't add the authentication cookie of the user\n");

    logger("Exiting\n");

    free(ep);
    return res;
}