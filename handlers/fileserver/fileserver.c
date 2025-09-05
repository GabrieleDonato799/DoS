#include "fileserver.h"
#include <common.h>
#include <lib/webUtils.h>
#include <stdlib.h>

#define DEF_CACHING_TIME 3600

HTTPResponse_t * fileSrvReqHdlr(HTTPRequest_t * req){
    Endpoint_t * ep = NULL;
    HTTPResponse_t * res = NULL;
    HTTPResponseLine_t * resLine = (HTTPResponseLine_t *)calloc(1, sizeof(HTTPResponseLine_t));
    HTTPBody_t * body = NULL;
    char * text = NULL;
    char * reqDoc = NULL; // requested document canonical absolute path
    FILE * reqDocFile = NULL;
    int reqDocSz = 0;
    bool fileExists = false;
    
    logger("fileSrvReqHdlr", "Entering\n");

    initResponse(&res);

    // prepare response line
    if(!ResponseLineSetProtocol(resLine, HTTP_VERSION_1_1))
        logger("fileSrvReqHdlr", "Couldn't set the response' protocol version\n");
    if(!ResponseLineSetStatusCode(resLine, 200))
        logger("fileSrvReqHdlr", "Couldn't set the response' status code\n");
    if(!ResponseSetResLine(res, resLine))
        logger("fileSrvReqHdlr", "Couldn't set the response' status line\n");

    // handle file operation
    ep = RequestGetEndpoint(req);
    if(!ep){
        logger("fileSrvReqHdlr", "Invalid endpoint\n");
        return NULL;
    }
    reqDoc = URLPath2AbsFilePath(EndpointGetPath(ep), "./content");
    if(reqDoc == NULL){
        logger("fileSrvReqHdlr", "Invalid file path\n");
        return NULL;
    }

    if(strcmp(EndpointGetMethod(ep), "POST") == 0){
        body = BodyGetData(RequestGetBody(req));

        reqDocFile = fopen(reqDoc, "wb");
        if(!reqDocFile){
            logger("fileSrvReqHdlr", "Couldn't open the requested file\n"); perror("fopen");
            return NULL;
        }
        if(body)
            fwrite(body->data, sizeof(char), body->size, reqDocFile);
        fclose(reqDocFile);
    }
    else if(strcmp(EndpointGetMethod(ep), "HEAD") == 0){
        // Check if the If-Modified-Since request header is present
        HTTPHeader_t * ifModSince = RequestFindHeader(req, "If-Modified-Since");
        HTTPHeader_t * lastModDate = HeaderCreate("Last-Modified", getLastModDate(reqDoc));

        // browser caching
        if(ifModSince && compareDateRFC7231(lastModDate, ifModSince) <= 0){
            free(res);
            free(ep);
            res = createErrorResponse(304);
            return res;
        }

        reqDocFile = fopen(reqDoc, "rb");
        if(!reqDocFile){
            logger("fileSrvReqHdlr", "Couldn't open the requested file\n"); perror("fopen");
            free(res);
            free(ep);
            res = createErrorResponse(404);
            return res;
        }

        // get file size
        fseek(reqDocFile, 0L, SEEK_END);
        reqDocSz = ftell(reqDocFile);
        rewind(reqDocFile);

        if(reqDocSz > MAX_RESPONSE_BODY_SIZE){
            logger("fileSrvReqHdlr", "Request file is too big\n");
            return NULL;
        }

        fclose(reqDocFile);

        // file specific headers
        if(!ResponseAddHeader(res, "Content-Length", 0))
            logger("fileSrvReqHdlr", "Couldn't add the response header Content-Length\n");
        if(!ResponseAddHeader(res, "Last-Modified", HeaderGetValue(lastModDate)))
            logger("fileSrvReqHdlr", "Couldn't add the response header Date\n");
        if(!ResponseAddHeader(res, "Expires", timetToDateRFC7231(time(NULL)+DEF_CACHING_TIME)))
            logger("fileSrvReqHdlr", "Couldn't add the response header Expires\n");
        if(!ResponseAddHeader(res, "Cache-Control", "public, max-age=3600"))
            logger("fileSrvReqHdlr", "Couldn't add the response header Cache-Control\n");
    }
    else if(strcmp(EndpointGetMethod(ep), "GET") == 0){
        // Check if the If-Modified-Since request header is present
        HTTPHeader_t * ifModSince = RequestFindHeader(req, "If-Modified-Since");
        HTTPHeader_t * lastModDate = HeaderCreate("Last-Modified", getLastModDate(reqDoc));

        // browser caching
        if(ifModSince && compareDateRFC7231(lastModDate, ifModSince) <= 0){
            free(res);
            free(ep);
            res = createErrorResponse(304);
            return res;
        }

        body = (HTTPBody_t *)calloc(1, sizeof(HTTPBody_t));
        reqDocFile = fopen(reqDoc, "rb");
        if(!reqDocFile){
            logger("fileSrvReqHdlr", "Couldn't open the requested file\n"); perror("fopen");
            free(res);
            free(ep);
            res = createErrorResponse(404);
            return res;
        }

        // get file size
        fseek(reqDocFile, 0L, SEEK_END);
        reqDocSz = ftell(reqDocFile);
        rewind(reqDocFile);

        if(reqDocSz > MAX_RESPONSE_BODY_SIZE){
            logger("fileSrvReqHdlr", "Request file is too big\n");
            return NULL;
        }

        // set body
        text = (char *)malloc(reqDocSz*sizeof(char));
        int read = 0;
        if((read = fread(text, sizeof(char), reqDocSz, reqDocFile)) != reqDocSz){
            if(ferror(reqDocSz))
            logger("fileSrvReqHdlr", "Couldn't read the request file\n");
        }
        logger("fileSrvReqHdlr", "read: %d\n", read);
        if(!BodySetData(body, text, reqDocSz))
            logger("fileSrvReqHdlr", "Couldn't set the response' body data\n");
        if(!ResponseAddBody(res, body))
            logger("fileSrvReqHdlr", "Couldn't add the body to the response\n");
        fclose(reqDocFile);

        // file specific headers
        if(!ResponseAddHeader(res, "Content-Length", itoa(reqDocSz)))
            logger("fileSrvReqHdlr", "Couldn't add the response header Content-Length\n");
        if(!ResponseAddHeader(res, "Last-Modified", HeaderGetValue(lastModDate)));
            logger("fileSrvReqHdlr", "Couldn't add the response header Last-Modified\n");
        if(!ResponseAddHeader(res, "Expires", timetToDateRFC7231(time(NULL)+DEF_CACHING_TIME)))
            logger("fileSrvReqHdlr", "Couldn't add the response header Expires\n");
        if(!ResponseAddHeader(res, "Cache-Control", "max-age=3600"))
            logger("fileSrvReqHdlr", "Couldn't add the response header Cache-Control\n");
    }
    else if(strcmp(EndpointGetMethod(ep), "PUT") == 0){
        body = BodyGetData(RequestGetBody(req));

        reqDocFile = fopen(reqDoc, "wb");
        if(!reqDocFile){
            logger("fileSrvReqHdlr", "Couldn't open the requested file\n"); perror("fopen");
            return NULL;
        }
        if(body)
            fwrite(body->data, sizeof(char), body->size, reqDocFile);
        fclose(reqDocFile);

        if(!ResponseAddHeader(res, "Content-Length", 0))
            logger("fileSrvReqHdlr", "Couldn't add the response header Content-Length\n");
    }
    else if(strcmp(EndpointGetMethod(ep), "DELETE") == 0){
        if(unlink(reqDoc) < 0){
            perror("unlink");
            logger("fileSrvReqHdlr", "Couldn't delete the file: %s\n", reqDoc);

            free(res);
            free(ep);
            res = createErrorResponse(404);
            return res;
        }
    }
    
    // headers
    if(!ResponseAddHeader(res, "Content-Type", "text/html"))
        logger("fileSrvReqHdlr", "Couldn't add the response header Content-Type\n");
    if(!ResponseAddHeader(res, "Server", "Donato's web Server"))
        logger("fileSrvReqHdlr", "Couldn't add the response header Server\n");
    if(!ResponseAddHeader(res, "Date", generateDateRFC7231()))
        logger("fileSrvReqHdlr", "Couldn't add the response header Date\n");
    if(!ResponseAddHeader(res, "Connection", "Close"))
        logger("fileSrvReqHdlr", "Couldn't add the response header Connection\n");

    logger("fileSrvReqHdlr", "Exiting\n");

    free(ep);
    return res;
}