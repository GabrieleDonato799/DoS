#include "webserver.h"
#include <common.h>
#include <lib/webUtils.h>
#include <lib/httpproto/httpproto.h>
#include <stdlib.h>

HTTPResponse_t * webSrvReqHdlr(HTTPRequest_t * req){
    Endpoint_t * ep = NULL;
    HTTPResponse_t * res = NULL;
    HTTPResponseLine_t * resLine = (HTTPResponseLine_t *)calloc(1, sizeof(HTTPResponseLine_t));
    HTTPBody_t * body = (HTTPBody_t *)calloc(1, sizeof(HTTPBody_t));
    char * text = NULL;
    char * reqDoc = NULL; // requested document canonical absolute path
    FILE * reqDocFile = NULL;
    int reqDocSz = 0;
    
    logger("webSrvReqHdlr", "Entering\n");

    initResponse(&res);

    // read file
    ep = RequestGetEndpoint(req);
    if(!ep){
        logger("webSrvReqHdlr", "Invalid endpoint\n");
        return NULL;
    }
    reqDoc = URLPath2AbsFilePath(EndpointGetPath(ep), "./content");
    if(reqDoc == NULL){
        logger("webSrvReqHdlr", "Invalid file path\n");
        return NULL;
    }
    reqDocFile = fopen(reqDoc, "rb");
    if(!reqDocFile){
        logger("webSrvReqHdlr", "Couldn't open the requested file\n"); perror("fopen");
        return NULL;
    }

    // get file size
    fseek(reqDocFile, 0L, SEEK_END);
    reqDocSz = ftell(reqDocFile);
    rewind(reqDocFile);

    if(reqDocSz > MAX_RESPONSE_BODY_SIZE){
        logger("webSrvReqHdlr", "Request file is too big\n");
        return NULL;
    }

    // prepare response line
    if(!ResponseLineSetProtocol(resLine, HTTP_VERSION_1_1))
        logger("webSrvReqHdlr", "Couldn't set the response' protocol version\n");
    if(!ResponseLineSetStatusCode(resLine, 200))
        logger("webSrvReqHdlr", "Couldn't set the response' status code\n");
    if(!ResponseSetResLine(res, resLine))
        logger("webSrvReqHdlr", "Couldn't set the response' status line\n");
    
    // headers
    if(!ResponseAddHeader(res, "Content-Length", itoa(reqDocSz)))
        logger("webSrvReqHdlr", "Couldn't add the response header Content-Length\n");
    if(!ResponseAddHeader(res, "Content-Type", "text/html"))
        logger("webSrvReqHdlr", "Couldn't add the response header Content-Type\n");
    if(!ResponseAddHeader(res, "Server", "Donato's web Server"))
        logger("webSrvReqHdlr", "Couldn't add the response header Server\n");
    if(!ResponseAddHeader(res, "Date", generateDateRFC7231()))
        logger("webSrvReqHdlr", "Couldn't add the response header Date\n");
    if(!ResponseAddHeader(res, "Connection", "Close"))
        logger("webSrvReqHdlr", "Couldn't add the response header Connection\n");

    // set body
    text = (char *)malloc(reqDocSz*sizeof(char));
    int read = 0;
    if((read = fread(text, sizeof(char), reqDocSz, reqDocFile)) != reqDocSz){
        if(ferror(reqDocSz))
        logger("webSrvReqHdlr", "Couldn't read the request file\n");
    }
    logger("webSrvReqHdlr", "read: %d\n", read);
    if(!BodySetData(body, text, reqDocSz))
        logger("webSrvReqHdlr", "Couldn't set the response' body data\n");
    if(!ResponseAddBody(res, body))
        logger("webSrvReqHdlr", "Couldn't add the body to the response\n");

    logger("webSrvReqHdlr", "Exiting\n");

    free(ep);
    return res;
}