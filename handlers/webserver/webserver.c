#include <common.h>
#include "webserver.h"
#include <stdlib.h>

HTTPResponse_t * webSrvReqHdlr(HTTPRequest_t req){
    HTTPResponse_t * res = (HTTPResponse_t *)calloc(1, sizeof(HTTPResponse_t));
    res->nHeaders = 0;
    HTTPResponseLine_t * resLine = (HTTPResponseLine_t *)calloc(1, sizeof(HTTPResponseLine_t));
    HTTPBody_t * body = (HTTPBody_t *)calloc(1, sizeof(HTTPBody_t));
    char * text = "<html><head><title>Dos</title></head><body><p>Welcome to Donato's web Server!</p></body></html>";
    
    logger("webSrvReqHdlr", "Entering\n");

    if(!ResponseLineSetProtocol(resLine, HTTP_VERSION_1_1))
        logger("webSrvReqHdlr", "Couldn't set the response' protocol version\n");
    if(!ResponseLineSetStatusCode(resLine, 200))
        logger("webSrvReqHdlr", "Couldn't set the response' status code\n");

    if(!ResponseSetResLine(res, resLine))
        logger("webSrvReqHdlr", "Couldn't set the response' status line\n");
    
    if(!ResponseAddHeader(res, "Content-Length", itoa(strlen(text))))
        logger("webSrvReqHdlr", "Couldn't add the response header\n");
    if(!ResponseAddHeader(res, "Date", generateDateRFC7231()))
        logger("webSrvReqHdlr", "Couldn't add the response header\n");

    if(!BodySetData(body, text))
        logger("webSrvReqHdlr", "Couldn't set the response' body data\n");
    if(!ResponseAddBody(res, body))
        logger("webSrvReqHdlr", "Couldn't add the body to the response\n");

    logger("webSrvReqHdlr", "Exiting\n");

    return res;
}