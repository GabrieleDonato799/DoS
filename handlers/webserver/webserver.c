#include "webserver.h"
#include <common.h>
#include <lib/webUtils.h>
#include <lib/httpproto/httpproto.h>
#include <handlers/srv/srv.h>
#include <stdlib.h>

HTTPResponse_t * loginReqHdlr(HTTPRequest_t * req){
    HTTPResponse_t * res = NULL;
    
    res = createErrorResponse(200);

    if(!ResponseAddHeader(res, "Set-Cookie", "username=user; Path=/; SameSite=Strict;")){
        logger("Couldn't set the Cookie!\n");
        res = createErrorResponse(500);
    }

    return res;
}

HTTPResponse_t * logoutReqHdlr(HTTPRequest_t *){
    HTTPResponse_t * res = NULL;
    
    res = createErrorResponse(200);

    if(!ResponseAddHeader(res, "Set-Cookie", "username=; Path=/; SameSite=Strict;")){
        logger("Couldn't unset the Cookie!\n");
        res = createErrorResponse(500);
    }

    return res;
}

HTTPResponse_t * webSrvReqHdlr(HTTPRequest_t * req){
    logger("The web server will handle this request.\n");
    return baseWebServer(req);
}