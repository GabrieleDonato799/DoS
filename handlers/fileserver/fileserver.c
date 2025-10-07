#include "fileserver.h"
#include <common.h>
#include <lib/webUtils.h>
#include <handlers/srv/srv.h>
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

HTTPResponse_t * fileSrvReqHdlr(HTTPRequest_t * req){
    logger("The file server will handle this request.\n");
    return baseWebServer(req);
}