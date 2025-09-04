#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <lib/httpproto/httpproto.h>

HTTPResponse_t * webSrvReqHdlr(HTTPRequest_t *);

#endif // WEBSERVER_H