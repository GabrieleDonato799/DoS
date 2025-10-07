#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <lib/httpproto/httpproto.h>

// Sets the cookie: "username=user; HTTPOnly; SameSite=Strict;"
HTTPResponse_t * loginReqHdlr(HTTPRequest_t *);

// Deletes the cookie by setting this cookie: "username=; HTTPOnly; SameSite=Strict;"
HTTPResponse_t * logoutReqHdlr(HTTPRequest_t *);

HTTPResponse_t * webSrvReqHdlr(HTTPRequest_t *);

#endif // WEBSERVER_H