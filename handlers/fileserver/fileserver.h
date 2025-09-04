#ifndef FILESERVER_H
#define FILESERVER_H

#include <lib/httpproto/httpproto.h>

HTTPResponse_t * fileSrvReqHdlr(HTTPRequest_t *);

#endif // FILESERVER_H