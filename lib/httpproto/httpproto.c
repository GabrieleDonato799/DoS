#include "httpproto.h"
#include <common.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

static char * HTTPRequestReadLine(int sockfd){
    static char buff[2*MAX_REQ_SIZE] = {};
    static int recvN = 0; // how many bytes have been received
    static char * start = buff, * end = buff;
    char * newStr = NULL;
    int moved;

    buff[MAX_REQ_SIZE] = 0;

    switch ((moved = recv(sockfd, buff, MAX_REQ_SIZE, MSG_DONTWAIT))) {
        case -1:
            if(errno == EAGAIN)
                ;
            else
                die("recv");
        break;
    }

    recvN += moved;
    if(recvN > MAX_REQ_SIZE){
        // TODO: send back a 413 Content Too Large
        die("413 Content Too Large");
    }
    
    // Find the EOL
    if((end = strstr(start, "\r\n")) == NULL){
        printf("rc: %p\n", end);
        die("strstr(\"\\r\\n\", start)");
    }

    if(end > buff + MAX_REQ_SIZE){
        end = buff + MAX_REQ_SIZE;
    }

    if(end-start > 0){
        newStr = (char *)malloc(sizeof(char)*(end-start +3));
        strncpy(newStr, start, end-start +2); // +2 keeps \r\n
        newStr[end-start +2] = 0;
        start = end +2; // skip the \r\n
    }

    return newStr;
}

static HTTPRequestLine_t * RequestParseReqLine(const char * s){
    const char *start = s, *end = s;
    HTTPRequestLine_t * reqLine;

    reqLine = (HTTPRequestLine_t *)calloc(1, sizeof(HTTPRequestLine_t));

    // HTTP method
    if((end = strstr(start, " ")) == NULL || end-start <= 0){
        die("method");
    }
    reqLine->method = (char *)malloc(sizeof(char) * (end-start +1));
    strncpy(reqLine->method, start, end-start);
    reqLine->method[end-start] = 0;
    start = end + 1;

    // URL (Only relatives are supported)
    if((end = strstr(start, " ")) == NULL || end-start <= 0){
        die("URL");
    }
    reqLine->path = (char *)malloc(sizeof(char) * (end-start +1));
    strncpy(reqLine->path, start, end-start);
    reqLine->path[end-start] = 0;
    start = end + 1;

    // HTTP protocol version (Only HTTP/1.1 is supported)
    if((end = strstr(start, "\r\n")) == NULL || end-start <= 0){
        die("protocol version");
    }
    reqLine->protocol = (char *)malloc(sizeof(char) * (end-start +1));
    strncpy(reqLine->protocol, start, end-start);
    reqLine->protocol[end-start] = 0;
    
    return reqLine;
}

void printHTTPRequestLine(HTTPRequestLine_t * r){
    logger("printHTTPRequestLine", "r->method: %s\nr->path: %s\nr->protocol: %s\n", r->method, r->path, r->protocol);
}

static HTTPHeader_t * RequestParseHeaderField(const char * line){
    const char *start = line, *end = line;
    HTTPHeader_t * hdr;

    hdr = (HTTPHeader_t *)calloc(1, sizeof(HTTPHeader_t));

    // Header name
    if((end = strstr(start, ": ")) == NULL || end-start <= 0){
        die("RequestParseHeaderField name");
    }
    hdr->name = (char *)malloc(sizeof(char) * (end-start +1)); // +1 string terminator
    strncpy(hdr->name, start, end-start);
    hdr->name[end-start] = 0;
    start = end + 2;
    
    // Header value
    if((end = strstr(start, "\r\n")) == NULL || end-start <= 0){
        die("RequestParseHeaderField value");
    }
    hdr->value = (char *)malloc(sizeof(char) * (end-start +1));
    strncpy(hdr->value, start, end-start);
    hdr->value[end-start] = 0;
    
    start = end + 1;

    return hdr;
}


// HTTPBody_t * RequestRecvBody(HTTPHeader_t contentLength){
// }
HTTPRequest_t * RequestParse(int client){
    char * line;
    int curHdr = 0;
  
    HTTPRequest_t * req = NULL;
    HTTPRequestLine_t * reqLine = NULL;
    HTTPHeader_t * headers = NULL; // NULL terminated
 
    initRequest(&req);

    headers = (HTTPHeader_t *)calloc(MAX_HEADERS +1, sizeof(HTTPHeader_t));
    
    reqLine = RequestParseReqLine(HTTPRequestReadLine(client));
    printHTTPRequestLine(reqLine);
  
    // parse the headers
    while((line = HTTPRequestReadLine(client)) != NULL){
      logger("RequestParse", "HTTPRequestReadLine: %s\n", line);
      
      // reached empty line separating headers from body
      if(strcmp("", line) == 0){
        break;
      }
  
      if(curHdr < MAX_HEADERS){
        headers[curHdr++] = *RequestParseHeaderField(line);
        logger("RequestParse", "HTTPHeader: name: %s, value: %s\n", headers[curHdr-1].name, headers[curHdr-1].value);
      }
      else{
        die("413 (Too many headers)"); // TODO: actually respond
      }
    }
  
    // assemble the request
    req->reqLine = reqLine;
    req->headers = headers;
  
    logger("RequestParse", "Exiting\n");  

    return req;
}

static HTTPHeader_t * findHeader(const HTTPHeader_t * vec, const char * headerName){
    const HTTPHeader_t * ptr;

    if(!vec || !headerName){
        return NULL;
    }
    ptr = vec;

    while(ptr != NULL){
        int rc;
        if((rc = strcasecmp(ptr->name, headerName)) == 0){
            return ptr;
        }
    }

    return NULL;
}

Endpoint_t * RequestGetEndpoint(const HTTPRequest_t * req){
    Endpoint_t * ep = (Endpoint_t *)malloc(sizeof(Endpoint_t));

    if(!req) return NULL;

    // find method and path of the request    
    EndpointSetMethod(ep, RequestLineGetMethod(req->reqLine));
    EndpointSetPath(ep, RequestLineGetPath(req->reqLine));

    if(!ep) return NULL;
    return ep;
}

/**
 * @brief Returns the body of the request, does not deep copies to prevent significant slowdowns.
 * 
 * @param req 
 * @return HTTPBody_t* 
 */
HTTPBody_t * RequestGetBody(const HTTPRequest_t * const req){
    return req->body;
}

/**
 * @brief Tries to find the header with name hdrName inside the request.
 * Returns a pointer to the matching header, returns NULL if the header is not present or if an error occurs.
 * 
 * @param req
 * @param hdrName 
 * @return HTTPHeader_t* 
 */
HTTPHeader_t * RequestFindHeader(const HTTPRequest_t * req, const char * hdrName){
    HTTPHeader_t * cur = NULL;
    int cmp;
    
    if(!req || !req->headers || !hdrName) return NULL;

    cur = req->headers;
    while(cur->name != NULL && cur->value != NULL){
        cmp = strcmp(cur->name, hdrName);
        if(cmp == 0){
            break;
        }
        cur += 1;
    }

    if(cur->name && cur->value)
        return cur;
    else
        return NULL;
}

void initRequest(HTTPRequest_t ** req){
    if(!req) die("initRequest: Invalid pointer\n");
    if(!*req)
        *req = (HTTPRequest_t *)malloc(sizeof(HTTPRequest_t));
    
    (*req)->reqLine = NULL;
    (*req)->headers = NULL;
    (*req)->body = NULL;
    
    return;
}

void freeRequest(HTTPRequest_t * req){
    if(req){
        if(req->reqLine){
            if(req->reqLine->method) free(req->reqLine->method);
            if(req->reqLine->path) free(req->reqLine->path);
            if(req->reqLine->protocol) free(req->reqLine->protocol);
        }
        if(req->headers){
            free(req->headers);
        }
        if(req->body){
            free(req->body);
        }

        free(req);
    }
    
    return;
}

bool ResponseSetResLine(HTTPResponse_t * const res, HTTPResponseLine_t * const resLine){
    if(!res || !resLine || !resLine->protocol || !resLine->statusCode || !resLine->statusMessage)
        return false;

    res->resLine = resLine;

    return true;
}

bool ResponseAddBody(HTTPResponse_t * const res, const HTTPBody_t * const body){
    if(!res || ! body)
        return false;
    res->body = body;
    return true;
}

bool ResponseAddHeader(HTTPResponse_t * res, const char * key, const char * value){
    HTTPHeader_t hdr;
    HTTPHeader_t *new = NULL;

    if(!HeaderSetName(&hdr, key) || !HeaderSetValue(&hdr, value))
        return false;

    // allocate more space for the new header
    res->nHeaders += 1;
    new = realloc(res->headers, (res->nHeaders)*sizeof(HTTPHeader_t));
    if(new)
        res->headers = new;
    else
        die("[ResponseAddHeader] Couldn't reallocate\n");

    res->headers[res->nHeaders -1] = hdr;

    return true;
}

bool ResponseSend(const HTTPResponse_t * const res, int sockfd){
    HTTPHeader_t * cur = NULL;
    char * codeStr = NULL;

    if(!res) return false;
    
    codeStr = (char *)malloc(4*sizeof(char)); // 3 chars for the code, 1 for terminator
    snprintf(codeStr, 4, "%3d\0", res->resLine->statusCode);

    Send(sockfd, res->resLine->protocol, strlen(res->resLine->protocol), 0);
    Send(sockfd, " ", 1, 0);
    Send(sockfd, codeStr, strlen(codeStr), 0);
    Send(sockfd, " ", 1, 0);
    Send(sockfd, res->resLine->statusMessage, strlen(res->resLine->statusMessage), 0);
    Send(sockfd, "\r\n", 2, 0);

    for(int i=0; i < res->nHeaders; i++){
        cur = &(res->headers[i]);

        Send(sockfd, cur->name, strlen(cur->name), 0);
        Send(sockfd, ": ", 2, 0);
        Send(sockfd, cur->value, strlen(cur->value), 0);
        Send(sockfd, "\r\n", 2, 0);
    }
    Send(sockfd, "\r\n", 2, 0);

    if(res->body)
        Send(sockfd, res->body->data, res->body->size, 0);

    free(codeStr);
}

void initResponse(HTTPResponse_t ** res){
    if(!res) die("initResponse: Invalid pointer");
    if(!*res)
        *res = (HTTPResponse_t *)malloc(sizeof(HTTPResponse_t));

    (*res)->resLine = NULL;
    (*res)->headers = NULL;
    (*res)->nHeaders = 0;
    (*res)->body = NULL;
    
    return;
}

void freeResponse(HTTPResponse_t * res){
    if(res){
        if(res->resLine){
            if(res->resLine->statusMessage) free(res->resLine->statusMessage);
            if(res->resLine->protocol) free(res->resLine->protocol);
        }
        if(res->headers){
            free(res->headers);
        }
        if(res->body){
            free(res->body);
        }

        free(res);
    }
    
    return;
}

char * RequestLineGetMethod(HTTPRequestLine_t * reqLine){
    int len = strlen(reqLine->method);
    char * method = (char *)malloc(sizeof(char)*(len +1));
    strncpy(method, reqLine->method, len+1);
    return method;
}
// char * RequestLineGetHost(){
// }
char * RequestLineGetPath(HTTPRequestLine_t * reqLine){
    int len = strlen(reqLine->path);
    char * path = (char *)malloc(sizeof(char)*(len +1));
    strncpy(path, reqLine->path, len+1);
    return path;
}

// char * RequestLineGetProtocol(){
// }

bool ResponseLineSetProtocol(HTTPResponseLine_t * const resLine, const int versionCode){
    // These variables should only be visible here
    static const char * const http1_1 = "HTTP/1.1";
    static const int http1_1_size = sizeof(http1_1);

    switch (versionCode)
    {
        case HTTP_VERSION_1_1:
            resLine->protocol = (char*)malloc(http1_1_size +1);
            strncpy(resLine->protocol, http1_1, http1_1_size +1);
        break;
        
        default:
            logger("ResponseLineSetProtocol", "Invalid HTTP version\n");
            return false;
        break;
    }

    return true;
}

/**
 * @brief Get the status message of the supplied HTTP error code.
 * A copy of the error message is allocated and must be freed correctly.
 * 
 * @param code 
 * @return char* 
 */
char * getStatusMessage(const int code){
    char * str = NULL, *  copyStr = NULL;
    switch(code){
        case 100: str = "Continue"; break;
        case 101: str = "Switching Protocols"; break;
        case 102: str = "Processing"; break;
        case 103: str = "Early Hints"; break;
        case 200: str = "OK"; break;
        case 201: str = "Created"; break;
        case 202: str = "Accepted"; break;
        case 203: str = "Non-Authoritative Information"; break;
        case 204: str = "No Content"; break;
        case 205: str = "Reset Content"; break;
        case 206: str = "Partial Content"; break;
        case 207: str = "Multi-Status"; break;
        case 208: str = "Already Reported"; break;
        case 226: str = "IM Used"; break;
        case 300: str = "Multiple Choices"; break;
        case 301: str = "Moved Permanently"; break;
        case 302: str = "Found"; break;
        case 303: str = "See Other"; break;
        case 304: str = "Not Modified"; break;
        case 305: str = "Use Proxy"; break;
        case 306: str = "Switch Proxy"; break;
        case 307: str = "Temporary Redirect"; break;
        case 308: str = "Permanent Redirect"; break;
        case 400: str = "Bad Request"; break;
        case 401: str = "Unauthorized"; break;
        case 402: str = "Payment Required"; break;
        case 403: str = "Forbidden"; break;
        case 404: str = "Not Found"; break;
        case 405: str = "Method Not Allowed"; break;
        case 406: str = "Not Acceptable"; break;
        case 407: str = "Proxy Authentication Required"; break;
        case 408: str = "Request Timeout"; break;
        case 409: str = "Conflict"; break;
        case 410: str = "Gone"; break;
        case 411: str = "Length Required"; break;
        case 412: str = "Precondition Failed"; break;
        case 413: str = "Payload Too Large"; break;
        case 414: str = "URI Too Long"; break;
        case 415: str = "Unsupported Media Type"; break;
        case 416: str = "Range Not Satisfiable"; break;
        case 417: str = "Expectation Failed"; break;
        case 418: str = "I'm a teapot"; break;
        case 421: str = "Misdirected Request"; break;
        case 422: str = "Unprocessable Content"; break;
        case 423: str = "Locked"; break;
        case 424: str = "Failed Dependency"; break;
        case 425: str = "Too Early"; break;
        case 426: str = "Upgrade Required"; break;
        case 428: str = "Precondition Required"; break;
        case 429: str = "Too Many Requests"; break;
        case 431: str = "Request Header Fields Too Large"; break;
        case 451: str = "Unavailable For Legal Reasons"; break;
        case 500: str = "Internal Server Error"; break;
        case 501: str = "Not Implemented"; break;
        case 502: str = "Bad Gateway"; break;
        case 503: str = "Service Unavailable"; break;
        case 504: str = "Gateway Timeout"; break;
        case 505: str = "HTTP Version Not Supported"; break;
        case 506: str = "Variant Also Negotiates"; break;
        case 507: str = "Insufficient Storage"; break;
        case 508: str = "Loop Detected"; break;
        case 510: str = "Not Extended"; break;
        case 511: str = "Network Authentication Required"; break;
    }
    
    copyStr = (char *)malloc((strlen(str) +1)*sizeof(char));
    strcpy(copyStr, str);

    return copyStr;
}

static bool ResponseLineSetStatusMessage(HTTPResponseLine_t * const resLine, const int code){
    resLine->statusMessage = getStatusMessage(code);
    
    return true;
}

bool ResponseLineSetStatusCode(HTTPResponseLine_t * const resLine, const int code){
    int outcome = true;
    
    resLine->statusCode = code;
    outcome = ResponseLineSetStatusMessage(resLine, code);
    
    return outcome;
}

bool HeaderSetName(HTTPHeader_t * const hdr, const char * const name){
    if(!hdr || !name)
        return false;

    hdr->name = (char *)malloc((strlen(name) +1)*sizeof(char));
    strcpy(hdr->name, name);
    
    return true;
}
bool HeaderSetValue(HTTPHeader_t * const hdr, const char * const value){
    if(!hdr || !value)
        return false;

    hdr->value = (char *)malloc((strlen(value) +1)*sizeof(char));
    strcpy(hdr->value, value);
    
    return true;
}

char * HeaderGetValue(const HTTPHeader_t * const hdr){
    return hdr->value;
}

HTTPHeader_t * HeaderCreate(const char * name, const char * value){
    HTTPHeader_t * hdr = (HTTPHeader_t *)malloc(sizeof(HTTPHeader_t));

    if(!name || !value) return NULL;

    HeaderSetName(hdr, name);
    HeaderSetValue(hdr, value);

    return hdr;
}

/**
 * @brief Returns a pointer to the data of the body, doesn't deep copy to prevent slowdowns.
 * Returns NULL on error.
 * 
 * @param body 
 * @return char* 
 */
char * BodyGetData(const HTTPBody_t * body){
    if(!body) return NULL;
    return body->data;
}

bool BodySetData(HTTPBody_t * body, const char * data, const int size){
    if(!body || !data)
        return false;
    body->data = data;
    body->size = size;
    return true;
}

/**
 * @brief Takes an endpoint and returns its path
 * 
 * @param ep endpoint 
 * @return char* 
 */
char * EndpointGetPath(const Endpoint_t * const ep){
    char * copy = NULL; 

    if(!ep) return NULL;

    copy = (char *)malloc(strlen(ep->path)*sizeof(char));
    strcpy(copy, ep->path);

    return copy;
}

/**
 * @brief Takes an endpoint and returns its method
 * 
 * @param ep endpoint 
 * @return char* 
 */
char * EndpointGetMethod(const Endpoint_t * const  ep){
    char * copy = NULL; 

    if(!ep) return NULL;

    copy = (char *)malloc(strlen(ep->method)*sizeof(char));
    strcpy(copy, ep->method);

    return copy;
}

bool EndpointSetMethod(Endpoint_t *ep, const char *method){
    int len = 0;

    if(!ep || !method) return false;
    len = strlen(method);
    ep->method = (char *)malloc(sizeof(char)*(len +1));
    strncpy(ep->method, method, len +1 < MAX_METHOD_LENGTH ? len +1 : MAX_METHOD_LENGTH);

    return true;
}

bool EndpointSetPath(Endpoint_t *ep, const char *path){
    int len = 0;
    
    if(!ep || !path) return false;
    len = strlen(path);
    ep->path = (char *)malloc(sizeof(char)*(len +1));
    strncpy(ep->path, path, len +1 < MAX_PATH_LENGTH ? len +1 : MAX_PATH_LENGTH);

    return true;
}


/**
 * @brief Takes a pattern and a URL path.
 * Returns whether the pattern matches the URL path.
 * Use '*' to match everything after a point, for example the pattern "/example/*"
 * matches the patterns: "/example/", "/example/a", "/example/veryverylong/short".
 * Only the first '*' is used for comparison. 
 * 
 * @return true 
 * @return false 
 */
static bool checkPatternPath(const char * const pattern, const char * const path){
    char * star = NULL;
    int res = false;
    int N = 0;

    // Check which string is starred
    star = strchr(pattern, '*');

    if(star){
        N = star - pattern;

        printf("path %s, pattern %s, star %s, N %d\n", path, pattern, star, N);
        printf("%d\n", res = strncmp(path, pattern, N));
    }
    else{
        return strcmp(pattern, path) == 0;
    }

    return false;
}

bool EndpointCompare(const Endpoint_t * const A, const Endpoint_t * const B){
    if(
        strcmp(A->method, B->method) == 0 &&
        strcmp(A->path, B->path) == 0
    )
        return true;
    else
        return false;
}

bool EndpointCmpPatternPath(const Endpoint_t * const A, const Endpoint_t * const B){
    if(
        strcmp(A->method, B->method) == 0 &&
        checkPatternPath(A->path, B->path) == 0
    )
        return true;
    else
        return false;
}

Endpoint_t * EndpointCopy(const Endpoint_t *ep){
    if(!ep || !ep->method || !ep->path) return NULL;
    
    Endpoint_t * new = (Endpoint_t*)malloc(sizeof(Endpoint_t));
    new->method = (char *)malloc((strlen(ep->method) +1)*sizeof(char));
    new->path = (char *)malloc((strlen(ep->path) +1)*sizeof(char));

    strcpy(new->method, ep->method);
    strcpy(new->path, ep->path);

    return new;
}

void EndpointPrint(const Endpoint_t * const ep){
    printf("ep->method: %s\nep->path: %s\n", ep->method, ep->path);
}

/**
 * @brief Takes a time_t and returns a string of a RFC7231 compliant Date header value. 
 * 
 * @param t 
 * @return char* 
 */
char * timetToDateRFC7231(const time_t t){
    char * outstr = (char *)malloc(MAX_DATE_HEADER_VALUE_SIZE*sizeof(char));
    struct tm *tmp;

    tmp = gmtime(&t);
    if (tmp == NULL) {
        logger("timetToDateRFC7231", "Error retrieving localtime (gmtime)\n");
        return NULL;
    }

    if (strftime(outstr, MAX_DATE_HEADER_VALUE_SIZE, "%a, %d %b %Y %T GMT", tmp) == 0) {
        logger("timetToDateRFC7231", "strftime returned 0\n");
        return NULL;
    }

    logger("timetToDateRFC7231", "Result string is \"%s\"\n", outstr);

    return outstr;
}

/**
 * @brief Returns a string with the current date formatted for HTTP communications.
 * 
 */
char * generateDateRFC7231(){
    char * outstr = NULL;
    time_t t;

    t = time(NULL);
    outstr = timetToDateRFC7231(t);

    return outstr;
}

/**
 * @brief Compares two Date headers values.
 * If the first date is less than the second, returns -1.
 * If the dates are equal, returns 0;
 * If the first date is greater than the second, returns 1.
 * 
 * @param A 
 * @param B 
 * @return int 
 */
int compareDateRFC7231(const HTTPHeader_t * const A, const HTTPHeader_t * const B){
    struct tm tmA, tmB;
    char * valA, *valB;
    time_t tA, tB;

    if(!A || !B) return NULL;

    valA = HeaderGetValue(A);
    valB = HeaderGetValue(B);

    memset(&tmA, 0, sizeof(tmA));
    memset(&tmB, 0, sizeof(tmB));
    strptime(valA, "%a, %d %b %Y %T GMT", &tmA);
    strptime(valB, "%a, %d %b %Y %T GMT", &tmB);

    tA = mktime(&tmA);
    tB = mktime(&tmB);
    
    return (tA < tB ? -1 : (tA == tB ? 0 : -1));
}