#ifndef HTTPPROTO_H
#define HTTPPROTO_H
#include <stdbool.h>
#include <time.h>

#define MAX_REQ_SIZE 8192
#define MAX_HEADERS 100
#define MAX_PATH_LENGTH 256
#define MAX_METHOD_LENGTH 10
#define MAX_DATE_HEADER_VALUE_SIZE 200
// 16 MiB
#define MAX_RESPONSE_BODY_SIZE 16777216
#define HTTP_VERSION_1_1 2

typedef struct{
    char * method;
    char * path;
    char * protocol;
} HTTPRequestLine_t;

typedef struct{
    char * protocol;
    int statusCode;
    char * statusMessage;
} HTTPResponseLine_t;

typedef struct{
    char * name;
    char * value;
} HTTPHeader_t;

typedef struct{
    char * data;
    int size; // to support binary files
} HTTPBody_t;

// The headers should be a NULL terminated vector of HTTPHeader_t
typedef struct {
    HTTPRequestLine_t * reqLine;
    HTTPHeader_t * headers;
    HTTPBody_t * body;
} HTTPRequest_t;

// The headers should be a NULL terminated vector of HTTPHeader_t
typedef struct{
    HTTPResponseLine_t * resLine;
    HTTPHeader_t * headers;
    int nHeaders;
    HTTPBody_t * body;
} HTTPResponse_t;

typedef struct{
    char * path;
    char * method;
} Endpoint_t;

typedef HTTPResponse_t * (*handler_t)(HTTPRequest_t *);

/**
 * @brief Reads a line of data from a TCP stream, use only WITHOUT PERMANENT CONNECTIONS.
 * Takes the stream file descriptor.
 * Returns a buffer to a copy of the line read, it it encounters an empty line it returns NULL instead.
 * It should not be called again in the current worker process after returning NULL, as it is not currently resettable.
 * 
 * @return char *
 */
// static char * HTTPRequestReadLine(int sockfd);

// static HTTPRequestLine_t * RequestParseReqLine(const char *);
void printHTTPRequestLine(HTTPRequestLine_t *);

/**
 * @brief Takes a line read with HTTPRequestReadLine(), returns the parsed HTTP header.
 * The line must contain the trailing "\r\n".
 * 
 * @return HTTPHeader_t 
 */
// static HTTPHeader_t * RequestParseHeaderField(const char *);
// static HTTPBody_t * RequestRecvBody(HTTPHeader_t);

/**
 * @brief Takes the client socket file descriptor, receives, parses and returns the request.
 * 
 * @return HTTPRequest_t 
 */
HTTPRequest_t * RequestParse(int);

/**
 * @brief Takes a HTTPHeader_t NULL terminated vector and a header name.
 * Returns a pointer to the header inside the vector, which name matches the supplied one, returns NULL on error.
 * The search is case insensitive.
 * 
 * @return HTTPHeader_t* 
 */
// static HTTPHeader_t * findHeader(const HTTPHeader_t *, const char *);

/**
 * @brief Takes a HTTP Request and returns an endpoint structure, describing the method and path of the request.
 * 
 * @return Endpoint_t *
 */
Endpoint_t * RequestGetEndpoint(const HTTPRequest_t *);

HTTPBody_t * RequestGetBody(const HTTPRequest_t *);

HTTPHeader_t * RequestFindHeader(const HTTPRequest_t *, const char *);

/**
 * @brief Initializes the fields of a request structure.
 * 
 */
void initRequest(HTTPRequest_t **);

/**
 * @brief Takes a request and correctly frees every field.
 * Can be used on halfy filled HTTPRequest structures.
 * 
 */
void freeRequest(HTTPRequest_t *);

bool ResponseSetResLine(HTTPResponse_t *, HTTPResponseLine_t *);
bool ResponseAddBody(HTTPResponse_t *, const HTTPBody_t *);

/**
 * @brief Takes a response, an header name an value.
 * Returns true on success, false otherwise.
 * 
 * @return bool
 */
bool ResponseAddHeader(HTTPResponse_t *, const char *, const char *);

/**
 * @brief Transmits the HTTP response over the file descriptor.
 * Returns true on success, false otherwise.
 * 
 * @return bool
 */
bool ResponseSend(const HTTPResponse_t *, int);

/**
 * @brief Initializes the fields of a response structure.
 * 
 */
void initResponse(HTTPResponse_t **);

/**
 * @brief Takes a response and correctly frees every field.
 * Can be used on halfy filled HTTPResponse structures.
 * 
 */
void freeResponse(HTTPResponse_t *);

/**
 * @brief Returns a copy of the method of the request line.
 * 
 * @return char* 
 */
char * RequestLineGetMethod(HTTPRequestLine_t *);
char * RequestLineGetHost(HTTPRequestLine_t *);

/**
 * @brief Returns a copy of the path of the request line.
 * 
 * @return char* 
 */
char * RequestLineGetPath(HTTPRequestLine_t *);
char * RequestLineGetProtocol(HTTPRequestLine_t *);

/**
 * @brief Takes a status line and a HTTP_VERSION_X, sets the correct version string.
 * 
 * @return true on success
 * @return false on error
 */
bool ResponseLineSetProtocol(HTTPResponseLine_t *, const int);

char * getStatusMessage(const int);

/**
 * @brief Takes a status line and sets the status code.
 * 
 * @return true on success
 * @return false on error
 */
bool ResponseLineSetStatusCode(HTTPResponseLine_t *, int);

bool HeaderSetName(HTTPHeader_t *, const char *);
bool HeaderSetValue(HTTPHeader_t *, const char *);
char * HeaderGetValue(const HTTPHeader_t *);

HTTPHeader_t * HeaderCreate(const char *, const char *);

char * BodyGetData(const HTTPBody_t *);
bool BodySetData(HTTPBody_t *, const char *, const int);

char * EndpointGetPath(const Endpoint_t *);

char * EndpointGetMethod(const Endpoint_t *);

/**
 * @brief Sets the path of the Endpoint_t. Returns false on error, true otherwise.
 * 
 * @return bool
 */
bool EndpointSetPath(Endpoint_t *, const char *);

/**
 * @brief Sets the method of the Endpoint_t. Returns false on error, true otherwise.
 * 
 * @return bool
 */
bool EndpointSetMethod(Endpoint_t *, const char *);

/**
 * @brief Takes two endpoints and compares them.
 * 
 * @return true if both the method and path field match
 * @return false otherwise
 */
bool EndpointCompare(const Endpoint_t *, const Endpoint_t *);

/**
 * @brief Takes two endpoints and compares them, treating the path of
 * the first like a pattern for the second, comparing them with
 * checkPatternPath().
 * 
 * @return true if both the method and path field match
 * @return false otherwise
 */
bool EndpointCmpPatternPath(const Endpoint_t *, const Endpoint_t *);

/**
 * @brief Returns a deep copy of the Endpoint_t, allocated on the heap.
 * You can only copy a fully initialized Endpoint_t (ie both method and path set).
 * 
 */
Endpoint_t * EndpointCopy(const Endpoint_t *);

/**
 * @brief Takes an endpoint and prints out its fields.
 * 
 */
void EndpointPrint(const Endpoint_t *);

char * timetToDateRFC7231(const time_t);

char * generateDateRFC7231();

int compareDateRFC7231(const HTTPHeader_t *, const HTTPHeader_t *);

#endif // HTTPPROTO_H