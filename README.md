# Donato's web Server
C server with sockets implementing the HTTP/1.1 protocol and file handling service.

Student: Gabriele Donato, Matriculation number: 31884A

# Configuration
To get started:
```bash
git clone https://github.com/GabrieleDonato799/DoS.git
cd DoS
make run
```

By default the server exposes resources under `localhost:3456/www/`.
Documents must be put under the public directory `content`.

The code is organised as follows:

```bash
project/
	bin/
		# executable
	content/
		# web content and files
	main.c # listening process, forking, high level connection handling
	switcher.h
	switcher.c # request switching logic
	common.h
	common.c # code shared by most C modules
	unittests.py # unit tests with Python3 unittest module
	lib/
		# libraries
		httpproto/
			httpproto.h
			httpproto.c # HTTP 1.1 implementation
		path.h
		path.c # path handling utilities
		lists.h
		lists.c # simple list implementation
	handlers/
		# request handlers / services implementation
		webserver/
			webserver.h
			webserver.c
		fileserver/
			fileserver.h
			fileserver.c
    content/
      # public content
```

To configure the services or the main server software, a basic internal configuration API is present.

# Requirements analysis

| Functional requirement                                                                 | Priority |
| -------------------------------------------------------------------------------------- | -------- |
| Concurrent server implementation with fork()                                           | 1        |
| HTTP request parsing                                                                   | 1        |
| HTTP response building                                                                 | 1        |
| Support for the following HTTP headers: Host, Content-Length, Date, Server, Connection | 2        |
| Converting between the HTTP Date header value format and a C date format               | 2        |
| Support for the following HTTP methods: GET/HEAD, PUT, POST, DELETE                    | 3        |
| Basic cookie retrieval (Cookie header) and setting (Set-Cookie header)                 | 4        |
| Basic negotiation capabilities with Accept and Content-Type                            | 4        |
| A file handling service to manage files under a specific directory                     | 5        |
| Files specified in the path of the URL of the HTTP request                             | 5        |
| Conditional GET requests, linked to the last modification time of the files            | 5        |
| Persistent TCP connections with keepalive, Connection header field                     | 6        |

| Non-functional requirement           | Priority |
| ------------------------------------ | -------- |
| Prevent path traversal with chroot() | 6        |


## Required privileges
The server is executed as a normal user, running it under a dedicated user is recommended. The server will only bind not well-known ports. Services must have the necessary file system permissions and should follow the principle of least privilege.
# Architecture
## Concurrent server implementation with fork()
### Components and Responsibilities
The *listening process*:  
receives connections from the clients and delegates their handling to worker processes. Configures the switching logic by binding endpoints to the request handlers.

The *worker process*:  
handles the connection with the client by parsing requests, then passing it to the request handler, indicated by the switching logic, and sending the response back to the client.

The *switching logic*:  
keeps the bindings between an endpoint and a request handler, determines which request handler must receive a request from a client. 

The *request handler*:  
implements the service logic, takes a request and builds a response, returned to the worker process for transmission.

The architecture is designed to work with and without permanent TCP connections.
```mermaid
flowchart TD
	subgraph listening [listening process]
		J[Configure the request handlers]
	    A[Starts listening]
	    B[Accepts a connection]
	    F["Forks()"]
    end
    subgraph worker [worker process]
	    K["Handle the connection"]
    end

	J-->A
    A-->B
    F-->K
    B-->F
    F-->A
```
Follow the important code fragments of the listening process:

```C
int main() {
  int server = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  
  // local socket setup...
  // listen to incoming connections ...
  // registering custom signal handlers to prevent child zombies when exiting...

  // register request handlers for the file service
  const Endpoint_t fileEpDELETE = {"/www/*", "DELETE"};
  registerHdlr(&fileEpDELETE, fileSrvReqHdlr);
  // ...

  logger("main", "Server started\n");

  while (1) {
    int s;
    if ((s = accept(server, (struct sockaddr *)&saddr, &size_saddr)) >= 0) {
      pid_t pid;

      logger("main", "Client connected!\n");
      if ((pid = fork()) < 0) { // error
        die("fork");
      } else if (pid == 0) { // son
        logger("main", "I've been forked!\n");
        // sockets handling & communications
        close(server);
        connectionHandler(s, (struct sockaddr *)&s, sizeof(s));
        close(s);
        
        logger("main", "Client disconnected!\n");
        exit(EXIT_SUCCESS);
      } else { // father
        close(s);
      }
    }
  }

  return 0;
}
```
Follows the operations a worker process does when handling a single request.
```mermaid
flowchart TD
    subgraph worker [worker process]
		direction TB
	    K["Parse the request to extract the endpoint"]
	    G["The request switch logic returns the correct request handler"]
	    H["The handler builds the response"]
	    L["Sends the response"]
    end

    K-->|"switcher( Endpoint )"|G
    G-->|"handler( ParsedRequest )"|H
    H-->L
```
Notice that the worker process can die on the following events:
- unrecoverable error
- closed connection
- connection timeout
- parsing errors

Follow the important code fragments of the connection handling logic:
```C
void connectionHandler(int client, struct sockaddr *sa, int length) {
  HTTPRequest_t * req = NULL;
  HTTPResponse_t * res = NULL;
  Endpoint_t * ep = NULL;
  handler_t handler = NULL;

  // Restore signal handlers
  // ...

  // logging to a per worker file
  // ... output redirection
  
  req = RequestParse(client);
  ep = RequestGetEndpoint(req);
    
  handler = switcher(ep);
  if(handler)
    res = handler(req);
  else
    logger("connectionHandler", "Invalid request handler: %p!\n", handler);

  if(!res)
    res = createErrorResponse(500);

  if(!ResponseSend(res, client)){
    logger("connectionHandler", "Couldn't send the response\n");
  }

  freeRequest(req);
  freeResponse(res);

  return;
}
```
To distinguish between requests for different services, a request handler is bound to an endpoint.
###  Shared abstract data types
The endpoint to which the request handler is bound is not dependent on the service configuration itself, but depends on the server software configuration.
The scheme, host, port and path on which the service must be exposed are determined by the listening server process, on startup, long before a request handler receives data. Thus every request is handled with the same configuration.
```mermaid
---
title: Request Handler Configuration Abstract Data Types
---
classDiagram
	class Endpoint{
		-string path
		-string method
		
		+int compare(Endpoint)
		+string setPath()
		+string setMethod()
		+string getPath()
		+string getMethod()
	}
```
The bindings are managed with a simple list implementation as follows:
```mermaid
---
title: List Abstract Data Types
---
classDiagram
    class Dict{
	    -Endpoint key
	    -Handler value

		+creaDict(Endpoint, Handler)
	    +getKey()
	    +setKey()
	    +getValue()
	    +setValue()
    }
    
    class Node{
	    -Dict dict
	    -NodeRef Next
    }
```

### Switching logic
The switcher() returns a handler function exported by the request handler's module. The switching logic:
	- Determines which handler must receive the request, by comparing the endpoint to those of the bound handlers.
	- Simply returns the handler reference to the worker process (to enforce the principle of single responsibility).
```mermaid
---
title: Binding of a request handler
---
sequenceDiagram
	participant W as Worker process
	participant S as Switching logic
	
	W->>S: registerHdlr( endpoint )
	alt
		S->>W: Success
	else
		S->>W: Error: Endpoint in use
	else
		S->>W: Error: Invalid endpoint
	end
```

```mermaid
---
title: Requesting a service and responding
---
sequenceDiagram
	participant C as Client
	participant W as Worker process
	participant S as Switching logic
	participant H as Request handler
	
	loop While the connection is up / For a single request
		C->>+W: Request
		W->>+S: switcher( Endpoint )
		S-->>-W: handler
		W->>+H: handler( ParsedRequest )
		alt Handler success
			H-->>-W: Built response/Error response
			W-->>-C: Response
		else Handler error
			H-->>W: Error
			W-->>C: 500 Internal Server Error
		end
		
	end
```
## Requests parsing and response building
The software can exclusively handle URLs in [origin form](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages#request_targets) (relative path to the Host header field).
A request handler needs the method to determine the type of action and the path to determine the target resource.
The request handler builds the response using the HTTPResponse primitives. Compares them by checking if they have the same path and method.
The HTTPRequest has a parse() primitive, for the worker process to parse it.
The HTTPResponse has a send() primitive, to hide the details of the transmission.

### HTTP specific abstract data types
Objects are copied whenever possible.
```mermaid
---
title: HTTP Abstract Data Types
---
classDiagram
    HTTPRequest o-- HTTPRequestLine
    HTTPRequest o-- HTTPHeader
    HTTPRequest o-- HTTPBody
    HTTPResponse o-- HTTPResponseLine
    HTTPResponse o-- HTTPHeader
    HTTPResponse o-- HTTPBody
    
    class HTTPRequest{
	    -string readLine()
	    -HTTPReqLine parseReqLine()
	    -HTTPHeader parseHeaderField()
	    -HTTPBody recvBody(HTTPHeader contentLength)
	    +HTTPRequest parse()
    }
    
    class HTTPResponse{
	    +bool setResLine(HTTPRequestLine)
	    +bool addBody(HTTPBody)
	    +bool addHeader(string key, string value)
	    +bool send()
    }
    
    class HTTPRequestLine{
        -string method
        -string path
        -string protocol
  
        +string getMethod()
        +string getHost()
        +string getPath()
        +string getProtocol()
    }
    class HTTPResponseLine{
        -string protocol
        -int statusCode
        -string statusMessage
  
        +bool setProtocol(string)
        +bool setStatusCode(int)
        -bool setStatusMessage(string)
    }
  
    class HTTPHeader{
        -string name
        -string value
 
        +bool setName(string)
        +bool setValue(string)
    }
  
    class HTTPBody{
        -string data
  
        +string getData()
        +string setData()
    }
```
```mermaid
---
title: send() primitive of HTTPResponse
---
flowchart TD
	A["Send status line"]
	B["Send headers"]
	C["Send body"]
	D["Send blankline"]
	E{"Method implies body?"}
	Z["Done"]

	A-->B
	B-->D
	D-->E
	E-->|Yes|C
	E-->|No|Z
	C-->Z
```
The parser logic is as follows:
```mermaid
---
title: parse() method of HTTPRequest
---
flowchart TD
	B["parseReqLine(readLine())"]
	subgraph "Parsing headers"
		H["line = readLine()"]
		F{"empty line?"}
		E["hdr = parseHeaderField()"]
		G["Add hdr to headers[]"]
		I["method implies body support?"]
	end
	D["readBody()"]
	J["return the parsed request"]
	
	B-->H
	H-->F
	F-->|Yes, no more headers|I
	F-->|No|E
	I-->|Yes|D
	I-->|No|J
	D-->J
	E-->G
	G-->H
```

Follow the important code fragments of parser logic:
```C
HTTPRequest_t * RequestParse(int client){
    char * line;
    int curHdr = 0;
  
    HTTPRequest_t * req = NULL;
    HTTPRequestLine_t * reqLine = NULL;
    HTTPHeader_t * headers = NULL; // NULL terminated
 
    initRequest(&req);

    headers = (HTTPHeader_t *)calloc(MAX_HEADERS +1, sizeof(HTTPHeader_t));
    
    reqLine = RequestParseReqLine(HTTPRequestReadLine(client));
  
    // parse the headers
    while((line = HTTPRequestReadLine(client)) != NULL){
      // reached empty line separating headers from body
      if(strcmp("", line) == 0){
        break;
      }
  
      if(curHdr < MAX_HEADERS){
        headers[curHdr++] = *RequestParseHeaderField(line);
      }
      else{
        die("413 (Too many headers)");
      }
    }
  
    // assemble the request
    req->reqLine = reqLine;
    req->headers = headers;
  
    logger("RequestParse", "Exiting\n");  

    return req;
}
```
The readline() primitive abstracts away the details of the TCP connection stream and memory allocation and management of the receiver's buffer.
```mermaid
---
title: readLine()
---
flowchart TD
	A["Create a full sized request buffer, start and end pointers"]
	B["Read N bytes from connection stream"]
	C["endptr = findEOL()"]
	D{"EOL found?"}
	E["Extract string [startptr, endptr]"]
	F["startptr = endptr + 1"]
	G["Return extracted string"]

	K["End of buffer reached?"]
	L["413 Content Too Large"]

	A-->B
	B-->C
	C-->D
	D-->|Yes|E
	D-->|No|K
	E-->F
	F-->G
	K-->|Yes|L
	K-->|No|B
```
Here is the code fragment of the readLine primitive:

```C
static char * HTTPRequestReadLine(int sockfd){
	// create a full sized request buffer
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
        die("strstr(start, \"\\r\\n\")");
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
```
## Cookies
The server provides primitives to set and restore http headers. The usage of cookies is left to the specific request handler implementation.

## Services
Every service must be organised in a module that exports the required functionality.
The services are configured at startup by the listening process, by passing the endpoint configuration of the request handler to the switching logic.

### URL's path to folder path translation
The translation of an URL's path to a folder path to access the actual document it is as follows:
```mermaid
---
title: URL's path to folder path
---
flowchart TD
	A["Obtain the base directory realpath B"]
	C["Append the URL path U<br>to get BU"]
	D["Get real-path BUr"]
	J{"realpath() fails?"}
	K["Remove last path<br>component of BU"]
	L{"Failed at least once?"}
	M{"Removed only<br>one component?"}
	N["Add the component back"]
	E{"First bytes of B<br>equal to BU?"}
	F["Path traversal"]
	G["Ok, return real-path BUr"]
	O["Error"]
	Z["END"]

	A-->C
	C-->D
	D-->J
	J-->|yes|K
	K-->D
	J-->|no|L
	L-->|yes|M
	M-->|yes|N
	M-->|no|O
	N-->E
	L-->|no|E
	E-->|no|F
	E-->|yes|G
	O-->Z
	G-->Z
	F-->Z
```
The logic can be found inside /webUtils.c --> URLPath2AbsFilePath()

To remove components a new module, which represents the Path ADT, has been created.
```mermaid
---
title: Path Abstract Data Type
---
classDiagram
    class Path ADT{
        -string lastRemovedComponent
        -bool reachedStart
  
        +string setPath(string)
        +string getPath()
        +int getNumberRemovedComponents()
        +bool getLastRemovedComponent(stringRef)
        +bool removeLastComponent()
    }
```
The general idea of how the primitives should be used is as follows (name have been reduced):
```mermaid
---
title: How to use the Path primitives
---
flowchart TD
	A["setPath"]
	B["getPath"]
	C["getNumRemComp"]
	D["getLastRemComp"]
	E["remLastComp"]
	
	A-->E
	E-->E
	E-->B
	E-->C
	E-->D
```
## Web server service
Exposes a public directory of web documents. Every file is a resource accessible from a specific path under the particular exposed folder, which is verified by the URL path translation logic.

## File service
This service exposes files for creation (POST), retrieval (GET/HEAD), edit (PUT), deletion (DELETE). Files are specified in the URL's path of the request.
```mermaid
flowchart TD
	A[Translate URL's path -> folder path]
	B[Execute operation]
	D[Prepare response]
	E[Return response]
	
	A-->B
	B-->D
	D-->E
```

### Browser caching
The file server tells the browser to cache a file for one hour as an example. It also provides the Last-Modified header, linked to the last modification time of the files.

An example is the following image I requested for a second time a resource and the server responded correctly with a `304 Not Modified` response.  
<img width="809" height="755" alt="304_cached_response" src="https://github.com/user-attachments/assets/d24036e2-cc2c-45b5-a6d6-182c08df15da" />

Instead, this is a subsequent request with the disabled browser cache.  
<img width="809" height="741" alt="200_non_cached_response" src="https://github.com/user-attachments/assets/5eaba6d0-fb7c-4cad-b71a-0d6276e24b2e" />
