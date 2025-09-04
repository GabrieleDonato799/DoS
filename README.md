# Donato's web Server
C server with sockets implementing the HTTP/1.1 protocol and file handling service.

Student: Gabriele Donato, Matriculation number: 31884A

## Configuration
To get started:
```bash
git clone https://github.com/GabrieleDonato799/DoS.git
cd DoS
make run
```

By default the server exposes resources under `localhost:3456/www/`.
Documents must be put under the public directory `content`.

The code is organized as follows:

```bash
project/
	bin/
		# executable
	main.c # listening process, forking, high level connection handling
	switcher.h
	switcher.c # request switching logic
	lib/
		# libraries
		httpproto/
			httpproto.h
			httpproto.c # HTTP 1.1 implementation
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

### Required privileges
The server is executed as a normal user, running it under a dedicated user is recommended. The server will only bind not well-known ports. Services must have the necessary file system permissions and should follow the principle of least privilege.
## Architecture
### Concurrent server implementation with fork()
#### Components and Responsibilities
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
Follows the operations a worker process does when handling a single request.
```mermaid
flowchart TD
    subgraph worker [worker process]
	    K["Parse the request to extract the endpoint"]
	    G["The request switch logic returns the correct request handler"]
	    H["The handler builds the response"]
	    L["Sends the response"]
	    I["Die on<br>- unrecoverable error<br>- closed connection<br>- connection timeout<br>- parsing errors"]
    end

    K-->|"switcher( Endpoint )"|G
    G-->|"handler( ParsedRequest )"|H
    H-->L
```
To distinguish between requests for different services, a request handler is bound to an endpoint.
####  Shared abstract data types
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

#### Switching logic
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
			W-->>C: 501 Internal Server Error
		end
		
	end
```
### Requests parsing and response building
The software can exclusively handle URLs in [origin form](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages#request_targets) (relative path to the Host header field).
A request handler needs the method to determine the type of action and the path to determine the target resource.
The request handler builds the response using the HTTPResponse primitives. Compares them by checking if they have the same path and method.
The HTTPRequest has a parse() primitive, for the worker process to parse it.
The HTTPResponse has a send() primitive, to hide the details of the transmission.

#### HTTP specific abstract data types
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
## Cookies
The server provides primitives to set and restore http headers. The usage of cookies is left to the specific request handler implementation.

## Services
Every service must be organized in a module that exports the required functionality.
The service are configured at startup by the listening process, by passing the endpoint configuration of the request handler to the switching logic.

#### URL's path to folder path translation
The translation of an URL's path to a folder path to access the actual document it is as follows:
```mermaid
---
title: URL's path to folder path
---
flowchart TD
	A["Obtain the base directory realpath B"]
	B["Append the URL path"]
	C["Obtain the realpath BU"]
	D{"First bytes of B<br>equal to BU?"}
	E["Path traversal"]
	F["Ok"]

	A-->B
	B-->C
	C-->D
	D-->|no|E
	D-->|yes|F
```

### Web server service
Exposes a public directory of web documents. Every file is a resource accessible from a specific path under the particular exposed folder, which is verified by the URL path translation logic.

### File service
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

#### Browser caching
The file server tells the browser to cache a file for one hour as an example. It also provides the Last-Modified header, linked to the last modification time of the files.
