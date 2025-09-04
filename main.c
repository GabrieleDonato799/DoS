#include "common.h"
#include "lib/webUtils.h"
#include "lib/httpproto/httpproto.h"
#include "switcher.h"
#include "handlers/webserver/webserver.h"
#include "handlers/fileserver/fileserver.h"
#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <wait.h>
#include <signal.h>

#define LISTEN_PORT 3456
#define MAXLEN 255
#define MAX_CONNS 10

int moved;

// client handling logic
void handlerEcho(int, struct sockaddr *, int);

void connectionHandler(int, struct sockaddr *, int);

void handle_signal(int);

// Kills all the workers at exit
void killChildren();

// Flushes stdout to prevent losing useful log data.
// Note that the stdout of the workers is redirected to a per worker log file.
void dumpLogs();

int main() {
  struct sockaddr_in saddr;
  int server = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  socklen_t size_saddr;
  int yes=1;

  // endpoint setup
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  saddr.sin_port = htons(LISTEN_PORT);
  size_saddr = sizeof(saddr);

  if((setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) < 0){
    die("setsockopt");
  }
  if ((moved = bind(server, (struct sockaddr *)&saddr, sizeof(saddr))) < 0) {
    die("bind");
  }

  if ((moved = listen(server, MAX_CONNS)) < 0) {
    die("listen");
  }

  // signal handlers to prevent child zombies when exiting
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
  signal(SIGCHLD, handle_signal);
  atexit(killChildren);
  atexit(dumpLogs);

  // register request handlers
  // const Endpoint_t webEp = {"/www/*", "GET"};
  const Endpoint_t fileEpHEAD = {"/www/*", "HEAD"};
  const Endpoint_t fileEpGET = {"/www/*", "GET"};
  const Endpoint_t fileEpPUT = {"/www/*", "PUT"};
  const Endpoint_t fileEpPOST = {"/www/*", "POST"};
  const Endpoint_t fileEpDELETE = {"/www/*", "DELETE"};
  // registerHdlr(&webEp, webSrvReqHdlr);
  registerHdlr(&fileEpHEAD, fileSrvReqHdlr);
  registerHdlr(&fileEpGET, fileSrvReqHdlr);
  registerHdlr(&fileEpPUT, fileSrvReqHdlr);
  registerHdlr(&fileEpPOST, fileSrvReqHdlr);
  registerHdlr(&fileEpDELETE, fileSrvReqHdlr);

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

void dumpLogs(){
  fflush(stdout);
}

void killChildren(void){
  int status;
  pid_t pid;

  // logger("killChildren", "Entering\n");

  while((pid = waitpid(0, &status, WNOHANG)) > 0); // wait all children, then die

  // logger("killChildren", "Exiting\n");
  
  return;
}

void handle_signal(int signum) {

  logger("handle_signal", "Entering, %s\n", strsignal(signum));

  switch(signum){
    case SIGINT:
    case SIGTERM:
    {
      killChildren();
      logger("handle_signal", "exit(EXIT_SUCCESS)\n");
      exit(EXIT_SUCCESS);
    }
    break;
    case SIGCHLD:
    {
      killChildren();
    }
    break;
  }

  logger("handle_signal", "Exiting\n");
}

void connectionHandler(int client, struct sockaddr *sa, int length) {
  char logName[25];
  HTTPRequest_t * req = NULL;
  HTTPResponse_t * res = NULL;
  Endpoint_t * ep = NULL;
  handler_t handler = NULL;

  // Restore signal handlers
  signal(SIGINT, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGCHLD, SIG_DFL);

  logger("connectionHandler", "Entering\n");

  // logging to a per worker file
  snprintf(logName, 25, "logs/child_%d.log", getpid());
  freopen(logName, "w", stdout);
  freopen(logName, "w", stderr);

  req = RequestParse(client);
  ep = RequestGetEndpoint(req);
  
  logger("connectionHandler", "ep->method: %s, ep->path: %s\n", ep->method, ep->path);
  
  printRegisteredHdlrs();
  handler = switcher(ep);
  if(handler)
    res = handler(req);
  else
    logger("connectionHandler", "Invalid request handler: %p!\n", handler);

  if(!res)
    res = createErrorResponse(501);

  if(!ResponseSend(res, client)){
    logger("connectionHandler", "Couldn't send the response\n");
  }

  freeRequest(req);
  freeResponse(res);

  return;
}

void handlerEcho(int client, struct sockaddr *sa, int length) {
  char sendbuff[MAXLEN + 1]; // last byte will always be zero
  char recvbuff[MAXLEN + 1];

  memset(sendbuff, 0, MAXLEN + 1);
  memset(recvbuff, 0, MAXLEN + 1);

  Recv(client, recvbuff, MAXLEN, 0);
  strcpy(sendbuff, recvbuff);
  Send(client, sendbuff, MAXLEN, 0);

  return;
}
