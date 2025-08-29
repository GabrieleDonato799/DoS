#include "switcher.h"
#include "lists.h"
#include "lib/httpproto/httpproto.h"

#define MAX_ENDPOINTS 10

handler_t switcher(const Endpoint_t *ep){
    return cercaHandler(registeredHandlers, ep);
}

bool registerHdlr(const Endpoint_t * ep, const handler_t hdlr){
    Endpoint_t * new = EndpointCopy(ep);

    Dict_t d = creaDict(new, hdlr);
    registeredHandlers = inserisciInTesta(registeredHandlers, d);
}

bool printRegisteredHdlrs(){
    stampaDict(registeredHandlers);
}