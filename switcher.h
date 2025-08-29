#ifndef SWITCHER_H
#define SWITCHER_H

#include "lib/httpproto/httpproto.h"

static struct S_Node * registeredHandlers;

// typedef HTTPResponse_t (*handler_t)(HTTPRequest_t *);

// Takes a NULL terminated vector of Dict_t 
handler_t switcher(const Endpoint_t *);

/**
 * @brief Register the association between an Endpoint and a request handler.
 * The Endpoint is deep copied.
 * 
 * @return true on success
 * @return false on error
 */
bool registerHdlr(const Endpoint_t *, const handler_t);

bool printRegisteredHdlrs();

#endif // SWITCHER_H