#ifndef LISTS_H
#define LISTS_H

#include "lib/httpproto/httpproto.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct{
    void * key;
    void * value;
} Dict_t;

struct S_Node{
    Dict_t dict;
    struct S_Node * next;
};

void exampleHdlr(void);

Dict_t creaDict(const Endpoint_t *, const handler_t *);

/**
 * @brief Returns the dictionary' key. NULL on error.
 * 
 * @return void* 
 */
void * DictGetKey(const Dict_t *);

/**
 * @brief Returns the dictionary' value. NULL on error.
 * 
 * @return void* 
 */
void * DictGetValue(const Dict_t *);

/**
 * @brief Sets the dictionary' key.
 * Returns true on success, false on error.
 * 
 * @return bool
 */
bool DictSetKey(Dict_t *, const void *);

/**
 * @brief Returns the dictionary' value. NULL on error.
 * Returns true on success, false on error.
 * 
 * @return bool 
 */
bool DictSetValue(Dict_t *, const void *);

/**
 * @brief To initialize a list, create a struct S_Node pointer variable and assign it NULL.
 * 
 * @return struct S_Node* NULL
 */
struct S_Node * creaLista();

struct S_Node * inserisciInTesta(struct S_Node *, Dict_t);

// struct S_Node * rimuoviInTesta(struct S_Node *);

// struct S_Node * cancella(const struct S_Node *);

/**
 * @brief Takes an endpoint, returns the corresponding handler. Returns NULL if absent or if an error occurs.
 * 
 * @return struct Node_S* 
 */
handler_t cercaHandler(const struct S_Node *, const Endpoint_t *);

void stampaDict(const struct S_Node *);

#endif // LISTS_H