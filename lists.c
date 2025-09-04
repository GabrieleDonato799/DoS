#include "lists.h"
#include "lib/httpproto/httpproto.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>

void exampleHdlr(void){
    logger("exampleHdlr", "Hi!\n");
}

Dict_t creaDict(const Endpoint_t * ep, const handler_t * hdlr){
    Dict_t d;
    DictSetKey(&d, (void *)ep);
    DictSetValue(&d, (void *)hdlr);
    return d;
}

void * DictGetKey(const Dict_t * const d){
    void * key = NULL;
    if(d) key = d->key;
    return key;
}
void * DictGetValue(const Dict_t * const d){
    void * value = NULL;
    if(d) value = d->value;
    return value;
}
bool DictSetKey(Dict_t * const d, const void * const key){
    if(!d) return false;
    d->key = key;
    return true;
}
bool DictSetValue(Dict_t *d, const void * const value){
    if(!d) return false;
    d->value = value;
    return true;
}

struct S_Node * creaLista(){
    return NULL;
}

struct S_Node * inserisciInTesta(struct S_Node * list, const Dict_t dict){
    struct S_Node * e = (struct S_Node *)malloc(sizeof(struct S_Node));

    if(e == NULL){
        printf("Errore: malloc in inserisciInTesta()\n");
        exit(EXIT_FAILURE);
    }

    e->next = list;
    e->dict = dict;
    
    return e;
}

// struct S_Node * rimuoviInTesta(struct S_Node * list){
//     struct S_Node * head = list;

//     if(list == NULL) return NULL;

//     list = list->next;
//     free(head);
//     return list;
// }

// struct S_Node * cancella(struct S_Node * list){
//     while((list = rimuoviInTesta(list)) != NULL);

//     return NULL;
// }

/**
 * @brief Takes an endpoint, returns the corresponding handler. Returns NULL if absent or if an error occurs.
 * 
 * @return struct Node_S* 
 */
handler_t cercaHandler(const struct S_Node * list, const Endpoint_t * sample){
    const struct S_Node *cur;

    if(list == NULL) return NULL;

    cur = list;
    while(cur != NULL && EndpointCmpPatternPath(sample, DictGetKey(&cur->dict)) == 0){
        cur = cur->next;
    }

    if(cur){
        return (handler_t)(DictGetValue(&cur->dict));
    }
    else{
        return (handler_t)NULL;
    }
}

void stampaDict(const struct S_Node * list){
    while(list != NULL){
        logger("stampaDict", "key: %p, value: %p, next: %p\n", list, list->dict.key, list->dict.value, list->next);
        list = list->next;
    }
    return;
}