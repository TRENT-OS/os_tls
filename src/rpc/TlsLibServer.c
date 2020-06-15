/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(OS_TLS_WITH_RPC_SERVER)

#include "lib/TlsLib.h"
#include "rpc/TlsLibServer.h"

#include <string.h>
#include <stdlib.h>

struct TlsLibServer
{
    TlsLib_t* library;
    OS_Dataport_t dataport;
};

/**
 * The component hosting the OS_Tls in RPC_SERVER mode needs to implement
 * a function to provide the server with its client specific context.
 * This way, it is up to the component to handle multiple clients and their
 * respective contexts.
 */
extern OS_Tls_Handle_t
TlsLibServer_getTls(
    void);

// This is not exposed via the header
void*
OS_Tls_getServer(
    OS_Tls_Handle_t api);

// Get SeosTlsRpcServer context from API
#define GET_SELF(s) {                                   \
    OS_Tls_t *a;                                        \
    if (((a = TlsLibServer_getTls()) == NULL) ||        \
        ((s = OS_Tls_getServer(a)) == NULL) )           \
    {                                                   \
        return OS_ERROR_INVALID_PARAMETER;              \
    }                                                   \
    if (OS_Tls_MODE_SERVER != OS_Tls_getMode(a)) {      \
        return OS_ERROR_INVALID_STATE;                  \
    }                                                   \
}

// Server functions ------------------------------------------------------------

OS_Error_t
TlsLibServer_init(
    TlsLibServer_t**     self,
    TlsLib_t*            library,
    const OS_Dataport_t* dataport)
{
    TlsLibServer_t* svr;

    if (NULL == self || NULL == dataport || OS_Dataport_isUnset(*dataport))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((svr = malloc(sizeof(TlsLibServer_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = svr;

    memset(svr, 0, sizeof(TlsLibServer_t));
    svr->dataport = *dataport;
    svr->library  = library;

    return OS_SUCCESS;
}

OS_Error_t
TlsLibServer_free(
    TlsLibServer_t* self)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    free(self);

    return OS_SUCCESS;
}

// RPC functions ---------------------------------------------------------------

OS_Error_t
TlsLibServer_handshake(
    void)
{
    TlsLibServer_t* self;

    GET_SELF(self);
    return TlsLib_handshake(self->library);
}

OS_Error_t
TlsLibServer_write(
    size_t dataSize)
{
    TlsLibServer_t* self;

    GET_SELF(self);
    return TlsLib_write(self->library, OS_Dataport_getBuf(self->dataport),
                        dataSize);
}

OS_Error_t
TlsLibServer_read(
    size_t* dataSize)
{
    TlsLibServer_t* self;

    GET_SELF(self);
    return TlsLib_read(self->library, OS_Dataport_getBuf(self->dataport),
                       dataSize);
}

OS_Error_t
TlsLibServer_reset(
    void)
{
    TlsLibServer_t* self;

    GET_SELF(self);
    return TlsLib_reset(self->library);
}

#endif /* OS_TLS_WITH_RPC_SERVER */