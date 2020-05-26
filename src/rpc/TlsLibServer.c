/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(SEOS_TLS_WITH_RPC_SERVER)

#include "lib/TlsLib.h"
#include "rpc/TlsLibServer.h"

#include <string.h>
#include <stdlib.h>

struct TlsLibServer
{
    TlsLib_t* library;
    void* dataport;
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
        return SEOS_ERROR_INVALID_PARAMETER;            \
    }                                                   \
    if (OS_Tls_MODE_SERVER != OS_Tls_getMode(a)) {      \
        return SEOS_ERROR_INVALID_STATE;                \
    }                                                   \
}

// Server functions ------------------------------------------------------------

OS_Error_t
TlsLibServer_init(
    TlsLibServer_t**             self,
    const TlsLibServer_Config_t* cfg)
{
    TlsLibServer_t* svr;
    OS_Error_t err;

    if (NULL == self || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((svr = malloc(sizeof(TlsLibServer_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = svr;
    memset(svr, 0, sizeof(TlsLibServer_t));
    svr->dataport = cfg->dataport;

    // We need an instance of the library for the server to work with
    if ((err = TlsLib_init(&svr->library, &cfg->library)) != SEOS_SUCCESS)
    {
        free(svr);
    }

    return err;
}

OS_Error_t
TlsLibServer_free(
    TlsLibServer_t* self)
{
    OS_Error_t err;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = TlsLib_free(self->library);
    free(self);

    return err;
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
    return TlsLib_write(self->library, self->dataport, dataSize);
}

OS_Error_t
TlsLibServer_read(
    size_t* dataSize)
{
    TlsLibServer_t* self;

    GET_SELF(self);
    return TlsLib_read(self->library, self->dataport, dataSize);
}

OS_Error_t
TlsLibServer_reset(
    void)
{
    TlsLibServer_t* self;

    GET_SELF(self);
    return TlsLib_reset(self->library);
}

#endif /* SEOS_TLS_WITH_RPC_SERVER */