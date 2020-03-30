/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(SEOS_TLS_WITH_RPC_SERVER)

#include "OS_TlsLib.h"
#include "OS_TlsRpcServer.h"

#include <string.h>
#include <stdlib.h>

struct OS_TlsRpcServer
{
    OS_TlsLib_t* library;
    void* dataport;
};

/**
 * The component hosting the OS_Tls in RPC_SERVER mode needs to implement
 * a function to provide the server with its client specific context.
 * This way, it is up to the component to handle multiple clients and their
 * respective contexts.
 */
extern OS_Tls_Handle_t
OS_TlsRpcServer_getTls(
    void);

// This is not exposed via the header
void*
OS_Tls_getServer(
    OS_Tls_Handle_t api);

// Get SeosTlsRpcServer context from API
#define GET_SELF(s) {                                   \
    OS_Tls_t *a;                                        \
    if (((a = OS_TlsRpcServer_getTls()) == NULL) ||     \
        ((s = OS_Tls_getServer(a)) == NULL) )           \
    {                                                   \
        return SEOS_ERROR_INVALID_PARAMETER;            \
    }                                                   \
    if (OS_Tls_MODE_RPC_SERVER != OS_Tls_getMode(a)) {  \
        return SEOS_ERROR_INVALID_STATE;                \
    }                                                   \
}

// Server functions ------------------------------------------------------------

seos_err_t
OS_TlsRpcServer_init(
    OS_TlsRpcServer_t**             self,
    const OS_TlsRpcServer_Config_t* cfg)
{
    OS_TlsRpcServer_t* svr;
    seos_err_t err;

    if (NULL == self || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((svr = malloc(sizeof(OS_TlsRpcServer_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = svr;
    memset(svr, 0, sizeof(OS_TlsRpcServer_t));
    svr->dataport = cfg->dataport;

    // We need an instance of the library for the server to work with
    if ((err = OS_TlsLib_init(&svr->library, &cfg->library)) != SEOS_SUCCESS)
    {
        free(svr);
    }

    return err;
}

seos_err_t
OS_TlsRpcServer_free(
    OS_TlsRpcServer_t* self)
{
    seos_err_t err;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = OS_TlsLib_free(self->library);
    free(self);

    return err;
}

// RPC functions ---------------------------------------------------------------

seos_err_t
OS_TlsRpcServer_handshake(
    void)
{
    OS_TlsRpcServer_t* self;

    GET_SELF(self);
    return OS_TlsLib_handshake(self->library);
}

seos_err_t
OS_TlsRpcServer_write(
    size_t dataSize)
{
    OS_TlsRpcServer_t* self;

    GET_SELF(self);
    return OS_TlsLib_write(self->library, self->dataport, dataSize);
}

seos_err_t
OS_TlsRpcServer_read(
    size_t* dataSize)
{
    OS_TlsRpcServer_t* self;

    GET_SELF(self);
    return OS_TlsLib_read(self->library, self->dataport, dataSize);
}

seos_err_t
OS_TlsRpcServer_reset(
    void)
{
    OS_TlsRpcServer_t* self;

    GET_SELF(self);
    return OS_TlsLib_reset(self->library);
}

#endif /* SEOS_TLS_WITH_RPC_SERVER */