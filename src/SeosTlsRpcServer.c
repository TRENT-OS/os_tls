/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(SEOS_TLS_WITH_RPC_SERVER)

#include "SeosTlsLib.h"
#include "SeosTlsRpcServer.h"

#include <string.h>
#include <stdlib.h>

struct SeosTlsRpcServer
{
    SeosTlsLib* library;
    void* dataport;
};

/**
 * The component hosting the SeosTlsApi in RPC_SERVER mode needs to implement
 * a function to provide the server with its client specific context.
 * This way, it is up to the component to handle multiple clients and their
 * respective contexts.
 */
extern SeosTlsApi*
SeosTlsRpcServer_getSeosTlsApi(
    void);

// This is not exposed via the header
void*
SeosTlsApi_getServer(
    SeosTlsApi* api);

// Get SeosTlsRpcServer context from API
#define GET_SELF(s) {                                           \
    SeosTlsApi *a;                                              \
    if (((a = SeosTlsRpcServer_getSeosTlsApi()) == NULL) ||     \
        ((s = SeosTlsApi_getServer(a)) == NULL) )               \
    {                                                           \
        return SEOS_ERROR_INVALID_PARAMETER;                    \
    }                                                           \
    if (SeosTlsApi_Mode_RPC_SERVER != SeosTlsApi_getMode(a)) {  \
        return SEOS_ERROR_INVALID_STATE;                        \
    }                                                           \
}

// Server functions ------------------------------------------------------------

seos_err_t
SeosTlsRpcServer_init(
    SeosTlsRpcServer**             self,
    const SeosTlsRpcServer_Config* cfg)
{
    SeosTlsRpcServer* svr;
    seos_err_t err;

    if (NULL == self || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((svr = malloc(sizeof(SeosTlsRpcServer))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = svr;
    memset(svr, 0, sizeof(SeosTlsRpcServer));
    svr->dataport = cfg->dataport;

    // We need an instance of the library for the server to work with
    if ((err = SeosTlsLib_init(&svr->library, &cfg->library)) != SEOS_SUCCESS)
    {
        free(svr);
    }

    return err;
}

seos_err_t
SeosTlsRpcServer_free(
    SeosTlsRpcServer* self)
{
    seos_err_t err;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = SeosTlsLib_free(self->library);
    free(self);

    return err;
}

// RPC functions ---------------------------------------------------------------

seos_err_t
SeosTlsRpcServer_handshake(
    void)
{
    SeosTlsRpcServer* self;

    GET_SELF(self);
    return SeosTlsLib_handshake(self->library);
}

seos_err_t
SeosTlsRpcServer_write(
    size_t                  dataSize)
{
    SeosTlsRpcServer* self;

    GET_SELF(self);
    return SeosTlsLib_write(self->library, self->dataport, dataSize);
}

seos_err_t
SeosTlsRpcServer_read(
    size_t*                 dataSize)
{
    SeosTlsRpcServer* self;

    GET_SELF(self);
    return SeosTlsLib_read(self->library, self->dataport, dataSize);
}

seos_err_t
SeosTlsRpcServer_reset(
    void)
{
    SeosTlsRpcServer* self;

    GET_SELF(self);
    return SeosTlsLib_reset(self->library);
}

#endif /* SEOS_TLS_WITH_RPC_SERVER */