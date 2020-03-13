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

// Private static functions ----------------------------------------------------

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
    SeosTlsRpcServer_Handle handle)
{
    SeosTlsRpcServer* self = handle->context;
    if (handle->mode != SeosTlsApi_Mode_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTlsLib_handshake(self->library);
}

seos_err_t
SeosTlsRpcServer_write(
    SeosTlsRpcServer_Handle handle,
    size_t                  dataSize)
{
    SeosTlsRpcServer* self = handle->context;
    if (handle->mode != SeosTlsApi_Mode_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTlsLib_write(self->library, self->dataport, dataSize);
}

seos_err_t
SeosTlsRpcServer_read(
    SeosTlsRpcServer_Handle handle,
    size_t*                 dataSize)
{
    SeosTlsRpcServer* self = handle->context;
    if (handle->mode != SeosTlsApi_Mode_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTlsLib_read(self->library, self->dataport, dataSize);
}

seos_err_t
SeosTlsRpcServer_reset(
    SeosTlsRpcServer_Handle handle)
{
    SeosTlsRpcServer* self = handle->context;
    if (handle->mode != SeosTlsApi_Mode_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTlsLib_reset(self->library);
}

#endif /* SEOS_TLS_WITH_RPC_SERVER */