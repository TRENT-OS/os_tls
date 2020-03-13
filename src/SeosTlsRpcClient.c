/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(SEOS_TLS_WITH_RPC_CLIENT)

#include "SeosTlsRpcClient.h"
#include "SeosTlsRpcServer.h"

#include <string.h>
#include <stdlib.h>

struct SeosTlsRpcClient
{
    SeosTlsRpcServer_Handle handle;
    void* dataport;
};

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
SeosTlsRpcClient_init(
    SeosTlsRpcClient**             self,
    const SeosTlsRpcClient_Config* cfg)
{
    SeosTlsRpcClient* cli;

    if (NULL == self || NULL == cfg || NULL == cfg->dataport || NULL == cfg->handle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((cli = malloc(sizeof(SeosTlsRpcClient))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = cli;
    memset(cli, 0, sizeof(SeosTlsRpcClient));
    cli->handle     = cfg->handle;
    cli->dataport   = cfg->dataport;

    return SEOS_SUCCESS;
}

seos_err_t
SeosTlsRpcClient_free(
    SeosTlsRpcClient* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    free(self);

    return SEOS_SUCCESS;
}

// RPC functions ---------------------------------------------------------------

seos_err_t
SeosTlsRpcClient_handshake(
    SeosTlsRpcClient* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosTlsRpcServer_handshake(self->handle);
}

seos_err_t
SeosTlsRpcClient_write(
    SeosTlsRpcClient* self,
    const void*       data,
    const size_t      dataSize)
{
    if (NULL == self || NULL == data)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > PAGE_SIZE)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(self->dataport, data, dataSize);

    return SeosTlsRpcServer_write(self->handle, dataSize);
}

seos_err_t
SeosTlsRpcClient_read(
    SeosTlsRpcClient* self,
    void*             data,
    size_t*           dataSize)
{
    seos_err_t rc;

    if (NULL == self || NULL == data || NULL == dataSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((rc = SeosTlsRpcServer_read(self->handle, dataSize)) == SEOS_SUCCESS)
    {
        if (*dataSize > PAGE_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        else
        {
            memcpy(data, self->dataport, *dataSize);
        }
    }

    return rc;
}

seos_err_t
SeosTlsRpcClient_reset(
    SeosTlsRpcClient* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosTlsRpcServer_reset(self->handle);
}

#endif /* SEOS_TLS_WITH_RPC_CLIENT */