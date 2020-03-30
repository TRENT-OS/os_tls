/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(SEOS_TLS_WITH_RPC_CLIENT)

#include "OS_TlsRpcClient.h"
#include "OS_TlsRpcServer.h"

#include <string.h>
#include <stdlib.h>

struct OS_TlsRpcClient
{
    void* dataport;
};

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
OS_TlsRpcClient_init(
    OS_TlsRpcClient_t**             self,
    const OS_TlsRpcClient_Config_t* cfg)
{
    OS_TlsRpcClient_t* cli;

    if (NULL == self || NULL == cfg || NULL == cfg->dataport)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((cli = malloc(sizeof(OS_TlsRpcClient_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = cli;
    memset(cli, 0, sizeof(OS_TlsRpcClient_t));
    cli->dataport   = cfg->dataport;

    return SEOS_SUCCESS;
}

seos_err_t
OS_TlsRpcClient_free(
    OS_TlsRpcClient_t* self)
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
OS_TlsRpcClient_handshake(
    OS_TlsRpcClient_t* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return OS_TlsRpcServer_handshake();
}

seos_err_t
OS_TlsRpcClient_write(
    OS_TlsRpcClient_t* self,
    const void*        data,
    const size_t       dataSize)
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

    return OS_TlsRpcServer_write(dataSize);
}

seos_err_t
OS_TlsRpcClient_read(
    OS_TlsRpcClient_t* self,
    void*              data,
    size_t*            dataSize)
{
    seos_err_t rc;

    if (NULL == self || NULL == data || NULL == dataSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((rc = OS_TlsRpcServer_read(dataSize)) == SEOS_SUCCESS)
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
OS_TlsRpcClient_reset(
    OS_TlsRpcClient_t* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return OS_TlsRpcServer_reset();
}

#endif /* SEOS_TLS_WITH_RPC_CLIENT */