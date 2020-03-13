/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(SEOS_TLS_WITH_RPC_CLIENT)

#include "SeosTlsRpc_Client.h"
#include "SeosTlsRpc_Server.h"

#include <string.h>
#include <stdlib.h>

struct SeosTlsRpc_Client
{
    void* dataport;
};

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
SeosTlsRpc_Client_init(
    SeosTlsRpc_Client**             self,
    const SeosTlsRpc_Client_Config* cfg)
{
    SeosTlsRpc_Client* cli;

    if (NULL == self || NULL == cfg || NULL == cfg->dataport)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((cli = malloc(sizeof(SeosTlsRpc_Client))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = cli;
    memset(cli, 0, sizeof(SeosTlsRpc_Client));
    cli->dataport   = cfg->dataport;

    return SEOS_SUCCESS;
}

seos_err_t
SeosTlsRpc_Client_free(
    SeosTlsRpc_Client* self)
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
SeosTlsRpc_Client_handshake(
    SeosTlsRpc_Client* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosTlsRpc_Server_handshake();
}

seos_err_t
SeosTlsRpc_Client_write(
    SeosTlsRpc_Client* self,
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

    return SeosTlsRpc_Server_write(dataSize);
}

seos_err_t
SeosTlsRpc_Client_read(
    SeosTlsRpc_Client* self,
    void*              data,
    size_t*            dataSize)
{
    seos_err_t rc;

    if (NULL == self || NULL == data || NULL == dataSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((rc = SeosTlsRpc_Server_read(dataSize)) == SEOS_SUCCESS)
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
SeosTlsRpc_Client_reset(
    SeosTlsRpc_Client* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosTlsRpc_Server_reset();
}

#endif /* SEOS_TLS_WITH_RPC_CLIENT */