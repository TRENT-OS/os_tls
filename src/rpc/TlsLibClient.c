/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(SEOS_TLS_WITH_RPC_CLIENT)

#include "rpc/TlsLibClient.h"
#include "rpc/TlsLibServer.h"

#include <string.h>
#include <stdlib.h>

struct TlsLibClient
{
    void* dataport;
};

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
TlsLibClient_init(
    TlsLibClient_t**             self,
    const TlsLibClient_Config_t* cfg)
{
    TlsLibClient_t* cli;

    if (NULL == self || NULL == cfg || NULL == cfg->dataport)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((cli = malloc(sizeof(TlsLibClient_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = cli;
    memset(cli, 0, sizeof(TlsLibClient_t));
    cli->dataport   = cfg->dataport;

    return SEOS_SUCCESS;
}

seos_err_t
TlsLibClient_free(
    TlsLibClient_t* self)
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
TlsLibClient_handshake(
    TlsLibClient_t* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return TlsLibServer_handshake();
}

seos_err_t
TlsLibClient_write(
    TlsLibClient_t* self,
    const void*     data,
    const size_t    dataSize)
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

    return TlsLibServer_write(dataSize);
}

seos_err_t
TlsLibClient_read(
    TlsLibClient_t* self,
    void*           data,
    size_t*         dataSize)
{
    seos_err_t rc;

    if (NULL == self || NULL == data || NULL == dataSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((rc = TlsLibServer_read(dataSize)) == SEOS_SUCCESS)
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
TlsLibClient_reset(
    TlsLibClient_t* self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return TlsLibServer_reset();
}

#endif /* SEOS_TLS_WITH_RPC_CLIENT */