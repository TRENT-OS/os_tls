/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "rpc/TlsLibClient.h"

#include <string.h>
#include <stdlib.h>

struct TlsLibClient
{
    if_OS_Tls_t rpc;
};

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

OS_Error_t
TlsLibClient_init(
    TlsLibClient_t**   self,
    const if_OS_Tls_t* rpc)
{
    TlsLibClient_t* cli;

    if (NULL == self || NULL == rpc || OS_Dataport_isUnset(rpc->dataport))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((cli = malloc(sizeof(TlsLibClient_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = cli;

    memset(cli, 0, sizeof(TlsLibClient_t));
    cli->rpc = *rpc;

    return OS_SUCCESS;
}

OS_Error_t
TlsLibClient_free(
    TlsLibClient_t* self)
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
TlsLibClient_handshake(
    TlsLibClient_t* self)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    return self->rpc.handshake();
}

OS_Error_t
TlsLibClient_write(
    TlsLibClient_t* self,
    const void*     data,
    const size_t    dataSize)
{
    if (NULL == self || NULL == data)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > OS_Dataport_getSize(self->rpc.dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), data, dataSize);

    return self->rpc.write(dataSize);
}

OS_Error_t
TlsLibClient_read(
    TlsLibClient_t* self,
    void*           data,
    size_t*         dataSize)
{
    OS_Error_t rc;

    if (NULL == self || NULL == data || NULL == dataSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((rc = self->rpc.read(dataSize)) == OS_SUCCESS)
    {
        if (*dataSize > OS_Dataport_getSize(self->rpc.dataport))
        {
            return OS_ERROR_INSUFFICIENT_SPACE;
        }
        else
        {
            memcpy(data, OS_Dataport_getBuf(self->rpc.dataport), *dataSize);
        }
    }

    return rc;
}

OS_Error_t
TlsLibClient_reset(
    TlsLibClient_t* self)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    return self->rpc.reset();
}