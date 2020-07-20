/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#if defined(OS_TLS_WITH_RPC_CLIENT)

#include "rpc/TlsLibClient.h"
#include "rpc/TlsLibServer.h"

#include <string.h>
#include <stdlib.h>

struct TlsLibClient
{
    OS_Dataport_t dataport;
};

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

OS_Error_t
TlsLibClient_init(
    TlsLibClient_t**     self,
    const OS_Dataport_t* dataport)
{
    TlsLibClient_t* cli;

    if (NULL == self || NULL == dataport || OS_Dataport_isUnset(*dataport))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((cli = malloc(sizeof(TlsLibClient_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = cli;

    memset(cli, 0, sizeof(TlsLibClient_t));
    cli->dataport = *dataport;

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

    return tls_rpc_handshake();
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
    else if (dataSize > OS_Dataport_getSize(self->dataport))
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(OS_Dataport_getBuf(self->dataport), data, dataSize);

    return tls_rpc_write(dataSize);
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

    if ((rc = tls_rpc_read(dataSize)) == OS_SUCCESS)
    {
        if (*dataSize > OS_Dataport_getSize(self->dataport))
        {
            return OS_ERROR_INSUFFICIENT_SPACE;
        }
        else
        {
            memcpy(data, OS_Dataport_getBuf(self->dataport), *dataSize);
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

    return tls_rpc_reset();
}

#endif /* OS_TLS_WITH_RPC_CLIENT */