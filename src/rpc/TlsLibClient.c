/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "rpc/TlsLibClient.h"

#include "lib_macros/Check.h"

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

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(rpc);
    CHECK_DATAPORT_SET(rpc->dataport);

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
    CHECK_PTR_NOT_NULL(self);

    free(self);

    return OS_SUCCESS;
}

// RPC functions ---------------------------------------------------------------

OS_Error_t
TlsLibClient_handshake(
    TlsLibClient_t* self)
{
    CHECK_PTR_NOT_NULL(self);

    return self->rpc.handshake();
}

OS_Error_t
TlsLibClient_write(
    TlsLibClient_t* self,
    const void*     data,
    size_t*         dataSize)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(data);
    CHECK_PTR_NOT_NULL(dataSize);

    CHECK_DATAPORT_SIZE(self->rpc.dataport, *dataSize);

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), data, *dataSize);

    return self->rpc.write(dataSize);
}

OS_Error_t
TlsLibClient_read(
    TlsLibClient_t* self,
    void*           data,
    size_t*         dataSize)
{
    OS_Error_t rc;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(data);
    CHECK_PTR_NOT_NULL(dataSize);

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
    CHECK_PTR_NOT_NULL(self);

    return self->rpc.reset();
}