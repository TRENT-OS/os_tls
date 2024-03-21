/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
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
    CHECK_DATAPORT_SET(self->rpc.dataport);
    CHECK_VALUE_NOT_ZERO(OS_Dataport_getSize(self->rpc.dataport));

    // If the requested length exceeds the dataport size, reduce it to the size
    // of the dataport.
    const size_t maxPossibleLen = OS_Dataport_getSize(self->rpc.dataport);

    if (*dataSize > maxPossibleLen)
    {
        *dataSize = maxPossibleLen;
    }

    memcpy(OS_Dataport_getBuf(self->rpc.dataport), data, *dataSize);

    return self->rpc.write(dataSize);
}

OS_Error_t
TlsLibClient_read(
    TlsLibClient_t* self,
    void*           data,
    size_t*         dataSize)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(data);
    CHECK_PTR_NOT_NULL(dataSize);
    CHECK_DATAPORT_SET(self->rpc.dataport);
    CHECK_VALUE_NOT_ZERO(OS_Dataport_getSize(self->rpc.dataport));

    // If the requested length exceeds the dataport size, reduce it to the size
    // of the dataport.
    const size_t maxPossibleLen = OS_Dataport_getSize(self->rpc.dataport);

    if (*dataSize > maxPossibleLen)
    {
        *dataSize = maxPossibleLen;
    }

    OS_Error_t rc = self->rpc.read(dataSize);
    if (rc == OS_SUCCESS)
    {
        memcpy(data, OS_Dataport_getBuf(self->rpc.dataport), *dataSize);
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
