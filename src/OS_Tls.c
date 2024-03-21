/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include "OS_Tls.h"

#include "lib/TlsLib.h"
#include "rpc/TlsLibClient.h"

#include "lib_macros/Check.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct OS_Tls
{
    OS_Tls_Mode_t mode;
    TlsLib_t* library;
    TlsLibClient_t* client;
};

OS_Error_t
OS_Tls_init(
    OS_Tls_Handle_t*       self,
    const OS_Tls_Config_t* cfg)
{
    OS_Error_t err;
    OS_Tls_t* api;

    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(cfg);

    if ((api = malloc(sizeof(OS_Tls_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(api, 0, sizeof(OS_Tls_t));
    api->mode = cfg->mode;

    switch (cfg->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        if ((err = TlsLib_init(&api->library, &cfg->library)) != OS_SUCCESS)
        {
            goto err0;
        }
        break;
    case OS_Tls_MODE_CLIENT:
        if ((err = TlsLibClient_init(&api->client, &cfg->rpc)) != OS_SUCCESS)
        {
            goto err0;
        }
        break;
    default:
        Debug_LOG_ERROR("Mode is invalid");
        err = OS_ERROR_INVALID_PARAMETER;
        goto err0;
    }

    *self = api;

    return OS_SUCCESS;

err0:
    free(api);

    return err;
}

OS_Error_t
OS_Tls_free(
    OS_Tls_Handle_t self)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        err = TlsLib_free(self->library);
        break;
    case OS_Tls_MODE_CLIENT:
        err = TlsLibClient_free(self->client);
        break;
    default:
        Debug_LOG_FATAL("TLS instance is configured in unknown mode!");
        return OS_ERROR_GENERIC;
    }

    free(self);

    return err;
}

OS_Error_t
OS_Tls_handshake(
    OS_Tls_Handle_t self)
{
    CHECK_PTR_NOT_NULL(self);

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return TlsLib_handshake(self->library);
    case OS_Tls_MODE_CLIENT:
        return TlsLibClient_handshake(self->client);
    default:
        Debug_LOG_FATAL("TLS instance is configured in unknown mode!");
        return OS_ERROR_GENERIC;
    }
}

OS_Error_t
OS_Tls_write(
    OS_Tls_Handle_t self,
    const void*     data,
    size_t*         dataSize)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        err = TlsLib_write(self->library, data, dataSize);
        Debug_LOG_TRACE("TlsLib_write, ret: %d, size: %d", err, *dataSize);
        break;
    case OS_Tls_MODE_CLIENT:
        err = TlsLibClient_write(self->client, data, dataSize);
        Debug_LOG_TRACE("TlsLibClient_write, ret: %d, size: %d", err, *dataSize);
        break;
    default:
        Debug_LOG_FATAL("TLS instance is configured in unknown mode!");
        err = OS_ERROR_GENERIC;
    }

    return err;
}

OS_Error_t
OS_Tls_read(
    OS_Tls_Handle_t self,
    void*           data,
    size_t*         dataSize)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        err = TlsLib_read(self->library, data, dataSize);
        Debug_LOG_TRACE("TlsLib_read, ret: %d, size: %d", err, *dataSize);
        break;
    case OS_Tls_MODE_CLIENT:
        err = TlsLibClient_read(self->client, data, dataSize);
        Debug_LOG_TRACE("TlsLibClient_read, ret: %d, size: %d", err, *dataSize);
        break;
    default:
        Debug_LOG_FATAL("TLS instance is configured in unknown mode!");
        err = OS_ERROR_GENERIC;
    }

    return err;
}

OS_Error_t
OS_Tls_reset(
    OS_Tls_Handle_t self)
{
    CHECK_PTR_NOT_NULL(self);

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return TlsLib_reset(self->library);
    case OS_Tls_MODE_CLIENT:
        return TlsLibClient_reset(self->client);
    default:
        Debug_LOG_FATAL("TLS instance is configured in unknown mode!");
        return OS_ERROR_GENERIC;
    }
}

OS_Tls_Mode_t
OS_Tls_getMode(
    OS_Tls_Handle_t self)
{
    return (NULL == self) ? OS_Tls_MODE_NONE : self->mode;
}