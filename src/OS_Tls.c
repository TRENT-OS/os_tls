/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Tls.h"

#include "lib/TlsLib.h"
#include "rpc/TlsLibServer.h"
#include "rpc/TlsLibClient.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct OS_Tls
{
    OS_Tls_Mode_t mode;
    TlsLib_t* library;
    union
    {
        void* client;
        void* server;
    } rpc;
};

OS_Error_t
OS_Tls_init(
    OS_Tls_Handle_t*       self,
    const OS_Tls_Config_t* cfg)
{
    OS_Error_t err;
    OS_Tls_t* api;

    if (NULL == self || NULL == cfg)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((api = malloc(sizeof(OS_Tls_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(api, 0, sizeof(OS_Tls_t));
    api->mode = cfg->mode;

    if (cfg->mode != OS_Tls_MODE_CLIENT)
    {
        if ((err = TlsLib_init(&api->library, &cfg->library)) != OS_SUCCESS)
        {
            goto err0;
        }
    }

    switch (cfg->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        // Done above.
        break;
#if defined(OS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_CLIENT:
        if ((err = TlsLibClient_init((TlsLibClient_t**) &api->rpc.client,
                                     &cfg->dataport)) != OS_SUCCESS)
        {
            goto err0;
        }
        break;
#endif /* OS_TLS_WITH_RPC_CLIENT */
#if defined(OS_TLS_WITH_RPC_SERVER)
    case OS_Tls_MODE_SERVER:
        if ((err = TlsLibServer_init((TlsLibServer_t**) &api->rpc.server, api->library,
                                     &cfg->dataport)) != OS_SUCCESS)
        {
            goto err0;
        }
        break;
#endif /* OS_TLS_WITH_RPC_SERVER */
    default:
        err = OS_ERROR_NOT_SUPPORTED;
        goto err0;
    }

    * self = api;

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

    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if (self->mode != OS_Tls_MODE_CLIENT)
    {
        if ((err = TlsLib_free(self->library)) != OS_SUCCESS)
        {
            return err;
        }
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        // Nothing to do
        break;
#if defined(OS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_CLIENT:
        err = TlsLibClient_free(self->rpc.client);
        break;
#endif /* OS_TLS_WITH_RPC_CLIENT */
#if defined(OS_TLS_WITH_RPC_SERVER)
    case OS_Tls_MODE_SERVER:
        err = TlsLibServer_free(self->rpc.server);
        break;
#endif /* OS_TLS_WITH_RPC_SERVER */
    default:
        err = OS_ERROR_NOT_SUPPORTED;
    }

    free(self);

    return err;
}

OS_Error_t
OS_Tls_handshake(
    OS_Tls_Handle_t self)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return TlsLib_handshake(self->library);
#if defined(OS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_CLIENT:
        return TlsLibClient_handshake(self->rpc.client);
#endif /* OS_TLS_WITH_RPC_CLIENT */
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    return OS_ERROR_GENERIC;
}

OS_Error_t
OS_Tls_write(
    OS_Tls_Handle_t self,
    const void*     data,
    size_t*         dataSize)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return TlsLib_write(self->library, data, dataSize);
#if defined(OS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_CLIENT:
        return TlsLibClient_write(self->rpc.client, data, dataSize);
#endif /* OS_TLS_WITH_RPC_CLIENT */
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    return OS_ERROR_GENERIC;
}

OS_Error_t
OS_Tls_read(
    OS_Tls_Handle_t self,
    void*           data,
    size_t*         dataSize)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return TlsLib_read(self->library, data, dataSize);
#if defined(OS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_CLIENT:
        return TlsLibClient_read(self->rpc.client, data, dataSize);
#endif /* OS_TLS_WITH_RPC_CLIENT */
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    return OS_ERROR_GENERIC;
}

OS_Error_t
OS_Tls_reset(
    OS_Tls_Handle_t self)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return TlsLib_reset(self->library);
#if defined(OS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_CLIENT:
        return TlsLibClient_reset(self->rpc.client);
#endif /* OS_TLS_WITH_RPC_CLIENT */
    default:
        return OS_ERROR_NOT_SUPPORTED;
    }

    return OS_ERROR_GENERIC;
}

void*
OS_Tls_getServer(
    OS_Tls_Handle_t self)
{
    return (NULL == self) ? NULL : self->rpc.server;
}

OS_Tls_Mode_t
OS_Tls_getMode(
    OS_Tls_Handle_t self)
{
    return (NULL == self) ? OS_Tls_MODE_NONE : self->mode;
}