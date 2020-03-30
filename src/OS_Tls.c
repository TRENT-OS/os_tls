/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Tls.h"

#include "OS_TlsLib.h"
#include "OS_TlsRpcServer.h"
#include "OS_TlsRpcClient.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct OS_Tls
{
    OS_Tls_Mode_t mode;
    void* context;
};

seos_err_t
OS_Tls_init(
    OS_Tls_Handle_t*       self,
    const OS_Tls_Config_t* cfg)
{
    seos_err_t err;
    OS_Tls_t* api;

    if (NULL == self || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((api = malloc(sizeof(OS_Tls_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(api, 0, sizeof(OS_Tls_t));
    api->mode = cfg->mode;

    switch (cfg->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        err = OS_TlsLib_init((OS_TlsLib_t**) &api->context, &cfg->config.library);
        break;
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_RPC_CLIENT:
        err = OS_TlsRpcClient_init((OS_TlsRpcClient_t**) &api->context,
                                   &cfg->config.client);
        break;
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
#if defined(SEOS_TLS_WITH_RPC_SERVER)
    case OS_Tls_MODE_RPC_SERVER:
        err = OS_TlsRpcServer_init((OS_TlsRpcServer_t**) &api->context,
                                   &cfg->config.server);
        break;
#endif /* SEOS_TLS_WITH_RPC_SERVER */
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    if (SEOS_SUCCESS != err)
    {
        free(api);
    }

    *self = api;

    return err;
}

seos_err_t
OS_Tls_free(
    OS_Tls_Handle_t self)
{
    seos_err_t err;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        err = OS_TlsLib_free(self->context);
        break;
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_RPC_CLIENT:
        err = OS_TlsRpcClient_free(self->context);
        break;
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
#if defined(SEOS_TLS_WITH_RPC_SERVER)
    case OS_Tls_MODE_RPC_SERVER:
        err = OS_TlsRpcServer_free(self->context);
        break;
#endif /* SEOS_TLS_WITH_RPC_SERVER */
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    free(self);

    return err;
}

seos_err_t
OS_Tls_handshake(
    OS_Tls_Handle_t self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return OS_TlsLib_handshake(self->context);
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_RPC_CLIENT:
        return OS_TlsRpcClient_handshake(self->context);
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
OS_Tls_write(
    OS_Tls_Handle_t self,
    const void*     data,
    const size_t    dataSize)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return OS_TlsLib_write(self->context, data, dataSize);
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_RPC_CLIENT:
        return OS_TlsRpcClient_write(self->context, data, dataSize);
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
OS_Tls_read(
    OS_Tls_Handle_t self,
    void*           data,
    size_t*         dataSize)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return OS_TlsLib_read(self->context, data, dataSize);
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_RPC_CLIENT:
        return OS_TlsRpcClient_read(self->context, data, dataSize);
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
OS_Tls_reset(
    OS_Tls_Handle_t self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case OS_Tls_MODE_LIBRARY:
        return OS_TlsLib_reset(self->context);
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case OS_Tls_MODE_RPC_CLIENT:
        return OS_TlsRpcClient_reset(self->context);
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

void*
OS_Tls_getServer(
    OS_Tls_Handle_t self)
{
    return (NULL == self) ? NULL : self->context;
}

OS_Tls_Mode_t
OS_Tls_getMode(
    OS_Tls_Handle_t self)
{
    return (NULL == self) ? OS_Tls_MODE_NONE : self->mode;
}