/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "SeosTlsApi.h"

#include "SeosTlsLib.h"
#include "SeosTlsRpc_Server.h"
#include "SeosTlsRpc_Client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct SeosTlsApi
{
    SeosTlsApi_Mode mode;
    void* context;
};

seos_err_t
SeosTlsApi_init(
    SeosTlsApiH*             self,
    const SeosTlsApi_Config* cfg)
{
    seos_err_t err;
    SeosTlsApi* api;

    if (NULL == self || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((api = malloc(sizeof(SeosTlsApi))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(api, 0, sizeof(SeosTlsApi));
    api->mode = cfg->mode;

    switch (cfg->mode)
    {
    case SeosTlsApi_Mode_LIBRARY:
        err = SeosTlsLib_init((SeosTlsLib**) &api->context, &cfg->config.library);
        break;
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case SeosTlsApi_Mode_RPC_CLIENT:
        err = SeosTlsRpc_Client_init((SeosTlsRpc_Client**) &api->context,
                                     &cfg->config.client);
        break;
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
#if defined(SEOS_TLS_WITH_RPC_SERVER)
    case SeosTlsApi_Mode_RPC_SERVER:
        err = SeosTlsRpc_Server_init((SeosTlsRpc_Server**) &api->context,
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
SeosTlsApi_free(
    SeosTlsApiH self)
{
    seos_err_t err;

    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case SeosTlsApi_Mode_LIBRARY:
        err = SeosTlsLib_free(self->context);
        break;
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case SeosTlsApi_Mode_RPC_CLIENT:
        err = SeosTlsRpc_Client_free(self->context);
        break;
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
#if defined(SEOS_TLS_WITH_RPC_SERVER)
    case SeosTlsApi_Mode_RPC_SERVER:
        err = SeosTlsRpc_Server_free(self->context);
        break;
#endif /* SEOS_TLS_WITH_RPC_SERVER */
    default:
        err = SEOS_ERROR_NOT_SUPPORTED;
    }

    free(self);

    return err;
}

seos_err_t
SeosTlsApi_handshake(
    SeosTlsApiH self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case SeosTlsApi_Mode_LIBRARY:
        return SeosTlsLib_handshake(self->context);
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case SeosTlsApi_Mode_RPC_CLIENT:
        return SeosTlsRpc_Client_handshake(self->context);
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
SeosTlsApi_write(
    SeosTlsApiH  self,
    const void*  data,
    const size_t dataSize)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case SeosTlsApi_Mode_LIBRARY:
        return SeosTlsLib_write(self->context, data, dataSize);
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case SeosTlsApi_Mode_RPC_CLIENT:
        return SeosTlsRpc_Client_write(self->context, data, dataSize);
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
SeosTlsApi_read(
    SeosTlsApiH self,
    void*       data,
    size_t*     dataSize)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case SeosTlsApi_Mode_LIBRARY:
        return SeosTlsLib_read(self->context, data, dataSize);
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case SeosTlsApi_Mode_RPC_CLIENT:
        return SeosTlsRpc_Client_read(self->context, data, dataSize);
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
SeosTlsApi_reset(
    SeosTlsApiH self)
{
    if (NULL == self)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (self->mode)
    {
    case SeosTlsApi_Mode_LIBRARY:
        return SeosTlsLib_reset(self->context);
#if defined(SEOS_TLS_WITH_RPC_CLIENT)
    case SeosTlsApi_Mode_RPC_CLIENT:
        return SeosTlsRpc_Client_reset(self->context);
#endif /* SEOS_TLS_WITH_RPC_CLIENT */
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

void*
SeosTlsApi_getServer(
    SeosTlsApiH self)
{
    return (NULL == self) ? NULL : self->context;
}

SeosTlsApi_Mode
SeosTlsApi_getMode(
    SeosTlsApiH self)
{
    return (NULL == self) ? SeosTlsApi_Mode_NONE : self->mode;
}