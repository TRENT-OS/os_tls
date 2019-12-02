/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SeosTls.h"
#include "SeosTlsRpcServer.h"
#include "SeosTlsRpcClient.h"

#include "SeosTlsApi_Impl.h"

seos_err_t
SeosTlsApi_init(SeosTlsApi_Context*         ctx,
                const SeosTlsApi_Config*    cfg)
{
    if (NULL == ctx || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    ctx->mode = cfg->mode;

    switch (cfg->mode)
    {
    case SeosTls_Mode_AS_LIBRARY:
        return SeosTls_init(&ctx->context.library, &cfg->config.library);
    case SeosTls_Mode_AS_RPC_CLIENT:
        return SeosTlsRpcClient_init(&ctx->context.client, &cfg->config.client);
    case SeosTls_Mode_AS_RPC_SERVER:
        return SeosTlsRpcServer_init(&ctx->context.server, &cfg->config.server);
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
SeosTlsApi_free(SeosTlsApi_Context*     ctx)
{
    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (ctx->mode)
    {
    case SeosTls_Mode_AS_LIBRARY:
        return SeosTls_free(&ctx->context.library);
    case SeosTls_Mode_AS_RPC_CLIENT:
        return SeosTlsRpcClient_free(&ctx->context.client);
    case SeosTls_Mode_AS_RPC_SERVER:
        return SeosTlsRpcServer_free(&ctx->context.server);
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
SeosTlsApi_handshake(SeosTlsApi_Context*    ctx)
{
    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (ctx->mode)
    {
    case SeosTls_Mode_AS_LIBRARY:
        return SeosTls_handshake(&ctx->context.library);
    case SeosTls_Mode_AS_RPC_CLIENT:
        return SeosTlsRpcClient_handshake(&ctx->context.client);
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
SeosTlsApi_write(SeosTlsApi_Context*        ctx,
                 const void*                data,
                 const size_t               dataSize)
{
    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (ctx->mode)
    {
    case SeosTls_Mode_AS_LIBRARY:
        return SeosTls_write(&ctx->context.library, data, dataSize);
    case SeosTls_Mode_AS_RPC_CLIENT:
        return SeosTlsRpcClient_write(&ctx->context.client, data, dataSize);
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}

seos_err_t
SeosTlsApi_read(SeosTlsApi_Context*         ctx,
                void*                       data,
                size_t*                     dataSize)
{
    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    switch (ctx->mode)
    {
    case SeosTls_Mode_AS_LIBRARY:
        return SeosTls_read(&ctx->context.library, data, dataSize);
    case SeosTls_Mode_AS_RPC_CLIENT:
        return SeosTlsRpcClient_read(&ctx->context.client, data, dataSize);
    default:
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_ERROR_GENERIC;
}