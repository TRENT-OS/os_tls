/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosTlsRpcClient.h"
#include "SeosTlsRpcServer.h"

#include <string.h>

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
SeosTlsRpcClient_init(SeosTlsRpcClient_Context*         ctx,
                      const SeosTlsRpcClient_Config*    cfg)
{
    printf("%s\n", __func__);

    if (NULL == ctx || NULL == cfg || NULL == cfg->dataport || NULL == cfg->handle)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(ctx, 0, sizeof(SeosTlsRpcClient_Context));
    ctx->handle     = cfg->handle;
    ctx->dataport   = cfg->dataport;

    return SEOS_SUCCESS;
}

seos_err_t
SeosTlsRpcClient_free(SeosTlsRpcClient_Context*         ctx)
{
    printf("%s\n", __func__);

    UNUSED_VAR(ctx);

    return SEOS_ERROR_NOT_SUPPORTED;
}

// RPC functions ---------------------------------------------------------------

seos_err_t
SeosTlsRpcClient_handshake(SeosTlsRpcClient_Context*    ctx)
{
    printf("%s\n", __func__);

    return SeosTlsRpcServer_handshake(ctx->handle);
}

seos_err_t
SeosTlsRpcClient_write(SeosTlsRpcClient_Context*    ctx,
                       const void*                  data,
                       const size_t                 dataSize)
{
    printf("%s\n", __func__);

    if (NULL == ctx || NULL == data)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (dataSize > PAGE_SIZE)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    memcpy(ctx->dataport, data, dataSize);

    return SeosTlsRpcServer_write(ctx->handle, dataSize);
}

seos_err_t
SeosTlsRpcClient_read(SeosTlsRpcClient_Context* ctx,
                      void*                     data,
                      size_t*                   dataSize)
{
    printf("%s\n", __func__);

    seos_err_t rc;

    if (NULL == ctx || NULL == data || NULL == dataSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((rc = SeosTlsRpcServer_read(ctx->handle, dataSize)) == SEOS_SUCCESS)
    {
        if (*dataSize > PAGE_SIZE)
        {
            return SEOS_ERROR_INSUFFICIENT_SPACE;
        }
        else
        {
            memcpy(data, ctx->dataport, *dataSize);
        }
    }

    return rc;
}