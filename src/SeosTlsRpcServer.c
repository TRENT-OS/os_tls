/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#if defined(SEOS_TLS_WITH_RPC_SERVER)

#include "SeosTlsRpcServer.h"
#include "SeosTlsLib.h"

#include "LibDebug/Debug.h"

#include <string.h>

// Private static functions ----------------------------------------------------

// Server functions ------------------------------------------------------------

seos_err_t
SeosTlsRpcServer_init(SeosTlsRpcServer_Context*         ctx,
                      const SeosTlsRpcServer_Config*    cfg)
{
    if (NULL == ctx || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(ctx, 0, sizeof(SeosTlsRpcServer_Context));
    ctx->dataport = cfg->dataport;

    // We need an instance of the library for the server to work with
    return SeosTlsLib_init(&ctx->library, &cfg->library);
}

seos_err_t
SeosTlsRpcServer_free(SeosTlsRpcServer_Context* ctx)
{
    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return SeosTlsLib_free(&ctx->library);
}

// RPC functions ---------------------------------------------------------------

/**
 * The following code will not be built when we are building a LIB (the define
 * is set in the makefile). However, these symbols will be included when we are
 * building the component which builds SeosTlsRpcServer.c again and then links it
 * via Camkes to the RpcClient side.
 */

seos_err_t
SeosTlsRpcServer_handshake(SeosTlsRpcServer_Handle handle)
{
    SeosTlsRpcServer_Context* ctx = &handle->context.server;
    if (handle->mode != SeosTlsApi_Mode_AS_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTlsLib_handshake(&ctx->library);
}

seos_err_t
SeosTlsRpcServer_write(SeosTlsRpcServer_Handle      handle,
                       size_t                       dataSize)
{
    SeosTlsRpcServer_Context* ctx = &handle->context.server;
    if (handle->mode != SeosTlsApi_Mode_AS_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTlsLib_write(&ctx->library, ctx->dataport, dataSize);
}

seos_err_t
SeosTlsRpcServer_read(SeosTlsRpcServer_Handle       handle,
                      size_t*                       dataSize)
{
    SeosTlsRpcServer_Context* ctx = &handle->context.server;
    if (handle->mode != SeosTlsApi_Mode_AS_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTlsLib_read(&ctx->library, ctx->dataport, dataSize);
}

#endif /* SEOS_TLS_WITH_RPC_SERVER */