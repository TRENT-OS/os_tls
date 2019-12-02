/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosTlsRpcServer.h"
#include "SeosTls.h"

#include <string.h>

// Private static functions ----------------------------------------------------

// Server functions ------------------------------------------------------------

seos_err_t
SeosTlsRpcServer_init(SeosTlsRpcServer_Context*         ctx,
                      const SeosTlsRpcServer_Config*    cfg)
{
    printf("%s\n", __func__);

    memset(ctx, 0, sizeof(SeosTlsRpcServer_Context));
    ctx->dataport = cfg->dataport;

    // We need an instance of the library for the server to work with
    return SeosTls_init(&ctx->library, &cfg->library);
}

seos_err_t
SeosTlsRpcServer_free(SeosTlsRpcServer_Context* ctx)
{
    printf("%s\n", __func__);

    return SeosTls_free(&ctx->library);
}

// RPC functions ---------------------------------------------------------------

#if defined(COMPILE_AS_RPC_SERVER)

/**
 * The following code will not be built when we are building a LIB (the define
 * is set in the makefile). However, these symbols will be included when we are
 * building the component which builds SeosTlsRpcServer.c again and then links it
 * via Camkes to the RpcClient side.
 */

seos_err_t
SeosTlsRpcServer_handshake(SeosTlsRpcServer_Handle handle)
{
    printf("%s\n", __func__);

    SeosTlsRpcServer_Context* ctx = &handle->context.server;
    if (handle->mode != SeosTls_Mode_AS_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTls_handshake(&ctx->library);
}

seos_err_t
SeosTlsRpcServer_write(SeosTlsRpcServer_Handle      handle,
                       size_t                       dataSize)
{
    printf("%s\n", __func__);

    SeosTlsRpcServer_Context* ctx = &handle->context.server;
    if (handle->mode != SeosTls_Mode_AS_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTls_write(&ctx->library, ctx->dataport, dataSize);
}

seos_err_t
SeosTlsRpcServer_read(SeosTlsRpcServer_Handle       handle,
                      size_t*                       dataSize)
{
    printf("%s\n", __func__);

    SeosTlsRpcServer_Context* ctx = &handle->context.server;
    if (handle->mode != SeosTls_Mode_AS_RPC_SERVER)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return SeosTls_read(&ctx->library, ctx->dataport, dataSize);
}

#endif