/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "seos_err.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

#include "SeosCryptoApi.h"

#include "SeosTlsApi.h"
#include "SeosTlsApi_Impl.h"

#include "LibDebug/Debug.h"

// Private static functions ----------------------------------------------------

static void logDebug(void*          ctx,
                     int            level,
                     const char*    file,
                     int            line,
                     const char*    str)
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(level);

    // we can't call Debug_LOG_DEBUG() because this will print file and line
    // where it is used - which is here. This is quite useless information.
    if (strlen(file) > 16)
    {
        printf("[...%s:%05i]: %s", file + (strlen(file) - 16), line, str);
    }
    else
    {
        printf("[%s:%05i]: %s", file, line, str);
    }
}

static int getRndBytes(void*            ctx,
                       unsigned char*   buf,
                       size_t           len)
{
    return SeosCryptoApi_rngGetBytes(ctx, 0, (void*) buf,
                                     len) == SEOS_SUCCESS ? 0 : 1;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosTlsApi_init(SeosTlsCtx*                tlsCtx,
                SeosCryptoCtx*             cryptoCtx,
                const SeosTls_Callbacks*   sockFuncs,
                void*                      sockCtx)
{
    int rc;

    if (NULL == tlsCtx || NULL == cryptoCtx || NULL == sockFuncs)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(tlsCtx, 0, sizeof(SeosTlsCtx));

    // Set to the max
    mbedtls_debug_set_threshold(100);

    // Setup config
    mbedtls_ssl_config_init(&tlsCtx->mbedtls.conf);
    if ((rc = mbedtls_ssl_config_defaults(&tlsCtx->mbedtls.conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_config_defaults() with code -0x%04x", -rc);
        return SEOS_ERROR_ABORTED;
    }
    mbedtls_ssl_conf_dbg(&tlsCtx->mbedtls.conf, logDebug, NULL);
    mbedtls_ssl_conf_rng(&tlsCtx->mbedtls.conf, getRndBytes, cryptoCtx);

    // -------------------------------------------------------------------------
    // Todo: This should not stay in production code!!!
    mbedtls_ssl_conf_authmode(&tlsCtx->mbedtls.conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    // -------------------------------------------------------------------------

    // Start session
    mbedtls_ssl_init(&tlsCtx->mbedtls.ssl);

    // Added to mbedTLS, to pass down the crypto context into the SSL context;
    //
    // !!
    // Attention: This has to happen before mbedtls_ssl_setup() is called, as
    // the crypto context is already needed during setup so that it can be used
    // in ssl_handshake_params_init() for the initialization of the digests.
    // !!
    mbedtls_ssl_set_crypto(&tlsCtx->mbedtls.ssl, cryptoCtx);

    // Set the send/recv callbacks to work on the socket context
    mbedtls_ssl_set_bio(&tlsCtx->mbedtls.ssl, sockCtx, sockFuncs->send,
                        sockFuncs->recv, NULL);

    if ((rc = mbedtls_ssl_setup(&tlsCtx->mbedtls.ssl, &tlsCtx->mbedtls.conf)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_setup() with code -0x%04x", -rc);
        return SEOS_ERROR_ABORTED;
    }

    return SEOS_SUCCESS;
}

seos_err_t
SeosTlsApi_handshake(SeosTlsCtx* ctx)
{
    int rc;

    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (ctx->open)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    while (true)
    {
        if ((rc = mbedtls_ssl_handshake(&ctx->mbedtls.ssl)) == 0)
        {
            // Handshake worked, so we can now proceed using the context with
            // write() and read() functionality...
            ctx->open = true;
            return SEOS_SUCCESS;
        }
        else if ((rc == MBEDTLS_ERR_SSL_WANT_READ) ||
                 (rc == MBEDTLS_ERR_SSL_WANT_WRITE) )
        {
            // mbedTLS required looping over mbedtls_ssl_handshake() for the handshake.
            // This leave more control for the calling application, but since we don't
            // need such detail at the moment, it's wrapped in this function
            continue;
        }
        else
        {
            Debug_LOG_ERROR("mbedtls_ssl_handshake() with code -0x%04x", -rc);
            return SEOS_ERROR_ABORTED;
        }
    }
}

seos_err_t
SeosTlsApi_write(SeosTlsCtx*    ctx,
                 const void*    data,
                 const size_t   dataSize)
{
    int written, to_write, offs;

    if (NULL == ctx || NULL == data)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!ctx->open)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    to_write = dataSize;
    offs     = 0;

    while (to_write > 0)
    {
        if ((written = mbedtls_ssl_write(&ctx->mbedtls.ssl, data + offs,
                                         to_write)) <= 0)
        {
            Debug_LOG_ERROR("mbedtls_ssl_write() with code -0x%04x", -written);
            return SEOS_ERROR_ABORTED;
        }
        // Handle cases where we write only parts
        to_write = to_write - written;
        offs     = offs     + written;
    }

    return SEOS_SUCCESS;
}

seos_err_t
SeosTlsApi_read(SeosTlsCtx*     ctx,
                void*           data,
                size_t*         dataSize)
{
    int rc;

    if (NULL == ctx || NULL == data || NULL == dataSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!ctx->open)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    rc = mbedtls_ssl_read(&ctx->mbedtls.ssl, data, *dataSize);
    if (rc > 0)
    {
        // We got some data
        *dataSize = rc;
        return SEOS_SUCCESS;
    }

    switch (rc)
    {
    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        // Server has signaled that the connection will be closed; so we know
        // that there will be no more data
        *dataSize = 0;
        ctx->open = false;
        return SEOS_SUCCESS;
    }

    Debug_LOG_ERROR("mbedtls_ssl_read() with code -0x%04x", -rc);

    return SEOS_ERROR_ABORTED;
}

seos_err_t
SeosTlsApi_free(SeosTlsCtx* ctx)
{
    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    mbedtls_ssl_free(&ctx->mbedtls.ssl);
    mbedtls_ssl_config_free(&ctx->mbedtls.conf);

    return SEOS_SUCCESS;
}

