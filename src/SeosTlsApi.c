/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static seos_err_t
initImpl(SeosTlsCtx* ctx)
{
    int rc;

    // Output levels: (0) none, (1) error, (2) + state change, (3) + informational
    mbedtls_debug_set_threshold((ctx->cfg.flags & SeosTls_Flags_DEBUG) ? 3 : 0);

    // Setup config
    mbedtls_ssl_config_init(&ctx->mbedtls.conf);
    if ((rc = mbedtls_ssl_config_defaults(&ctx->mbedtls.conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_config_defaults() with code 0x%04x", rc);
        goto err0;
    }

    // If we have debug, use internal logging function
    mbedtls_ssl_conf_dbg(&ctx->mbedtls.conf, logDebug, NULL);

    // Use SeosCryptoRng for TLS
    mbedtls_ssl_conf_rng(&ctx->mbedtls.conf, getRndBytes, ctx->cfg.crypto.context);

    if (ctx->cfg.flags & SeosTls_Flags_NO_VERIFY)
    {
        // We need to have the option to disable cert verification, even though it
        // is not advisable
        Debug_LOG_INFO("TLS certificate verification is disabled, this is NOT secure!");
        mbedtls_ssl_conf_authmode(&ctx->mbedtls.conf, MBEDTLS_SSL_VERIFY_NONE);
    }
    else
    {
        mbedtls_x509_crt_init(&ctx->mbedtls.cert);
        // We can feed here several PEM-encoded certificates; the function will
        // return the amount of correctly parsed certs..
        if ((rc = mbedtls_x509_crt_parse(&ctx->mbedtls.cert,
                                         (const unsigned char*)ctx->cfg.ca.cert,
                                         strlen(ctx->cfg.ca.cert) + 1)) != 0)
        {
            Debug_LOG_ERROR("mbedtls_x509_crt_parse() with code 0x%04x", rc);
            goto err1;
        }
        mbedtls_ssl_conf_ca_chain(&ctx->mbedtls.conf, &ctx->mbedtls.cert, NULL);
        mbedtls_ssl_conf_authmode(&ctx->mbedtls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }

    mbedtls_ssl_init(&ctx->mbedtls.ssl);

    // Attention: This has to happen before mbedtls_ssl_setup() is called, as
    // the crypto context is already needed during setup so that it can be used
    // in ssl_handshake_params_init() for the initialization of the digests.
    mbedtls_ssl_set_crypto(&ctx->mbedtls.ssl, ctx->cfg.crypto.context);

    // Set the send/recv callbacks to work on the socket context
    mbedtls_ssl_set_bio(&ctx->mbedtls.ssl, ctx->cfg.socket.context,
                        ctx->cfg.socket.send,
                        ctx->cfg.socket.recv, NULL);

    if ((rc = mbedtls_ssl_setup(&ctx->mbedtls.ssl, &ctx->mbedtls.conf)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_setup() with code 0x%04x", rc);
        goto err2;
    }

    return SEOS_SUCCESS;

err2:
    mbedtls_ssl_free(&ctx->mbedtls.ssl);
err1:
    if (!(ctx->cfg.flags & SeosTls_Flags_NO_VERIFY))
    {
        mbedtls_x509_crt_free(&ctx->mbedtls.cert);
    }
err0:
    mbedtls_ssl_config_free(&ctx->mbedtls.conf);

    return SEOS_ERROR_ABORTED;
}

static seos_err_t
freeImpl(SeosTlsCtx* ctx)
{
    mbedtls_ssl_free(&ctx->mbedtls.ssl);
    if (!(ctx->cfg.flags & SeosTls_Flags_NO_VERIFY))
    {
        mbedtls_x509_crt_free(&ctx->mbedtls.cert);
    }
    mbedtls_ssl_config_free(&ctx->mbedtls.conf);

    return SEOS_SUCCESS;
}

static seos_err_t
handshakeImpl(SeosTlsCtx* ctx)
{
    int rc;

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

static seos_err_t
writeImpl(SeosTlsCtx*    ctx,
          const void*    data,
          const size_t   dataSize)
{
    int rc;
    size_t written, to_write, offs;

    to_write = dataSize;
    offs     = 0;
    while (to_write > 0)
    {
        if ((rc = mbedtls_ssl_write(&ctx->mbedtls.ssl, data + offs, to_write)) <= 0)
        {
            Debug_LOG_ERROR("mbedtls_ssl_write() with code 0x%04x", rc);
            return SEOS_ERROR_ABORTED;
        }
        written  = rc;
        // Handle cases where we write only parts
        to_write = to_write - written;
        offs     = offs     + written;
    }

    return SEOS_SUCCESS;
}

static seos_err_t
readImpl(SeosTlsCtx*     ctx,
         void*           data,
         size_t*         dataSize)
{
    int rc;

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

    Debug_LOG_ERROR("mbedtls_ssl_read() with code 0x%04x", rc);

    return SEOS_ERROR_ABORTED;
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosTlsApi_init(SeosTlsCtx*           ctx,
                const SeosTls_Config* cfg)
{
    if (NULL == ctx || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (NULL == cfg->crypto.context)
    {
        Debug_LOG_ERROR("Crypto context is NULL");
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (NULL == cfg->socket.recv || NULL == cfg->socket.send)
    {
        Debug_LOG_ERROR("Socket callbacks for send/recv are not set");
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!(cfg->flags & SeosTls_Flags_NO_VERIFY) &&
             (strstr(cfg->ca.cert, "-----BEGIN CERTIFICATE-----") == NULL ||
              strstr(cfg->ca.cert, "-----END CERTIFICATE-----") == NULL) )
    {
        Debug_LOG_ERROR("Presented CA cert is not valid (maybe not PEM encoded?)");
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(ctx, 0, sizeof(SeosTlsCtx));
    memcpy(&ctx->cfg, cfg, sizeof(SeosTls_Config));

    return initImpl(ctx);
}

seos_err_t
SeosTlsApi_handshake(SeosTlsCtx* ctx)
{
    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (ctx->open)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return handshakeImpl(ctx);
}

seos_err_t
SeosTlsApi_write(SeosTlsCtx*    ctx,
                 const void*    data,
                 const size_t   dataSize)
{
    if (NULL == ctx || NULL == data)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!ctx->open)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return writeImpl(ctx, data, dataSize);
}

seos_err_t
SeosTlsApi_read(SeosTlsCtx*     ctx,
                void*           data,
                size_t*         dataSize)
{
    if (NULL == ctx || NULL == data || NULL == dataSize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!ctx->open)
    {
        return SEOS_ERROR_OPERATION_DENIED;
    }

    return readImpl(ctx, data, dataSize);
}

seos_err_t
SeosTlsApi_free(SeosTlsCtx* ctx)
{
    if (NULL == ctx)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    return freeImpl(ctx);
}