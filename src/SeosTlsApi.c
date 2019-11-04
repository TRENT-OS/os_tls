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

static void logDebug(void* ctx,
                     int level,
                     const char* file,
                     int line,
                     const char* str)
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(level);

    // we can't call Debug_LOG_DEBUG() because this will print file and line
    // where it is used - which is here. This is quite useless information.
    if (strlen(file) > 16)
    {
        printf("[mbedTLS] ...%s:%04i: %s", file + (strlen(file) - 16), line, str );
    }
    else
    {
        printf("[mbedTLS] %s:%04i: %s", file, line, str );
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
SeosTlsApi_init(SeosTlsCtx*                 tlsCtx,
                SeosCryptoCtx*              cryptoCtx,
                const SeosTls_Callbacks*    cbs,
                void*                       sockCtx)
{
    int rc;
    Debug_ASSERT_SELF(tlsCtx);

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
    if ((rc = mbedtls_ssl_setup(&tlsCtx->mbedtls.ssl, &tlsCtx->mbedtls.conf)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_setup() with code -0x%04x", -rc);
        return SEOS_ERROR_ABORTED;
    }

    mbedtls_ssl_set_bio(&tlsCtx->mbedtls.ssl, sockCtx, cbs->send, cbs->recv, NULL);

    return SEOS_SUCCESS;
}

seos_err_t
SeosTlsApi_handshake(SeosTlsCtx* api)
{
    int rc;

    while (true)
    {
        if ((rc = mbedtls_ssl_handshake(&api->mbedtls.ssl)) == 0)
        {
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
SeosTlsApi_write(SeosTlsCtx*            api,
                 const void*            data,
                 const size_t           dataSize)
{
    return SEOS_SUCCESS;
}

seos_err_t
SeosTlsApi_free(SeosTlsCtx* api)
{
    Debug_ASSERT_SELF(api);

    mbedtls_ssl_free(&api->mbedtls.ssl);
    mbedtls_ssl_config_free(&api->mbedtls.conf);

    return SEOS_SUCCESS;
}

