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
    printf("[mbedTLS] %s:%d: %s", file, line, str );
}

// Public functions ------------------------------------------------------------

seos_err_t
SeosTlsApi_init(SeosTlsCtx*                api,
                const SeosTls_Callbacks*   cbs,
                void*                      ctx)
{
    int rc;
    Debug_ASSERT_SELF(api);

    // Setup RNG
    mbedtls_entropy_init(&api->mbedtls.entropy);
    mbedtls_ctr_drbg_init(&api->mbedtls.drbg);
    if ((rc = mbedtls_ctr_drbg_seed(&api->mbedtls.drbg, mbedtls_entropy_func,
                                    &api->mbedtls.entropy, NULL, 0)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ctr_drbg_seed() with code -%d", -rc);
        return SEOS_ERROR_ABORTED;
    }

    // Setup config
    mbedtls_ssl_config_init(&api->mbedtls.conf);
    if ((rc = mbedtls_ssl_config_defaults (&api->mbedtls.conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_config_defaults() with code -%d", -rc);
        return SEOS_ERROR_ABORTED;
    }
    mbedtls_ssl_conf_dbg(&api->mbedtls.conf, logDebug, NULL);
    mbedtls_ssl_conf_rng(&api->mbedtls.conf, mbedtls_ctr_drbg_random,
                         &api->mbedtls.drbg);

    // Start session
    mbedtls_ssl_init(&api->mbedtls.ssl);
    if ((rc = mbedtls_ssl_setup(&api->mbedtls.ssl, &api->mbedtls.conf)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_setup() with code -%d", -rc);
        return SEOS_ERROR_ABORTED;
    }

    mbedtls_ssl_set_bio(&api->mbedtls.ssl, api->nwCtx, api->nw.send, api->nw.recv,
                        NULL);

    return SEOS_SUCCESS;
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
    mbedtls_entropy_free(&api->mbedtls.entropy);
    mbedtls_ctr_drbg_free(&api->mbedtls.drbg);

    return SEOS_SUCCESS;
}

