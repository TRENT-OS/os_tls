/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosTls_Impl.h
 *
 * @brief SEOS TLS context and functions
 *
 */

#pragma once

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "compiler.h"
#include "seos_err.h"

#include <stdbool.h>

typedef int (SeosTls_RecvFunc)(void* ctx, unsigned char* buf, size_t len);
typedef int (SeosTls_SendFunc)(void* ctx, const unsigned char* buf, size_t len);

typedef struct
{
    SeosTls_RecvFunc*   recv;
    SeosTls_SendFunc*   send;
} SeosTls_Callbacks;

typedef struct
{
    bool open;
    struct mbedtls
    {
        mbedtls_ssl_context         ssl;
        mbedtls_ssl_config          conf;
    } mbedtls;
} SeosTlsCtx;

/** @} */
