/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosTlsApi_Impl.h
 *
 * @brief SEOS TLS context and functions
 *
 */

#pragma once

#include "mbedtls/ssl.h"

#include "compiler.h"

#include <stdbool.h>

#define SeosTls_SIZE_CA_CERT_MAX    (1UL << 14)
//#define SeosTls_MAX_SUITES          16

typedef int (SeosTls_RecvFunc)(void* ctx, unsigned char* buf, size_t len);
typedef int (SeosTls_SendFunc)(void* ctx, const unsigned char* buf, size_t len);

typedef enum
{
    SeosTls_Flags_NONE          = 0x0000,
    /**
     *  Produce debug output from underlying protocol provider
     */
    SeosTls_Flags_DEBUG         = 0x0001,
    /**
     * Do not attempt to validate server certificate. This is dangerous,
     * so you better know what you are doing
     */
    SeosTls_Flags_NO_VERIFY     = 0x0002
} SeosTls_Flags;

// typedef enum
// {
//     SeosTls_Suite_NONE = 0,
//     SeosTls_Suite_DHE_RSA_WITH_AES_128_GCM_SHA256,
//     SeosTls_Suite_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
// } SeosTls_Suite;

// typedef enum
// {
//     SeosTls_Level_112_BIT,
//     SeosTls_Level_128_BIT,
//     SeosTls_Level_256_BIT,
// } SeosTls_Level;

typedef struct
{
    struct
    {
        SeosTls_RecvFunc*   recv;
        SeosTls_SendFunc*   send;
        void*               context;
    } socket;
    struct
    {
        char                cert[SeosTls_SIZE_CA_CERT_MAX];
    } ca;
    struct
    {
        SeosCryptoCtx*      context;
    } crypto;
    SeosTls_Flags           flags;
} SeosTls_Config;

typedef struct
{
    bool open;
    struct mbedtls
    {
        mbedtls_ssl_context         ssl;
        mbedtls_ssl_config          conf;
        mbedtls_x509_crt            cert;
    } mbedtls;
    SeosTls_Config                  cfg;
} SeosTlsCtx;

/** @} */
