/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Tls.h"

#include "LibDebug/Debug.h"

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ciphersuites.h"

// Need to make sure these match the MBEDTLS defines
Debug_STATIC_ASSERT(
    (int)OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ==
    (int)MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
Debug_STATIC_ASSERT(
    (int)OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ==
    (int)MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
Debug_STATIC_ASSERT(
    (int)OS_Tls_DIGEST_NONE ==
    (int)MBEDTLS_MD_NONE);
Debug_STATIC_ASSERT(
    (int)OS_Tls_DIGEST_SHA256 ==
    (int)MBEDTLS_MD_SHA256);

// We need to ensure that, because based on the ciphersuites we may add digests
// to the digest arrays down below
Debug_STATIC_ASSERT(OS_Tls_MAX_DIGESTS >= OS_Tls_MAX_CIPHERSUITES);

typedef struct TlsLib TlsLib_t;

OS_Error_t
TlsLib_init(
    TlsLib_t**             self,
    const TlsLib_Config_t* cfg);

OS_Error_t
TlsLib_handshake(
    TlsLib_t* self);

OS_Error_t
TlsLib_write(
    TlsLib_t*   self,
    const void* data,
    size_t*     dataSize);

OS_Error_t
TlsLib_read(
    TlsLib_t* self,
    void*     data,
    size_t*   dataSize);

OS_Error_t
TlsLib_reset(
    TlsLib_t* self);

OS_Error_t
TlsLib_free(
    TlsLib_t* self);