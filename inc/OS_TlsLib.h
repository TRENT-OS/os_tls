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
    (int)OS_TlsLib_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ==
    (int)MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
Debug_STATIC_ASSERT(
    (int)OS_TlsLib_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ==
    (int)MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
Debug_STATIC_ASSERT(
    (int)OS_TlsLib_DIGEST_NONE ==
    (int)MBEDTLS_MD_NONE);
Debug_STATIC_ASSERT(
    (int)OS_TlsLib_DIGEST_SHA256 ==
    (int)MBEDTLS_MD_SHA256);

// We need to ensure that, because based on the ciphersuites we may add digests
// to the digest arrays down below
Debug_STATIC_ASSERT(OS_TlsLib_MAX_DIGESTS >= OS_TlsLib_MAX_CIPHERSUITES);

typedef struct OS_TlsLib OS_TlsLib_t;

seos_err_t
OS_TlsLib_init(
    OS_TlsLib_t**             self,
    const OS_TlsLib_Config_t* cfg);

seos_err_t
OS_TlsLib_handshake(
    OS_TlsLib_t* self);

seos_err_t
OS_TlsLib_write(
    OS_TlsLib_t* self,
    const void*  data,
    const size_t dataSize);

seos_err_t
OS_TlsLib_read(
    OS_TlsLib_t* self,
    void*        data,
    size_t*      dataSize);

seos_err_t
OS_TlsLib_reset(
    OS_TlsLib_t* self);

seos_err_t
OS_TlsLib_free(
    OS_TlsLib_t* self);