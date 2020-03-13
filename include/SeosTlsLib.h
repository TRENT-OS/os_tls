/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi.h"

#include "LibDebug/Debug.h"

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ciphersuites.h"

// Need to make sure these match the MBEDTLS defines
Debug_STATIC_ASSERT(
    (int)SeosTlsLib_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256 ==
    (int)MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
Debug_STATIC_ASSERT(
    (int)SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ==
    (int)MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
Debug_STATIC_ASSERT(
    (int)SeosTlsLib_Digest_NONE ==
    (int)MBEDTLS_MD_NONE);
Debug_STATIC_ASSERT(
    (int)SeosTlsLib_Digest_SHA256 ==
    (int)MBEDTLS_MD_SHA256);

// We need to ensure that, because based on the ciphersuites we may add digests
// to the digest arrays down below
Debug_STATIC_ASSERT(SeosTlsLib_MAX_DIGESTS >= SeosTlsLib_MAX_CIPHERSUITES);

typedef struct SeosTlsLib SeosTlsLib;

seos_err_t
SeosTlsLib_init(
    SeosTlsLib**             self,
    const SeosTlsLib_Config* cfg);

seos_err_t
SeosTlsLib_handshake(
    SeosTlsLib* self);

seos_err_t
SeosTlsLib_write(
    SeosTlsLib*  self,
    const void*  data,
    const size_t dataSize);

seos_err_t
SeosTlsLib_read(
    SeosTlsLib* self,
    void*       data,
    size_t*     dataSize);

seos_err_t
SeosTlsLib_reset(
    SeosTlsLib* self);

seos_err_t
SeosTlsLib_free(
    SeosTlsLib* self);