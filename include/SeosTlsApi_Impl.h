/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosTlsApi_Impl.h
 *
 * @brief SEOS TLS API context and configuration structs
 *
 */

#pragma once

#include "SeosCryptoApi.h"

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ciphersuites.h"

#include "compiler.h"
#include "SeosError.h"

#include <stddef.h>
#include <stdbool.h>

/**
 * Maxmimum size of PEM-encoded CA cert we accept
 */
#define SeosTlsLib_SIZE_CA_CERT_MAX    2048
#define SeosTlsLib_MAX_CIPHERSUITES    8
#define SeosTlsLib_MAX_DIGESTS         SeosTlsLib_MAX_CIPHERSUITES

typedef int (SeosTlsLib_RecvFunc)(void* ctx, unsigned char* buf, size_t len);
typedef int (SeosTlsLib_SendFunc)(void* ctx, const unsigned char* buf,
                                  size_t len);

typedef enum
{
    SeosTlsLib_Flag_NONE          = 0x0000,
    /**
     *  Produce debug output from underlying protocol provider
     */
    SeosTlsLib_Flag_DEBUG         = 0x0001,
    /**
     * Do not attempt to validate server certificate. This is dangerous,
     * so you better know what you are doing
     */
    SeosTlsLib_Flag_NO_VERIFY     = 0x0002
} SeosTlsLib_Flag;

typedef enum
{
    SeosTlsLib_CipherSuite_NONE = 0,
    SeosTlsLib_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256 =
        MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
} SeosTlsLib_CipherSuite;

Debug_STATIC_ASSERT((int)SeosTlsLib_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256
                    == (int)MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
Debug_STATIC_ASSERT((int)
                    SeosTlsLib_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    == (int)MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

typedef enum
{
    SeosTlsLib_Digest_NONE     = MBEDTLS_MD_NONE,
    SeosTlsLib_Digest_SHA256   = MBEDTLS_MD_SHA256,
} SeosTlsLib_Digest;

Debug_STATIC_ASSERT((int)SeosTlsLib_Digest_NONE    == (int)MBEDTLS_MD_NONE);
Debug_STATIC_ASSERT((int)SeosTlsLib_Digest_SHA256  == (int)MBEDTLS_MD_SHA256);

/**
 * For legacy reasons it may be important to override the param/algorithm choices
 * automatically derived from the chosen ciphersuites (where possible).
 */
typedef struct
{
    /**
     * Possibly allow other digests as well (maybe the suite says to use SHA256
     * but for legacy reasons we may want to add SHA1 or so..)
     *
     * Note: We add +1 so the last element can be set to 0 (needed to pass the array
     * directly into mbedTLS)
     */
    SeosTlsLib_Digest   sessionDigests[SeosTlsLib_MAX_DIGESTS + 1];
    size_t              sessionDigestsLen;
    SeosTlsLib_Digest   signatureDigests[SeosTlsLib_MAX_DIGESTS + 1];
    size_t              signatureDigestsLen;
    /**
     * For all asymmetric operations (DH key exchange, RSA signatures, etc.)
     * we can enforce a mimimum level of security by making sure the respective
     * bit lenghts adhere to this minimum. The curve is currently set and can't
     * be changed, so there is no parameter for ECC.
     */
    size_t          rsaMinBits;
    size_t          dhMinBits;
} SeosTlsLib_Policy;

typedef struct
{
    struct
    {
        SeosTlsLib_RecvFunc*    recv;
        SeosTlsLib_SendFunc*    send;
        /**
         * This is a parameter which is passed into every call to send/recv.
         * Typically it would be a socket handle or similar.
         */
        void*                   context;
    } socket;
    struct
    {
        /**
         * Policy can be NULL, then it is set automatically.
         */
        SeosTlsLib_Policy*              policy;
        /**
         * Need an initialized crypto context for SEOS Crypto API
         */
        SeosCryptoCtx*              context;
        /**
         * Here a certificate in PEM encoding (including headers) is passed to
         * the TLS API so it can be used to verify the root of the server's
         * certificate chain.
         */
        char                        caCert[SeosTlsLib_SIZE_CA_CERT_MAX];
        /**
         * For simplicity, a user can just set some ciphersuites and be fine. The hash
         * given in the cipersuites will be ENFORCED for everything (incl. session hash,
         * signature hashes etc.). Similary, the key size of the AES key will be used to
         * determine the minimum asymmetric key lengths automatically, so all parameters
         * and algorithms will be internally consistent (as far as the suite allows it).
         *
         * Note: We add +1 so the last element can be set to 0 (needed to pass the array
         * directly into mbedTLS)
         */
        SeosTlsLib_CipherSuite      cipherSuites[SeosTlsLib_MAX_CIPHERSUITES + 1];
        size_t                      cipherSuitesLen;
    } crypto;
    SeosTlsLib_Flag                flags;
} SeosTlsLib_Config;

// We need to ensure that, because based on the ciphersuites we may add digests
// to the digest arrays down below
Debug_STATIC_ASSERT(SeosTlsLib_MAX_DIGESTS >= SeosTlsLib_MAX_CIPHERSUITES);

typedef struct
{
    bool                            open;
    struct mbedtls
    {
        mbedtls_ssl_context         ssl;
        mbedtls_ssl_config          conf;
        mbedtls_x509_crt            cert;
        mbedtls_x509_crt_profile    certProfile;
    } mbedtls;
    SeosTlsLib_Config               cfg;
    SeosTlsLib_Policy               policy;
} SeosTlsLib_Context;

typedef struct
{
    SeosTlsLib_Config               library;
    void*                           dataport;
}
SeosTlsRpcServer_Config;

typedef struct
{
    SeosTlsLib_Context              library;
    void*                           dataport;
}
SeosTlsRpcServer_Context;

typedef struct SeosTlsApi_Context SeosTlsApi_Context;
typedef SeosTlsApi_Context* SeosTlsRpcServer_Handle;

typedef struct
{
    SeosTlsRpcServer_Handle         handle;
    void*                           dataport;
} SeosTlsRpcClient_Config;

typedef struct
{
    SeosTlsRpcServer_Handle         handle;
    void*                           dataport;
} SeosTlsRpcClient_Context;

typedef enum
{
    /**
     * Use TLS module as library, all calls to the API will internally mapped to
     * be executed locally.
     */
    SeosTlsApi_Mode_AS_LIBRARY     = 0,
    /**
     * Use TLS module as component. This requires a TLS component with a matching
     * RPC interface. Calls to the API will internally be mapped to RPC calls and
     * thus will be executed in the component for better isolation.
     */
    SeosTlsApi_Mode_AS_RPC_SERVER,
    SeosTlsApi_Mode_AS_RPC_CLIENT
} SeosTlsApi_Mode;

struct SeosTlsApi_Context
{
    SeosTlsApi_Mode                     mode;
    union
    {
        SeosTlsLib_Context              library;
        SeosTlsRpcClient_Context        client;
        SeosTlsRpcServer_Context        server;
    } context;
};

typedef struct
{
    SeosTlsApi_Mode                     mode;
    union
    {
        SeosTlsLib_Config               library;
        SeosTlsRpcClient_Config         client;
        SeosTlsRpcServer_Config         server;
    } config;
} SeosTlsApi_Config;

/** @} */