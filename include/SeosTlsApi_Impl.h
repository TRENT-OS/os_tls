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
#define SeosTls_SIZE_CA_CERT_MAX    2048
#define SeosTls_MAX_CIPHERSUITES    8
#define SeosTls_MAX_DIGESTS         SeosTls_MAX_CIPHERSUITES

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

typedef enum
{
    SeosTls_CipherSuite_NONE                              = 0,
    SeosTls_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256   = MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    SeosTls_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
} SeosTls_CipherSuite;

Debug_STATIC_ASSERT((int)SeosTls_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256
                    == (int)MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
Debug_STATIC_ASSERT((int)SeosTls_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    == (int)MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

typedef enum
{
    SeosTls_Digest_NONE     = MBEDTLS_MD_NONE,
    SeosTls_Digest_SHA256   = MBEDTLS_MD_SHA256,
} SeosTls_Digest;

Debug_STATIC_ASSERT((int)SeosTls_Digest_NONE    == (int)MBEDTLS_MD_NONE);
Debug_STATIC_ASSERT((int)SeosTls_Digest_SHA256  == (int)MBEDTLS_MD_SHA256);

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
    SeosTls_Digest   sessionDigests[SeosTls_MAX_DIGESTS + 1];
    size_t           sessionDigestsLen;
    SeosTls_Digest   signatureDigests[SeosTls_MAX_DIGESTS + 1];
    size_t           signatureDigestsLen;
    /**
     * For all asymmetric operations (DH key exchange, RSA signatures, etc.)
     * we can enforce a mimimum level of security by making sure the respective
     * bit lenghts adhere to this minimum. The curve is currently set and can't
     * be changed, so there is no parameter for ECC.
     */
    size_t          rsaMinBits;
    size_t          dhMinBits;
} SeosTls_Policy;

typedef struct
{
    struct
    {
        SeosTls_RecvFunc*   recv;
        SeosTls_SendFunc*   send;
        /**
         * This is a parameter which is passed into every call to send/recv.
         * Typically it would be a socket handle or similar.
         */
        void*               context;
    } socket;
    struct
    {
        /**
         * Need an initialized crypto context for SEOS Crypto API
         */
        SeosCryptoCtx*          context;
        /**
         * Here a certificate in PEM encoding (including headers) is passed to
         * the TLS API so it can be used to verify the root of the server's
         * certificate chain.
         */
        char                    caCert[SeosTls_SIZE_CA_CERT_MAX];
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
        SeosTls_CipherSuite     cipherSuites[SeosTls_MAX_CIPHERSUITES + 1];
        size_t                  cipherSuitesLen;
    } crypto;
    SeosTls_Flags               flags;
    /**
     * Policy can be NULL, then it is set automatically.
     */
    SeosTls_Policy*             policy;
} SeosTls_Config;

// We need to ensure that, because based on the ciphersuites we may add digests
// to the digest arrays down below
Debug_STATIC_ASSERT(SeosTls_MAX_DIGESTS >= SeosTls_MAX_CIPHERSUITES);

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
    SeosTls_Config                  cfg;
    SeosTls_Policy                  policy;
} SeosTls_Context;

typedef struct
{
    SeosTls_Config              library;
    void*                       dataport;
}
SeosTlsRpcServer_Config;

typedef struct
{
    SeosTls_Context             library;
    void*                       dataport;
}
SeosTlsRpcServer_Context;

typedef struct SeosTlsApi_Context SeosTlsApi_Context;
typedef SeosTlsApi_Context* SeosTlsRpcServer_Handle;

typedef struct
{
    SeosTlsRpcServer_Handle     handle;
    void*                       dataport;
} SeosTlsRpcClient_Config;

typedef struct
{
    SeosTlsRpcServer_Handle     handle;
    void*                       dataport;
} SeosTlsRpcClient_Context;

typedef enum
{
    /**
     * Use TLS module as library, all calls to the API will internally mapped to
     * be executed locally.
     */
    SeosTls_Mode_AS_LIBRARY     = 0,
    /**
     * Use TLS module as component. This requires a TLS component with a matching
     * RPC interface. Calls to the API will internally be mapped to RPC calls and
     * thus will be executed in the component for better isolation.
     */
    SeosTls_Mode_AS_RPC_SERVER,
    SeosTls_Mode_AS_RPC_CLIENT
} SeosTls_Mode;

struct SeosTlsApi_Context
{
    SeosTls_Mode                    mode;
    union
    {
        SeosTls_Context             library;
        SeosTlsRpcClient_Context    client;
        SeosTlsRpcServer_Context    server;
    } context;
};

typedef struct
{
    SeosTls_Mode                    mode;
    union
    {
        SeosTls_Config              library;
        SeosTlsRpcClient_Config     client;
        SeosTlsRpcServer_Config     server;
    } config;
} SeosTlsApi_Config;

/** @} */