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
derivePolicy(const SeosTls_Config* cfg,
             SeosTls_Policy* policy)
{
    size_t i;

    memset(policy, 0x00, sizeof(SeosTls_Policy));
    policy->dhMinBits  = 9999;
    policy->rsaMinBits = 9999;

#   define MIN(a,b) ((a) < (b) ? (a) : (b))

    // Here we go through the ciphersuites given and derive appropriate security
    // parameters. The result will be the based on the WEAKEST ciphersuite given
    // by the user -- think a moment, this DOES make sense.
    for (i = 0; i < cfg->crypto.cipherSuitesLen; i++)
    {
        switch (cfg->crypto.cipherSuites[i])
        {
        // Careful, this is a FALLTHROUGH!
        case SeosTls_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256:
            policy->dhMinBits   = MIN(policy->dhMinBits,  2048);
        case SeosTls_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            policy->rsaMinBits  = MIN(policy->rsaMinBits, 2048);
            policy->signatureDigests[policy->signatureDigestsLen++] = SeosTls_Digest_SHA256;
            policy->sessionDigests[policy->sessionDigestsLen++]     = SeosTls_Digest_SHA256;
            break;
        default:
            return SEOS_ERROR_NOT_SUPPORTED;
        }
    }

#   undef MIN

    return SEOS_SUCCESS;
}

static seos_err_t
checkSuites(const SeosTls_CipherSuite*  suites,
            const size_t                numSuites)
{
    size_t i;

    if (numSuites < 0 || numSuites > SeosTls_MAX_CIPHERSUITES)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    for (i = 0; i < numSuites; i++)
    {
        switch (suites[i])
        {
        case SeosTls_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case SeosTls_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            break;
        default:
            return SEOS_ERROR_NOT_SUPPORTED;
        }
    }

    return SEOS_SUCCESS;
}

static seos_err_t
validatePolicy(const SeosTls_Config* cfg,
               const SeosTls_Policy* policy)
{
    size_t i;
    bool checkDH, checkRSA;

    if (policy->sessionDigestsLen < 0
        || policy->sessionDigestsLen > SeosTls_MAX_DIGESTS ||
        policy->signatureDigestsLen < 0
        || policy->signatureDigestsLen > SeosTls_MAX_DIGESTS )
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    // Check the session digests and signature digests
    for (i = 0; i < SeosTls_MAX_DIGESTS; i++)
    {
        if (i < policy->sessionDigestsLen)
        {
            switch (policy->sessionDigests[i])
            {
            case SeosTls_Digest_SHA256:
                break;
            default:
                return SEOS_ERROR_NOT_SUPPORTED;
            }
        }
        if (i < policy->signatureDigestsLen)
        {
            switch (policy->signatureDigests[i])
            {
            case SeosTls_Digest_SHA256:
                break;
            default:
                return SEOS_ERROR_NOT_SUPPORTED;
            }
        }
    }

    // We need to validate that the policy chosen does actually work with the
    // crypto library. Only validate those params that are actually relevant
    // for the selected ciphersuites...
    checkDH = false;
    checkRSA = false;
    for (i = 0; i < cfg->crypto.cipherSuitesLen; i++)
    {
        switch (cfg->crypto.cipherSuites[i])
        {
        case SeosTls_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            checkRSA = true;
            break;
        case SeosTls_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256:
            checkRSA = true;
            checkDH  = true;
            break;
        default:
            return SEOS_ERROR_NOT_SUPPORTED;
        }
    }

    if (checkRSA && ((policy->rsaMinBits > (SeosCryptoKey_Size_RSA_MAX * 8)) ||
                     (policy->rsaMinBits < (SeosCryptoKey_Size_RSA_MIN * 8))))
    {
        return SEOS_ERROR_NOT_SUPPORTED;
    }
    if (checkDH && ((policy->dhMinBits > (SeosCryptoKey_Size_DH_MAX * 8)) ||
                    (policy->dhMinBits < (SeosCryptoKey_Size_DH_MIN * 8))))
    {
        return SEOS_ERROR_NOT_SUPPORTED;
    }

    return SEOS_SUCCESS;
}

static void
setCertProfile(const SeosTls_Policy*        policy,
               const SeosTls_CipherSuite*   suites,
               const size_t                 suitesLen,
               mbedtls_x509_crt_profile*    profile)
{
    size_t i;

    memset(profile, 0, sizeof(mbedtls_x509_crt_profile));

    for (i = 0; i < suitesLen; i++)
    {
        switch (suites[i])
        {
        case SeosTls_CipherSuite_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case SeosTls_CipherSuite_DHE_RSA_WITH_AES_128_GCM_SHA256:
            profile->allowed_pks |= MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_RSA);
            break;
        default:
            Debug_LOG_ERROR("Ciphersuite %04x is not supported", suites[i]);
        }
    }

    for (i = 0; i < policy->signatureDigestsLen; i++)
    {
        switch (policy->signatureDigests[i])
        {
        case SeosTls_Digest_SHA256:
            profile->allowed_mds |= MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 );
            break;
        default:
            Debug_LOG_ERROR("Signature digest %02x is not supported",
                            policy->signatureDigests[i]);
        }
    }

    profile->rsa_min_bitlen = policy->rsaMinBits;
}

static seos_err_t
initImpl(SeosTlsCtx* ctx)
{
    int rc;

    // Apply default configuration first, the override parts of it..
    mbedtls_ssl_config_init(&ctx->mbedtls.conf);
    if ((rc = mbedtls_ssl_config_defaults(&ctx->mbedtls.conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_config_defaults() with code 0x%04x", rc);
        goto err0;
    }

    // Which ciphersuites are allowed? This heavily depends on the state of the
    // modified mbedTLS and cannot simply be changed!!
    mbedtls_ssl_conf_ciphersuites(&ctx->mbedtls.conf,
                                  (int*) ctx->cfg.crypto.cipherSuites);

    // Which hashes do we allow for server signatures?
    mbedtls_ssl_conf_sig_hashes(&ctx->mbedtls.conf,
                                (int*) ctx->policy.signatureDigests);

    // Which certs do we accept (hashes, rsa bitlen)
    setCertProfile(&ctx->policy, ctx->cfg.crypto.cipherSuites,
                   ctx->cfg.crypto.cipherSuitesLen, &ctx->mbedtls.certProfile);
    mbedtls_ssl_conf_cert_profile(&ctx->mbedtls.conf, &ctx->mbedtls.certProfile);

    // What is the minimum bitlen we allow for DH-based key exchanges?
    mbedtls_ssl_conf_dhm_min_bitlen(&ctx->mbedtls.conf,
                                    ctx->policy.dhMinBits);

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
        if ((rc = mbedtls_x509_crt_parse(&ctx->mbedtls.cert,
                                         (const unsigned char*)ctx->cfg.crypto.caCert,
                                         strlen(ctx->cfg.crypto.caCert) + 1)) != 0)
        {
            Debug_LOG_ERROR("mbedtls_x509_crt_parse() with code 0x%04x", rc);
            goto err1;
        }
        mbedtls_ssl_conf_ca_chain(&ctx->mbedtls.conf, &ctx->mbedtls.cert, NULL);
        mbedtls_ssl_conf_authmode(&ctx->mbedtls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }

    // Output levels: (0) none, (1) error, (2) + state change, (3) + informational
    mbedtls_debug_set_threshold((ctx->cfg.flags & SeosTls_Flags_DEBUG) ? 3 : 0);

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
SeosTlsApi_init(SeosTlsCtx*              ctx,
                const SeosTls_Config*    cfg,
                const SeosTls_Policy*    policy)
{
    seos_err_t err;

    if (NULL == ctx || NULL == cfg)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (NULL == cfg->crypto.context)
    {
        Debug_LOG_ERROR("Crypto context is NULL");
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (checkSuites(cfg->crypto.cipherSuites,
                         cfg->crypto.cipherSuitesLen) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Invalid selection of ciphersuites or too many ciphersuites given");
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (NULL == cfg->socket.recv || NULL == cfg->socket.send)
    {
        Debug_LOG_ERROR("Socket callbacks for send/recv are not set");
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    else if (!(cfg->flags & SeosTls_Flags_NO_VERIFY) &&
             (strstr(cfg->crypto.caCert, "-----BEGIN CERTIFICATE-----") == NULL ||
              strstr(cfg->crypto.caCert, "-----END CERTIFICATE-----") == NULL) )
    {
        Debug_LOG_ERROR("Presented CA cert is not valid (maybe not PEM encoded?)");
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(ctx, 0, sizeof(SeosTlsCtx));
    memcpy(&ctx->cfg, cfg, sizeof(SeosTls_Config));
    if (NULL == policy)
    {
        // If no policy is given, derive all the policy parameters based on the
        // WEAKEST ciphersuite given by the user.
        derivePolicy(&ctx->cfg, &ctx->policy);
        Debug_LOG_INFO("Derived policy with %i/%i digests and rsaMinBits=%i, dhMinBits=%i",
                       ctx->policy.sessionDigestsLen, ctx->policy.signatureDigestsLen,
                       ctx->policy.rsaMinBits, ctx->policy.dhMinBits);
    }
    else
    {
        memcpy(&ctx->policy, policy, sizeof(SeosTls_Policy));
    }

    if ((err = validatePolicy(&ctx->cfg, &ctx->policy)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Policy is not valid");
        return err;
    }

    // These two need to be zero-terminated so they can be passed to mbedTLS!
    ctx->cfg.crypto.cipherSuites[ctx->cfg.crypto.cipherSuitesLen] = 0;
    ctx->policy.signatureDigests[ctx->policy.signatureDigestsLen] = 0;

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