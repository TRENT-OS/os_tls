/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Tls.h"

#include "lib/TlsLib.h"

#include "mbedtls/debug.h"
#include "LibDebug/Debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct TlsLib
{
    bool open;
    struct mbedtls
    {
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_x509_crt cert;
        mbedtls_x509_crt_profile certProfile;
    } mbedtls;
    TlsLib_Config_t cfg;
    OS_Tls_Policy_t policy;
};

// Private static functions ----------------------------------------------------

// this is called by mbedTLS to log messages
static void
logDebug(
    void*       ctx,
    int         level,
    const char* file,
    int         line,
    const char* str)
{
    char msg[256];
    UNUSED_VAR(ctx);
    UNUSED_VAR(level);

    if (level < 1 || level > 4)
    {
        return;
    }

    size_t len_file_name = strlen(file);
    const size_t max_len_file = 16;
    bool is_short_file_name = (len_file_name <= max_len_file);

    snprintf(
        msg,
        sizeof(msg),
        "[%s%s:%05i]: %s",
        is_short_file_name ? "" : "...",
        &file[ is_short_file_name ?  0 : len_file_name - max_len_file],
        line,
        str);

    // Translate mbedTLS level to appropriate debug output
    switch (level)
    {
    case 1: // Error
        Debug_LOG_ERROR("%s", msg);
        break;
    case 2: // State change
    case 3: // Informational
        Debug_LOG_INFO("%s", msg);
        break;
    case 4: // Verbose
        Debug_LOG_DEBUG("%s", msg);
        break;
    default:
        // Do nothing
        break;
    }
}

static int
getRndBytes(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    return OS_CryptoRng_getBytes(ctx, 0, (void*) buf,
                                 len) == OS_SUCCESS ? 0 : 1;
}

static inline size_t
getMinOf(
    size_t a,
    size_t b)
{
    return (a < b) ? a : b;
}

static OS_Error_t
derivePolicy(
    const TlsLib_Config_t* cfg,
    OS_Tls_Policy_t*       policy)
{
    memset(policy, 0, sizeof(OS_Tls_Policy_t));
    policy->dhMinBits  = 9999;
    policy->rsaMinBits = 9999;

    // Here we go through the ciphersuites given and derive appropriate security
    // parameters. The result will be the based on the WEAKEST ciphersuite given
    // by the user -- think a moment, this DOES make sense.
    for (size_t i = 0; i < cfg->crypto.cipherSuitesLen; i++)
    {
        switch (cfg->crypto.cipherSuites[i])
        {
        // Careful, this is a FALLTHROUGH!
        case OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
            policy->dhMinBits   = getMinOf(policy->dhMinBits,  2048);
        case OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            policy->rsaMinBits  = getMinOf(policy->rsaMinBits, 2048);
            policy->signatureDigests[policy->signatureDigestsLen++] =
                OS_Tls_DIGEST_SHA256;
            policy->sessionDigests[policy->sessionDigestsLen++]     =
                OS_Tls_DIGEST_SHA256;
            break;
        default:
            return OS_ERROR_NOT_SUPPORTED;
        }
    }

    return OS_SUCCESS;
}

static OS_Error_t
checkSuites(
    const OS_Tls_CipherSuite_t* suites,
    const size_t                numSuites)
{
    size_t i;

    if (numSuites <= 0 || numSuites > OS_Tls_MAX_CIPHERSUITES)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    for (i = 0; i < numSuites; i++)
    {
        switch (suites[i])
        {
        case OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            break;
        default:
            return OS_ERROR_NOT_SUPPORTED;
        }
    }

    return OS_SUCCESS;
}

static OS_Error_t
validatePolicy(
    const TlsLib_Config_t* cfg,
    const OS_Tls_Policy_t* policy)
{
    size_t i;
    bool checkDH, checkRSA;

    if (policy->sessionDigestsLen < 0
        || policy->sessionDigestsLen > OS_Tls_MAX_DIGESTS ||
        policy->signatureDigestsLen < 0
        || policy->signatureDigestsLen > OS_Tls_MAX_DIGESTS )
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Check the session digests and signature digests
    for (i = 0; i < OS_Tls_MAX_DIGESTS; i++)
    {
        if (i < policy->sessionDigestsLen)
        {
            switch (policy->sessionDigests[i])
            {
            case OS_Tls_DIGEST_SHA256:
                break;
            default:
                return OS_ERROR_NOT_SUPPORTED;
            }
        }
        if (i < policy->signatureDigestsLen)
        {
            switch (policy->signatureDigests[i])
            {
            case OS_Tls_DIGEST_SHA256:
                break;
            default:
                return OS_ERROR_NOT_SUPPORTED;
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
        case OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            checkRSA = true;
            break;
        case OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
            checkRSA = true;
            checkDH  = true;
            break;
        default:
            return OS_ERROR_NOT_SUPPORTED;
        }
    }

    if (checkRSA && ((policy->rsaMinBits > (OS_CryptoKey_SIZE_RSA_MAX * 8)) ||
                     (policy->rsaMinBits < (OS_CryptoKey_SIZE_RSA_MIN * 8))))
    {
        return OS_ERROR_NOT_SUPPORTED;
    }
    if (checkDH && ((policy->dhMinBits > (OS_CryptoKey_SIZE_DH_MAX * 8)) ||
                    (policy->dhMinBits < (OS_CryptoKey_SIZE_DH_MIN * 8))))
    {
        return OS_ERROR_NOT_SUPPORTED;
    }

    return OS_SUCCESS;
}

static void
setCertProfile(
    const OS_Tls_Policy_t*      policy,
    const OS_Tls_CipherSuite_t* suites,
    const size_t                suitesLen,
    mbedtls_x509_crt_profile*   profile)
{
    size_t i;

    memset(profile, 0, sizeof(mbedtls_x509_crt_profile));

    for (i = 0; i < suitesLen; i++)
    {
        switch (suites[i])
        {
        case OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256:
            profile->allowed_pks |= MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_RSA);
            break;
        default:
            Debug_LOG_ERROR("Ciphersuite 0x%04x is not supported", suites[i]);
        }
    }

    for (i = 0; i < policy->signatureDigestsLen; i++)
    {
        switch (policy->signatureDigests[i])
        {
        case OS_Tls_DIGEST_SHA256:
            profile->allowed_mds |= MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 );
            break;
        default:
            Debug_LOG_ERROR("Signature digest 0x%02x is not supported",
                            policy->signatureDigests[i]);
        }
    }

    profile->rsa_min_bitlen = policy->rsaMinBits;
}

static OS_Error_t
initImpl(
    TlsLib_t* self)
{
    int rc;

    // Apply default configuration first, the override parts of it..
    mbedtls_ssl_config_init(&self->mbedtls.conf);
    if ((rc = mbedtls_ssl_config_defaults(&self->mbedtls.conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_config_defaults() failed with 0x%04x", rc);
        goto err0;
    }

    // Which ciphersuites are allowed? This heavily depends on the state of the
    // modified mbedTLS and cannot simply be changed!!
    mbedtls_ssl_conf_ciphersuites(&self->mbedtls.conf,
                                  (int*) self->cfg.crypto.cipherSuites);

    // Which hashes do we allow for server signatures?
    mbedtls_ssl_conf_sig_hashes(&self->mbedtls.conf,
                                (int*) self->policy.signatureDigests);

    // Which certs do we accept (hashes, rsa bitlen)
    setCertProfile(&self->policy, self->cfg.crypto.cipherSuites,
                   self->cfg.crypto.cipherSuitesLen, &self->mbedtls.certProfile);
    mbedtls_ssl_conf_cert_profile(&self->mbedtls.conf, &self->mbedtls.certProfile);

    // What is the minimum bitlen we allow for DH-based key exchanges?
    mbedtls_ssl_conf_dhm_min_bitlen(&self->mbedtls.conf,
                                    self->policy.dhMinBits);

    // If we have debug, use internal logging function
    mbedtls_ssl_conf_dbg(&self->mbedtls.conf, logDebug, NULL);

    // Use internal RNG of Crypto API for TLS
    mbedtls_ssl_conf_rng(&self->mbedtls.conf, getRndBytes,
                         (void*) self->cfg.crypto.handle);

    if (self->cfg.flags & OS_Tls_FLAG_NO_VERIFY)
    {
        // We need to have the option to disable cert verification, even though it
        // is not advisable
        Debug_LOG_INFO("TLS certificate verification is disabled, this is NOT secure!");
        mbedtls_ssl_conf_authmode(&self->mbedtls.conf, MBEDTLS_SSL_VERIFY_NONE);
    }
    else
    {
        mbedtls_x509_crt_init(&self->mbedtls.cert);
        if ((rc = mbedtls_x509_crt_parse(&self->mbedtls.cert,
                                         (const unsigned char*)self->cfg.crypto.caCert,
                                         strlen(self->cfg.crypto.caCert) + 1)) != 0)
        {
            Debug_LOG_ERROR("mbedtls_x509_crt_parse() failed with 0x%04x", rc);
            goto err1;
        }
        mbedtls_ssl_conf_ca_chain(&self->mbedtls.conf, &self->mbedtls.cert, NULL);
        mbedtls_ssl_conf_authmode(&self->mbedtls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }

    // Output levels: (0) none, (1) error, (2) + state change, (3) + informational
    mbedtls_debug_set_threshold((self->cfg.flags & OS_Tls_FLAG_DEBUG) ? 3 : 0);

    mbedtls_ssl_init(&self->mbedtls.ssl);

    // Attention: This has to happen before mbedtls_ssl_setup() is called, as
    // the crypto context is already needed during setup so that it can be used
    // in ssl_handshake_params_init() for the initialization of the digests.
    mbedtls_ssl_set_crypto(&self->mbedtls.ssl, self->cfg.crypto.handle);

    // Set the send/recv callbacks to work on the socket context
    mbedtls_ssl_set_bio(&self->mbedtls.ssl, self->cfg.socket.context,
                        self->cfg.socket.send,
                        self->cfg.socket.recv, NULL);

    if ((rc = mbedtls_ssl_setup(&self->mbedtls.ssl, &self->mbedtls.conf)) != 0)
    {
        Debug_LOG_ERROR("mbedtls_ssl_setup() failed with 0x%04x", rc);
        goto err2;
    }

    return OS_SUCCESS;

err2:
    mbedtls_ssl_free(&self->mbedtls.ssl);
err1:
    if (!(self->cfg.flags & OS_Tls_FLAG_NO_VERIFY))
    {
        mbedtls_x509_crt_free(&self->mbedtls.cert);
    }
err0:
    mbedtls_ssl_config_free(&self->mbedtls.conf);

    return OS_ERROR_ABORTED;
}

static OS_Error_t
freeImpl(
    TlsLib_t* self)
{
    mbedtls_ssl_free(&self->mbedtls.ssl);
    if (!(self->cfg.flags & OS_Tls_FLAG_NO_VERIFY))
    {
        mbedtls_x509_crt_free(&self->mbedtls.cert);
    }
    mbedtls_ssl_config_free(&self->mbedtls.conf);

    return OS_SUCCESS;
}

static OS_Error_t
handshakeImpl(
    TlsLib_t* self)
{
    int rc;

    for (;;)
    {
        rc = mbedtls_ssl_handshake(&self->mbedtls.ssl);
        switch (rc)
        {
        case 0:
            return OS_SUCCESS;
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            // The send/recv callbacks would send WANT_READ/WANT_WRITE in case
            // the socket I/O would block (e.g., 0 bytes available on read())
            Debug_LOG_INFO("mbedtls_ssl_handshake() would block");
            return OS_ERROR_WOULD_BLOCK;
        default:
            Debug_LOG_ERROR("mbedtls_ssl_handshake() failed with 0x%04x", rc);
            return OS_ERROR_ABORTED;
        }
    }
}

static OS_Error_t
writeImpl(
    TlsLib_t*   self,
    const void* data,
    size_t*     dataSize)
{
    int rc;
    size_t to_write, offs;

    to_write = *dataSize;
    offs     = 0;

    while (to_write > 0)
    {
        rc = mbedtls_ssl_write(&self->mbedtls.ssl, data + offs, to_write);
        if (rc <= 0)
        {
            switch (rc)
            {
            case 0:
                // Server can send empty messages for randomization purposes,
                // so this is not an error but we may want to notify the user
                // anyways..
                Debug_LOG_INFO("mbedtls_ssl_write() wrote 0 bytes");
                continue;
            case MBEDTLS_ERR_SSL_WANT_WRITE:
                // The write would block for some reason, even after we have done
                // some partial writing. If we should not block ourselves, then
                // return with OS_ERROR_WOULD_BLOCK. Otherwise, keep trying..
                Debug_LOG_INFO("mbedtls_ssl_write() would block");
                return OS_ERROR_WOULD_BLOCK;
            default:
                Debug_LOG_ERROR("mbedtls_ssl_write() failed with 0x%04x", rc);
                return OS_ERROR_ABORTED;
            }
        }
        // Update pointer/len in case of partial writes
        to_write  -= rc;
        offs      += rc;
        // Give back the amount of bytes actually written
        *dataSize  = offs;
    }

    return OS_SUCCESS;
}

static OS_Error_t
readImpl(
    TlsLib_t* self,
    void*     data,
    size_t*   dataSize)
{
    int rc;
    size_t to_read, offs;

    to_read = *dataSize;
    offs    = 0;

    while (to_read > 0)
    {
        rc = mbedtls_ssl_read(&self->mbedtls.ssl, data + offs, to_read);
        if (rc <= 0)
        {
            switch (rc)
            {
            case 0:
                // Server can send empty messages for randomization purposes,
                // so this is not an error but we may want to notify the user
                // anyways..
                Debug_LOG_INFO("mbedtls_ssl_read() read 0 bytes");
                continue;
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                // Server has signaled that the connection will be closed; we
                // count this as success but terminate the SSL session here.
                self->open = false;
                return OS_SUCCESS;
            case MBEDTLS_ERR_SSL_WANT_READ:
                // There were no bytes to read without blocking
                Debug_LOG_INFO("mbedtls_ssl_read() would block");
                return OS_ERROR_WOULD_BLOCK;
            default:
                Debug_LOG_ERROR("mbedtls_ssl_read() failed with 0x%04x", rc);
                return OS_ERROR_ABORTED;
            }
        }
        // Update pointer/len in case of partial read
        to_read  -= rc;
        offs     += rc;
        // Give back amount of bytes actually read
        *dataSize = offs;
    }

    return OS_SUCCESS;
}

static OS_Error_t
resetImpl(
    TlsLib_t* self)
{
    return (mbedtls_ssl_session_reset(&self->mbedtls.ssl) == 0) ?
           OS_SUCCESS : OS_ERROR_ABORTED;
}

// Public functions ------------------------------------------------------------

OS_Error_t
TlsLib_init(
    TlsLib_t**             self,
    const TlsLib_Config_t* cfg)
{
    OS_Error_t err;
    TlsLib_t* lib;

    if (NULL == self || NULL == cfg)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (NULL == cfg->crypto.handle)
    {
        Debug_LOG_ERROR("Crypto context is NULL");
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if ((err = checkSuites(cfg->crypto.cipherSuites,
                                cfg->crypto.cipherSuitesLen)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("Invalid selection of ciphersuites or too many ciphersuites given");
        return err;
    }
    else if (NULL == cfg->socket.recv || NULL == cfg->socket.send)
    {
        Debug_LOG_ERROR("Socket callbacks for send/recv are not set");
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (!(cfg->flags & OS_Tls_FLAG_NO_VERIFY) &&
             (strstr(cfg->crypto.caCert, "-----BEGIN CERTIFICATE-----") == NULL ||
              strstr(cfg->crypto.caCert, "-----END CERTIFICATE-----") == NULL) )
    {
        Debug_LOG_ERROR("Presented CA cert is not valid (maybe not PEM encoded?)");
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((lib = malloc(sizeof(TlsLib_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    *self = lib;
    memset(lib, 0, sizeof(TlsLib_t));
    memcpy(&lib->cfg, cfg, sizeof(TlsLib_Config_t));

    if (NULL == cfg->crypto.policy)
    {
        // If no policy is given, derive all the policy parameters based on the
        // WEAKEST ciphersuite given by the user.
        derivePolicy(&lib->cfg, &lib->policy);
        Debug_LOG_INFO("Derived policy with %zu/%zu digests and rsaMinBits=%zu, dhMinBits=%zu",
                       lib->policy.sessionDigestsLen, lib->policy.signatureDigestsLen,
                       lib->policy.rsaMinBits, lib->policy.dhMinBits);
    }
    else
    {
        lib->policy = *cfg->crypto.policy;
    }

    if ((err = validatePolicy(&lib->cfg, &lib->policy)) == OS_SUCCESS)
    {
        // These two need to be zero-terminated so they can be passed to mbedTLS!
        lib->cfg.crypto.cipherSuites[lib->cfg.crypto.cipherSuitesLen] = 0;
        lib->policy.signatureDigests[lib->policy.signatureDigestsLen] = 0;
        err = initImpl(lib);
    }

    if (OS_SUCCESS != err)
    {
        free(lib);
    }

    return err;
}

OS_Error_t
TlsLib_free(
    TlsLib_t* self)
{
    OS_Error_t err;

    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    err = freeImpl(self);
    free(self);

    return err;
}

OS_Error_t
TlsLib_handshake(
    TlsLib_t* self)
{
    OS_Error_t err;

    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (self->open)
    {
        return OS_ERROR_OPERATION_DENIED;
    }

    err = handshakeImpl(self);
    self->open = (err == OS_SUCCESS);

    return err;
}

OS_Error_t
TlsLib_write(
    TlsLib_t*   self,
    const void* data,
    size_t*     dataSize)
{
    if (NULL == self || NULL == data || NULL == dataSize || 0 == *dataSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (!self->open)
    {
        return OS_ERROR_OPERATION_DENIED;
    }

    return writeImpl(self, data, dataSize);
}

OS_Error_t
TlsLib_read(
    TlsLib_t* self,
    void*     data,
    size_t*   dataSize)
{
    if (NULL == self || NULL == data || NULL == dataSize || 0 == *dataSize)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (!self->open)
    {
        return OS_ERROR_OPERATION_DENIED;
    }

    return readImpl(self, data, dataSize);
}

OS_Error_t
TlsLib_reset(
    TlsLib_t* self)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Regardless of the success of resetImpl() we set the connection to closed,
    // because most likely a big part of the internal data structures will be
    // re-set even in case of error.
    self->open = false;

    return resetImpl(self);
}
