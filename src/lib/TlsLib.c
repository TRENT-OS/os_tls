/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "OS_Dataport.h"
#include "OS_Socket.h"
#include "OS_Tls.h"

#include "lib/TlsLib.h"

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "lib_debug/Debug.h"
#include "lib_macros/Check.h"

#include "lib_compiler/compiler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sel4/sel4.h>

#if defined(MBEDTLS_SSL_CLI_C) && defined(MBEDTLS_SSL_SRV_C)
#error "Used 3rdparty_mbedtls_* library shall not set client AND server."
#endif

#if !defined(MBEDTLS_SSL_CLI_C) && !defined(MBEDTLS_SSL_SRV_C)
#error "Used 3rdparty_mbedtls_* library shall set either client OR server."
#endif

struct TlsLib
{
    bool open;
    struct mbedtls
    {
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_x509_crt_profile certProfile;
        mbedtls_x509_crt caCerts;
        mbedtls_x509_crt ownCert;
        mbedtls_pk_context privateKey;

        int cipherSuites[__OS_Tls_CIPHERSUITE_MAX];
        int sigHashes[__OS_Tls_DIGEST_MAX];

        unsigned char* caCertsBuf;
        size_t caCertsBufSize;
        unsigned char* ownCertBuf;
        size_t ownCertBufSize;
        unsigned char* privateKeyBuf;
        size_t privateKeyBufSize;
    } mbedtls;
    TlsLib_Config_t cfg;
    OS_Tls_Policy_t policy;
};

#define MIN_BITS_UNLIMITED ((size_t) -1)

// Macro to translate mbedTLS errors into readable strings.
#define DEBUG_LOG_ERROR_MBEDTLS(_fn_, _ret_) do { \
    char msg[256] = {0}; \
    mbedtls_strerror(_ret_, msg, sizeof(msg)); \
    Debug_LOG_ERROR("%s() failed with '%s' (rc=%i)", _fn_, msg, _ret_); \
} while(0)

// Private static functions ----------------------------------------------------

// This function is called by mbedTLS to log messages.
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

    // Replace '\n' in mbedtls string with '\0' because otherwise it would
    // result in extra empty lines because Debug_LOG_XXX adds another '\n'.
    size_t msg_len = strlen(msg);
    if (msg_len > 0 && msg[msg_len - 1] == '\n')
    {
        msg[msg_len - 1] = '\0';
    }

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

static void
derivePolicy(
    const TlsLib_Config_t* cfg,
    OS_Tls_Policy_t*       policy)
{
    static const OS_Tls_Policy_t policies[__OS_Tls_CIPHERSUITE_MAX] =
    {
        [OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256] = {
            .handshakeDigests = OS_Tls_DIGEST_FLAGS(OS_Tls_DIGEST_SHA256),
            .certDigests      = OS_Tls_DIGEST_FLAGS(OS_Tls_DIGEST_SHA256),
            .rsaMinBits       = 2048,
            .dhMinBits        = 2048,
        },
        [OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256] = {
            .handshakeDigests = OS_Tls_DIGEST_FLAGS(OS_Tls_DIGEST_SHA256),
            .certDigests      = OS_Tls_DIGEST_FLAGS(OS_Tls_DIGEST_SHA256),
            .rsaMinBits       = 2048,
            .dhMinBits        = MIN_BITS_UNLIMITED,
        },
    };

    memset(policy, 0, sizeof(OS_Tls_Policy_t));
    policy->dhMinBits  = MIN_BITS_UNLIMITED;
    policy->rsaMinBits = MIN_BITS_UNLIMITED;

    // Here we go through the given ciphersuites and derive appropriate security
    // parameters. The result will be based on the WEAKEST ciphersuite given by
    // the user - think a moment, this DOES make sense.
    for (size_t i = 0; i < __OS_Tls_CIPHERSUITE_MAX; i++)
    {
        if (cfg->crypto.cipherSuites & OS_Tls_CIPHERSUITE_FLAGS(i))
        {
            policy->dhMinBits  = getMinOf(policy->dhMinBits, policies[i].dhMinBits);
            policy->rsaMinBits = getMinOf(policy->rsaMinBits, policies[i].rsaMinBits);
            policy->certDigests      |= policies[i].certDigests;
            policy->handshakeDigests |= policies[i].handshakeDigests;
        }
    }
}

static OS_Error_t
checkPolicy(
    const TlsLib_Config_t* cfg,
    const OS_Tls_Policy_t* policy)
{
    bool checkDH  = false;
    bool checkRSA = false;

    // Digest flags should never be zero
    CHECK_FLAGS_NOT_ZERO(policy->handshakeDigests);
    CHECK_FLAGS_NOT_ZERO(policy->certDigests);

    // OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    checkRSA |= !!(cfg->crypto.cipherSuites & OS_Tls_CIPHERSUITE_FLAGS(
                       OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
    // OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256
    checkRSA |= !!(cfg->crypto.cipherSuites & OS_Tls_CIPHERSUITE_FLAGS(
                       OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256));
    checkDH  |= !!(cfg->crypto.cipherSuites & OS_Tls_CIPHERSUITE_FLAGS(
                       OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256));

    // Check against known size limitations of Crypto API
    if (checkRSA)
    {
        CHECK_VALUE_IN_RANGE(policy->rsaMinBits,
                             (OS_CryptoKey_SIZE_RSA_MIN * 8),
                             (OS_CryptoKey_SIZE_RSA_MAX * 8) + 1);
    }
    if (checkDH)
    {
        CHECK_VALUE_IN_RANGE(policy->dhMinBits,
                             (OS_CryptoKey_SIZE_DH_MIN * 8),
                             (OS_CryptoKey_SIZE_DH_MAX * 8) + 1);
    }

    return OS_SUCCESS;
}

static void
setMbedTlsCertProfile(
    const TlsLib_t*           self,
    mbedtls_x509_crt_profile* profile)
{
    size_t i;
    static const int pks[__OS_Tls_CIPHERSUITE_MAX] =
    {
        [OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256] =
        MBEDTLS_PK_RSA,
        [OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256] =
        MBEDTLS_PK_RSA,
    };
    static const int digests[__OS_Tls_DIGEST_MAX] =
    {
        [OS_Tls_DIGEST_SHA256] = MBEDTLS_MD_SHA256
    };

    memset(profile, 0, sizeof(mbedtls_x509_crt_profile));

    for (i = 0; i < __OS_Tls_CIPHERSUITE_MAX; i++)
    {
        if (self->cfg.crypto.cipherSuites & OS_Tls_CIPHERSUITE_FLAGS(i))
        {
            profile->allowed_pks |= MBEDTLS_X509_ID_FLAG(pks[i]);
        }
    }
    for (i = 0; i < __OS_Tls_DIGEST_MAX; i++)
    {
        if (self->policy.certDigests & OS_Tls_DIGEST_FLAGS(i))
        {
            profile->allowed_mds |= MBEDTLS_X509_ID_FLAG(digests[i]);
        }
    }

    profile->rsa_min_bitlen = self->policy.rsaMinBits;
}

static void
setMbedTlsCipherSuites(
    const TlsLib_t* self,
    int*            cipherSuites)
{
    size_t i, num;
    static const int suites[__OS_Tls_CIPHERSUITE_MAX] =
    {
        [OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256] =
        MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        [OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256] =
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    };

    num = 0;
    for (i = 0; i < __OS_Tls_CIPHERSUITE_MAX; i++)
    {
        if (self->cfg.crypto.cipherSuites & OS_Tls_CIPHERSUITE_FLAGS(i))
        {
            cipherSuites[num++] = suites[i];
        }
    }

    // mbedTLSs: list of allowed ciphersuites, terminated by 0
    Debug_ASSERT(num < sizeof(cipherSuites));
    cipherSuites[num] = 0;
}

static void
setMbedTlsSigHashes(
    const TlsLib_t* self,
    int*            sigHashes)
{
    size_t num, i;
    static const int digests[__OS_Tls_DIGEST_MAX] =
    {
        [OS_Tls_DIGEST_SHA256] = MBEDTLS_MD_SHA256
    };

    num = 0;
    for (i = 0; i < __OS_Tls_DIGEST_MAX; i++)
    {
        if (self->policy.handshakeDigests & OS_Tls_DIGEST_FLAGS(i))
        {
            sigHashes[num++] = digests[i];
        }
    }

    // mbedTLS: list of allowed signature hashes, terminated by MBEDTLS_MD_NONE
    Debug_ASSERT(num < sizeof(sigHashes));
    sigHashes[num] = MBEDTLS_MD_NONE;
}

static bool
setMbedTlsCaCerts(
    TlsLib_t* const self)
{
    size_t size = 0;
    unsigned char* cert = NULL;

    if (self->cfg.crypto.caCerts != NULL)
    {
        size = strlen(self->cfg.crypto.caCerts) + 1;

        // Allocate own memory
        cert = calloc(1, size);

        if (cert == NULL)
        {
            return false;
        }

        // Copy data to own memory
        memcpy(cert, self->cfg.crypto.caCerts, size);
    }

    self->mbedtls.caCertsBufSize = size;
    self->mbedtls.caCertsBuf = cert;

    return true;
}

static bool
setMbedTlsOwnCert(
    TlsLib_t* const self)
{
    size_t size = 0;
    unsigned char* cert = NULL;

    if (self->cfg.crypto.ownCert != NULL)
    {
        size = strlen(self->cfg.crypto.ownCert) + 1;

        // Allocate own memory
        cert = calloc(1, size);

        if (cert == NULL)
        {
            return false;
        }

        // Copy data to own memory
        memcpy(cert, self->cfg.crypto.ownCert, size);
    }

    self->mbedtls.ownCertBufSize = size;
    self->mbedtls.ownCertBuf = cert;

    return true;
}

static bool
setMbedTlsPrivateKey(
    TlsLib_t* const self)
{
    size_t size = 0;
    unsigned char* key = NULL;

    if (self->cfg.crypto.privateKey != NULL)
    {
        size = strlen(self->cfg.crypto.privateKey) + 1;

        // Allocate own memory
        key = calloc(1, size);

        if (key == NULL)
        {
            return false;
        }

        // Copy data to own memory
        memcpy(key, self->cfg.crypto.privateKey, size);
    }

    self->mbedtls.privateKeyBufSize = size;
    self->mbedtls.privateKeyBuf = key;

    return true;
}

static int
defaultSendFunc(
    void*                ctx,
    const unsigned char* buf,
    size_t               len)
{
    OS_Error_t err;
    OS_Socket_Handle_t* hSocket = (OS_Socket_Handle_t*) ctx;
    size_t n;

    // If the requested length exceeds the dataport size, reduce it to the max
    // size of the dataport.
    const size_t maxPossibleLen = OS_Dataport_getSize(hSocket->ctx.dataport);

    if (len > maxPossibleLen)
    {
        len = maxPossibleLen;
    }

    err = OS_Socket_write(*hSocket, buf, len, &n);

    switch (err)
    {
    case OS_SUCCESS:
        // success
        return n;
    case OS_ERROR_TRY_AGAIN:
        // could not write
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    default:
        // error case
        Debug_LOG_ERROR("send / OS_Socket_write() failed with %d", err);
        return err;;
    }
}

static int
defaultRecvFunc(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    OS_Error_t err;
    OS_Socket_Handle_t* hSocket = (OS_Socket_Handle_t*) ctx;
    size_t n;

    // If the requested length exceeds the dataport size, reduce it to the max
    // size of the dataport.
    const size_t maxPossibleLen = OS_Dataport_getSize(hSocket->ctx.dataport);

    if (len > maxPossibleLen)
    {
        len = maxPossibleLen;
    }

    err = OS_Socket_read(*hSocket, buf, len, &n);

    switch (err)
    {
    case OS_SUCCESS:
        // success
        return n;
    case OS_ERROR_TRY_AGAIN:
        // nothing to read
        return MBEDTLS_ERR_SSL_WANT_READ;
    default:
        // error case
        Debug_LOG_ERROR("recv / OS_Socket_read() failed with %d", err);
        return err;
    }
}

static OS_Error_t
initImpl(
    TlsLib_t* self)
{
    int rc;

    // Apply default configuration first, then override parts of it
    mbedtls_ssl_config_init(&self->mbedtls.conf);

    // NOTE: Use MBEDTLS_SSL_CLI_C to decide whether to configure the endpoint
    // as TLS client or TLS server.
#ifdef MBEDTLS_SSL_CLI_C
    const int endpoint = MBEDTLS_SSL_IS_CLIENT;
#else // MBEDTLS_SSL_SRV_C
    const int endpoint = MBEDTLS_SSL_IS_SERVER;
#endif

    if ((rc = mbedtls_ssl_config_defaults(&self->mbedtls.conf,
                                          endpoint,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        DEBUG_LOG_ERROR_MBEDTLS("mbedtls_ssl_config_defaults", rc);
        goto err0;
    }

    // Copy external data structures to formats mbedTLS can use
    setMbedTlsCipherSuites(self, self->mbedtls.cipherSuites);
    setMbedTlsSigHashes(self, self->mbedtls.sigHashes);
    setMbedTlsCertProfile(self, &self->mbedtls.certProfile);

    // Make local copy of CA cert(s)
    if (!setMbedTlsCaCerts(self))
    {
        Debug_LOG_ERROR("Could not copy CA cert(s)");
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of own cert
    if (!setMbedTlsOwnCert(self))
    {
        Debug_LOG_ERROR("Could not copy own cert");
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    // Make local copy of private key
    if (!setMbedTlsPrivateKey(self))
    {
        Debug_LOG_ERROR("Could not copy private key");
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    // Which ciphersuites are allowed? This heavily depends on the state of the
    // modified mbedTLS and cannot simply be changed!
    mbedtls_ssl_conf_ciphersuites(&self->mbedtls.conf, self->mbedtls.cipherSuites);

    // Which hashes do we allow for server signatures?
    mbedtls_ssl_conf_sig_hashes(&self->mbedtls.conf, self->mbedtls.sigHashes);

    // Which certs do we accept (hashes, rsa bitlen)?
    mbedtls_ssl_conf_cert_profile(&self->mbedtls.conf, &self->mbedtls.certProfile);

#ifdef MBEDTLS_SSL_CLI_C
    // NOTE: Use MBEDTLS_SSL_CLI_C to hide this function for TLS servers because
    // it is only available for TLS clients.

    // What is the minimum bitlen we allow for DH-based key exchanges?
    mbedtls_ssl_conf_dhm_min_bitlen(&self->mbedtls.conf,
                                    self->policy.dhMinBits);
#endif

    // If we have debug, use internal logging function
    mbedtls_ssl_conf_dbg(&self->mbedtls.conf, logDebug, NULL);

    // Use internal RNG of Crypto API for TLS
    mbedtls_ssl_conf_rng(&self->mbedtls.conf, getRndBytes,
                         (void*) self->cfg.crypto.handle);

    if (self->cfg.flags & OS_Tls_FLAG_NO_VERIFY)
    {
        // We need to have the option to disable cert verification, even though
        // it is not advisable.
        Debug_LOG_INFO("TLS certificate verification is disabled, this is NOT secure!");
        mbedtls_ssl_conf_authmode(&self->mbedtls.conf, MBEDTLS_SSL_VERIFY_NONE);
    }
    else
    {
        mbedtls_ssl_conf_authmode(&self->mbedtls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }

    mbedtls_x509_crt_init(&self->mbedtls.caCerts);

    if (self->cfg.crypto.caCerts != NULL)
    {
        if ((rc = mbedtls_x509_crt_parse(&self->mbedtls.caCerts,
                                         self->mbedtls.caCertsBuf,
                                         self->mbedtls.caCertsBufSize)) != 0)
        {
            DEBUG_LOG_ERROR_MBEDTLS("mbedtls_x509_crt_parse", rc);
            goto err1;
        }
    }

    mbedtls_ssl_conf_ca_chain(&self->mbedtls.conf, &self->mbedtls.caCerts, NULL);

    mbedtls_x509_crt_init(&self->mbedtls.ownCert);

    if (self->cfg.crypto.ownCert != NULL)
    {
        if ((rc = mbedtls_x509_crt_parse(&self->mbedtls.ownCert,
                                         self->mbedtls.ownCertBuf,
                                         self->mbedtls.ownCertBufSize)) != 0)
        {
            DEBUG_LOG_ERROR_MBEDTLS("mbedtls_x509_crt_parse", rc);
            goto err1;
        }
    }

    mbedtls_pk_init(&self->mbedtls.privateKey);

    if (self->cfg.crypto.privateKey != NULL)
    {
        if ((rc = mbedtls_pk_parse_key(&self->mbedtls.privateKey,
                                       self->mbedtls.privateKeyBuf,
                                       self->mbedtls.privateKeyBufSize, NULL,
                                       0)) != 0)
        {
            DEBUG_LOG_ERROR_MBEDTLS("mbedtls_pk_parse_key", rc);
            goto err1;
        }
    }

    if ((rc = mbedtls_ssl_conf_own_cert(&self->mbedtls.conf,
                                        &self->mbedtls.ownCert,
                                        &self->mbedtls.privateKey)) != 0)
    {
        DEBUG_LOG_ERROR_MBEDTLS("mbedtls_ssl_conf_own_cert", rc);
        goto err1;
    }

    // Output levels: (0) none, (1) error, (2) state change, (3) informational
    mbedtls_debug_set_threshold((self->cfg.flags & OS_Tls_FLAG_DEBUG) ? 3 : 0);

    mbedtls_ssl_init(&self->mbedtls.ssl);

    // WARNING: This has to happen before mbedtls_ssl_setup() is called, as the
    // crypto context is already needed during setup so that it can be used in
    // ssl_handshake_params_init() for the initialization of the digests.
    mbedtls_ssl_set_crypto(&self->mbedtls.ssl, self->cfg.crypto.handle);

    mbedtls_ssl_send_t* sendFunc = defaultSendFunc;
    mbedtls_ssl_recv_t* recvFunc = defaultRecvFunc;

    // Set the send/recv callbacks to be used with mbedTLS.
    // Users can specify their own implementations via OS_TLS_init().
    // If no functions are defined, the default functions will be used.
    if (self->cfg.socket.send)
    {
        sendFunc = self->cfg.socket.send;
    }

    if (self->cfg.socket.recv)
    {
        recvFunc = self->cfg.socket.recv;
    }

    mbedtls_ssl_set_bio(&self->mbedtls.ssl,
                        self->cfg.socket.context,
                        sendFunc,
                        recvFunc,
                        NULL);

    if ((rc = mbedtls_ssl_setup(&self->mbedtls.ssl, &self->mbedtls.conf)) != 0)
    {
        DEBUG_LOG_ERROR_MBEDTLS("mbedtls_ssl_setup", rc);
        goto err2;
    }

    return OS_SUCCESS;

err2:
    mbedtls_ssl_free(&self->mbedtls.ssl);
err1:
    mbedtls_x509_crt_free(&self->mbedtls.caCerts);
    mbedtls_x509_crt_free(&self->mbedtls.ownCert);
    mbedtls_pk_free(&self->mbedtls.privateKey);
err0:
    mbedtls_ssl_config_free(&self->mbedtls.conf);

    return OS_ERROR_ABORTED;
}

static OS_Error_t
freeImpl(
    TlsLib_t* self)
{
    mbedtls_ssl_free(&self->mbedtls.ssl);
    mbedtls_x509_crt_free(&self->mbedtls.caCerts);
    mbedtls_x509_crt_free(&self->mbedtls.ownCert);
    mbedtls_pk_free(&self->mbedtls.privateKey);
    mbedtls_ssl_config_free(&self->mbedtls.conf);
    free(self->mbedtls.caCertsBuf);
    free(self->mbedtls.ownCertBuf);
    free(self->mbedtls.privateKeyBuf);

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
            Debug_LOG_INFO("mbedtls_ssl_handshake() successful with "
                           "ciphersuite %s",
                           mbedtls_ssl_get_ciphersuite(&self->mbedtls.ssl));
            return OS_SUCCESS;
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            // The send/recv callbacks return WANT_READ/WANT_WRITE in case
            // the socket I/O would block.
            if (self->cfg.flags & OS_Tls_FLAG_NON_BLOCKING)
            {
                return OS_ERROR_WOULD_BLOCK;
            }
            seL4_Yield();
            continue;
        case OS_ERROR_CONNECTION_CLOSED:
            Debug_LOG_ERROR("socket closed during mbedtls_ssl_handshake()");
            self->open = false;
            return OS_ERROR_CONNECTION_CLOSED;
        case OS_ERROR_NETWORK_CONN_SHUTDOWN:
            // Socket was closed by peer
            Debug_LOG_ERROR("connection closed during mbedtls_ssl_handshake()");
            self->open = false;
            return OS_ERROR_NETWORK_CONN_SHUTDOWN;
        default:
            DEBUG_LOG_ERROR_MBEDTLS("mbedtls_ssl_handshake", rc);
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

    for (;;)
    {
        rc = mbedtls_ssl_write(&self->mbedtls.ssl, data, *dataSize);
        if (rc < 0)
        {
            switch (rc)
            {
            case MBEDTLS_ERR_SSL_WANT_WRITE:
                // The write could block for some reason, even after we have
                // done some partial writing. If we do not want to block, return
                // with OS_ERROR_WOULD_BLOCK. Otherwise, keep trying.
                if (self->cfg.flags & OS_Tls_FLAG_NON_BLOCKING)
                {
                    return OS_ERROR_WOULD_BLOCK;
                }
                seL4_Yield();
                continue;
            case OS_ERROR_CONNECTION_CLOSED:
                Debug_LOG_ERROR("socket closed during mbedtls_ssl_write()");
                self->open = false;
                return OS_ERROR_CONNECTION_CLOSED;
            case OS_ERROR_NETWORK_CONN_SHUTDOWN:
                // Socket was closed by peer
                Debug_LOG_ERROR("connection closed during mbedtls_ssl_write()");
                self->open = false;
                return OS_ERROR_NETWORK_CONN_SHUTDOWN;
            default:
                DEBUG_LOG_ERROR_MBEDTLS("mbedtls_ssl_write", rc);
                return OS_ERROR_ABORTED;
            }
        }
        else
        {
            // We exit the loop with the first successfully written bytes or
            // 0 bytes, in case 0 bytes were requested to be sent.
            // This shall ensure, that we always return, independent of
            // capability to send data.
            // This also supports sending empty Tls packages of dataSize 0.

            // Give back the amount of bytes actually written
            *dataSize  = rc;
            break;
        }
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

    for (;;)
    {
        rc = mbedtls_ssl_read(&self->mbedtls.ssl, data, *dataSize);
        if (rc <= 0)
        {
            switch (rc)
            {
            case 0:
                // Server can send empty messages for randomization purposes, so
                // this is not an error.
                // We will silently read all 0-byte packages and not return
                // here. But we still want to notify the user with a log
                // message.
                Debug_LOG_INFO("mbedtls_ssl_read() read 0 bytes");
                continue;
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                // Server has signaled that the connection will be closed. We
                // count this as success but terminate the SSL session here.
                Debug_LOG_INFO("host has signaled that connection will be closed");
                self->open = false;
                return OS_ERROR_CONNECTION_CLOSED;
            case MBEDTLS_ERR_SSL_WANT_READ:
                // There were no bytes to read without blocking
                if (self->cfg.flags & OS_Tls_FLAG_NON_BLOCKING)
                {
                    return OS_ERROR_WOULD_BLOCK;
                }
                seL4_Yield();
                continue;
            case OS_ERROR_CONNECTION_CLOSED:
                // Socket was closed by network sock, OS_SOCK_EV_FIN received
                Debug_LOG_ERROR("socket closed during mbedtls_ssl_read()");
                self->open = false;
                return OS_ERROR_CONNECTION_CLOSED;
            case OS_ERROR_NETWORK_CONN_SHUTDOWN:
                // Socket was closed by peer
                Debug_LOG_ERROR("connection closed during mbedtls_ssl_read()");
                self->open = false;
                return OS_ERROR_NETWORK_CONN_SHUTDOWN;
            default:
                DEBUG_LOG_ERROR_MBEDTLS("mbedtls_ssl_read", rc);
                return OS_ERROR_ABORTED;
            }
        }
        else
        {
            // We exit the loop with the first successfully read bytes.
            // This shall ensure, that we always return, independent of the
            // server response.

            // Give back amount of bytes actually read
            *dataSize = rc;
            break;
        }
    }

    return OS_SUCCESS;
}

static OS_Error_t
closeNotifyImpl(
    TlsLib_t* self)
{
    int rc;

    if ((rc  = mbedtls_ssl_close_notify(&self->mbedtls.ssl)) != 0)
    {
        DEBUG_LOG_ERROR_MBEDTLS("mbedtls_ssl_close_notify", rc);
        return OS_ERROR_ABORTED;
    }

    return OS_SUCCESS;
}

static OS_Error_t
resetImpl(
    TlsLib_t* self)
{
    int rc;

    if ((rc  = mbedtls_ssl_session_reset(&self->mbedtls.ssl)) != 0)
    {
        DEBUG_LOG_ERROR_MBEDTLS("mbedtls_ssl_session_reset", rc);
        return OS_ERROR_ABORTED;
    }

    return OS_SUCCESS;
}

static OS_Error_t
checkParams(
    TlsLib_t**             self,
    const TlsLib_Config_t* cfg)
{
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(cfg);
    CHECK_PTR_NOT_NULL(cfg->crypto.handle);

    CHECK_FLAGS_NOT_ZERO(cfg->crypto.cipherSuites);

    if ( (!(cfg->flags & OS_Tls_FLAG_NO_VERIFY))
         && (cfg->crypto.caCerts == NULL))
    {
        Debug_LOG_ERROR("Flag NO_VERIFY is set but no CA cert(s) presented.");
        return OS_ERROR_INVALID_PARAMETER;
    }

    if (cfg->crypto.caCerts != NULL)
    {
        CHECK_STR_NOT_EMPTY(cfg->crypto.caCerts);
        if ( (strstr(cfg->crypto.caCerts,
                     "-----BEGIN CERTIFICATE-----") == NULL)
             || (strstr(cfg->crypto.caCerts,
                        "-----END CERTIFICATE-----") == NULL) )
        {
            Debug_LOG_ERROR("Presented CA cert(s) does not have BEGIN/END "
                            "(maybe it is not PEM encoded?)");
            return OS_ERROR_INVALID_PARAMETER;
        }
    }

    if (cfg->crypto.ownCert != NULL)
    {
        CHECK_STR_NOT_EMPTY(cfg->crypto.ownCert);
        if ( (strstr(cfg->crypto.ownCert,
                     "-----BEGIN CERTIFICATE-----") == NULL)
             || (strstr(cfg->crypto.ownCert,
                        "-----END CERTIFICATE-----") == NULL) )
        {
            Debug_LOG_ERROR("Presented own cert does not have BEGIN/END "
                            "(maybe it is not PEM encoded?)");
            return OS_ERROR_INVALID_PARAMETER;
        }
    }

    if (cfg->crypto.privateKey != NULL)
    {
        CHECK_STR_NOT_EMPTY(cfg->crypto.privateKey);
        if ( (strstr(cfg->crypto.privateKey,
                     "-----BEGIN RSA PRIVATE KEY-----") == NULL)
             || (strstr(cfg->crypto.privateKey,
                        "-----END RSA PRIVATE KEY-----") == NULL) )
        {
            Debug_LOG_ERROR("Presented private key does not have BEGIN/END "
                            "(maybe it is not PEM encoded?)");
            return OS_ERROR_INVALID_PARAMETER;
        }
    }

    return OS_SUCCESS;
}


// Public functions ------------------------------------------------------------

OS_Error_t
TlsLib_init(
    TlsLib_t**             self,
    const TlsLib_Config_t* cfg)
{
    OS_Error_t err;
    TlsLib_t* lib;

    if ((err = checkParams(self, cfg)) != OS_SUCCESS)
    {
        return err;
    }

    if ((lib = malloc(sizeof(TlsLib_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(lib, 0, sizeof(TlsLib_t));
    memcpy(&lib->cfg, cfg, sizeof(TlsLib_Config_t));

    if (NULL == cfg->crypto.policy)
    {
        // If no policy is given, derive all the policy parameters based on the
        // WEAKEST ciphersuite given by the user.
        derivePolicy(&lib->cfg, &lib->policy);
    }
    else
    {
        lib->policy = *cfg->crypto.policy;
    }

    if ((err = checkPolicy(&lib->cfg, &lib->policy)) == OS_SUCCESS)
    {
        err = initImpl(lib);
    }

    if (err != OS_SUCCESS)
    {
        free(lib);
    }

    *self = lib;

    return err;
}

OS_Error_t
TlsLib_free(
    TlsLib_t* self)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);

    err = freeImpl(self);
    free(self);

    return err;
}

OS_Error_t
TlsLib_handshake(
    TlsLib_t* self)
{
    OS_Error_t err;

    CHECK_PTR_NOT_NULL(self);

    if (self->open)
    {
        Debug_LOG_ERROR("The TLS session is already open");
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
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(data);
    CHECK_PTR_NOT_NULL(dataSize);
    CHECK_VALUE_NOT_ZERO(*dataSize);

    if (!self->open)
    {
        Debug_LOG_ERROR("The TLS session is not open yet");
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
    CHECK_PTR_NOT_NULL(self);
    CHECK_PTR_NOT_NULL(data);
    CHECK_PTR_NOT_NULL(dataSize);
    CHECK_VALUE_NOT_ZERO(*dataSize);

    if (!self->open)
    {
        Debug_LOG_ERROR("The TLS session is not open yet");
        return OS_ERROR_OPERATION_DENIED;
    }

    return readImpl(self, data, dataSize);
}

OS_Error_t
TlsLib_reset(
    TlsLib_t* self)
{
    CHECK_PTR_NOT_NULL(self);

    if (self->open)
    {
        // Ignore error and reset connection afterwards in any case.
        DECL_UNUSED_VAR(OS_Error_t error);

        // Notify peer that an open connection will be reset.
        error = closeNotifyImpl(self);
    }

    // Regardless of the success of resetImpl() we set the connection to closed,
    // because most likely a big part of the internal data structures will be
    // reset even in case of error.
    self->open = false;

    return resetImpl(self);
}
