#pragma once

#include "OS_Tls.h"

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ciphersuites.h"

#include "pb_tls_lib.h"

struct TlsLib
{
    bool open;
    struct mbedtls
    {
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_x509_crt cert;
        mbedtls_x509_crt_profile certProfile;
        int cipherSuites[__OS_Tls_CIPHERSUITE_MAX];
        int sigHashes[__OS_Tls_DIGEST_MAX];
        unsigned char* caCerts;
        size_t caCertLen;
    } mbedtls;
    struct pbtls
    {
        pbTlsLib_Config_t pbTlsConfig;
        void* ssl;
    } pbtls; //@11.11.2020 PointBlank
    TlsLib_Config_t cfg;
    OS_Tls_Policy_t policy;
};
