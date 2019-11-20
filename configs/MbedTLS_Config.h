#pragma once

/*
 * For now, the config for seos_crypto_api and seos_tls_api need to be identical
 * so that all the data structures are similar!!!
 */

#define MBEDTLS_DEBUG_C

#define USE_SEOS_CRYPTO

// -----------------------------------------------------------------------------
// Modules for seos_crypto_api
// -----------------------------------------------------------------------------

#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA256_C

#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_MODE_CBC

#define MBEDTLS_CTR_DRBG_C

#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_RSA_C

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_GENPRIME

#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDH_C

#define MBEDTLS_DHM_C

// -----------------------------------------------------------------------------
// Modules for seos_tls_api
// -----------------------------------------------------------------------------

#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C

#define MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_ASN1_PARSE_C

#include "mbedtls/check_config.h"