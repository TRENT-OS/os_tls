/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_Tls.h"

#include "lib_debug/Debug.h"

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ciphersuites.h"

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