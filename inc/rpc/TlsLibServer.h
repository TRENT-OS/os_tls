/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Tls.h"

typedef struct TlsLibServer TlsLibServer_t;

seos_err_t
TlsLibServer_init(
    TlsLibServer_t**             self,
    const TlsLibServer_Config_t* cfg);

seos_err_t
TlsLibServer_handshake(
    void);

seos_err_t
TlsLibServer_write(
    size_t dataSize);

seos_err_t
TlsLibServer_read(
    size_t* dataSize);

seos_err_t
TlsLibServer_reset(
    void);

seos_err_t
TlsLibServer_free(
    TlsLibServer_t* self);