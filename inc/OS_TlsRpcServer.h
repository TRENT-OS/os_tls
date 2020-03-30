/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Tls.h"

typedef struct OS_TlsRpcServer OS_TlsRpcServer_t;

seos_err_t
OS_TlsRpcServer_init(
    OS_TlsRpcServer_t**             self,
    const OS_TlsRpcServer_Config_t* cfg);

seos_err_t
OS_TlsRpcServer_handshake(
    void);

seos_err_t
OS_TlsRpcServer_write(
    size_t dataSize);

seos_err_t
OS_TlsRpcServer_read(
    size_t* dataSize);

seos_err_t
OS_TlsRpcServer_reset(
    void);

seos_err_t
OS_TlsRpcServer_free(
    OS_TlsRpcServer_t* self);