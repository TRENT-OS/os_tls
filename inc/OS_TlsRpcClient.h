/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Tls.h"

typedef struct OS_TlsRpcClient OS_TlsRpcClient_t;

seos_err_t
OS_TlsRpcClient_init(
    OS_TlsRpcClient_t**             self,
    const OS_TlsRpcClient_Config_t* cfg);

seos_err_t
OS_TlsRpcClient_handshake(
    OS_TlsRpcClient_t* self);

seos_err_t
OS_TlsRpcClient_write(
    OS_TlsRpcClient_t* self,
    const void*        data,
    const size_t       dataSize);

seos_err_t
OS_TlsRpcClient_read(
    OS_TlsRpcClient_t* self,
    void*              data,
    size_t*            dataSize);

seos_err_t
OS_TlsRpcClient_reset(
    OS_TlsRpcClient_t* self);

seos_err_t
OS_TlsRpcClient_free(
    OS_TlsRpcClient_t* self);