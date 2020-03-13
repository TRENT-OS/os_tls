/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi.h"

typedef struct SeosTlsRpcClient SeosTlsRpcClient;

seos_err_t
SeosTlsRpcClient_init(
    SeosTlsRpcClient**             self,
    const SeosTlsRpcClient_Config* cfg);

seos_err_t
SeosTlsRpcClient_handshake(
    SeosTlsRpcClient* self);

seos_err_t
SeosTlsRpcClient_write(
    SeosTlsRpcClient* self,
    const void*       data,
    const size_t      dataSize);

seos_err_t
SeosTlsRpcClient_read(
    SeosTlsRpcClient* self,
    void*             data,
    size_t*           dataSize);

seos_err_t
SeosTlsRpcClient_reset(
    SeosTlsRpcClient* self);

seos_err_t
SeosTlsRpcClient_free(
    SeosTlsRpcClient* self);