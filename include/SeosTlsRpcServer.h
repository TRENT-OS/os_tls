/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi.h"

typedef struct SeosTlsRpcServer SeosTlsRpcServer;

seos_err_t
SeosTlsRpcServer_init(
    SeosTlsRpcServer**             self,
    const SeosTlsRpcServer_Config* cfg);

seos_err_t
SeosTlsRpcServer_handshake(
    void);

seos_err_t
SeosTlsRpcServer_write(
    size_t dataSize);

seos_err_t
SeosTlsRpcServer_read(
    size_t* dataSize);

seos_err_t
SeosTlsRpcServer_reset(
    void);

seos_err_t
SeosTlsRpcServer_free(
    SeosTlsRpcServer* self);