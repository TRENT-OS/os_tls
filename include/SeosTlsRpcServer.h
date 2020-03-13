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
    SeosTlsRpcServer_Handle handle);

seos_err_t
SeosTlsRpcServer_write(
    SeosTlsRpcServer_Handle handle,
    size_t                  dataSize);

seos_err_t
SeosTlsRpcServer_read(
    SeosTlsRpcServer_Handle handle,
    size_t*                 dataSize);

seos_err_t
SeosTlsRpcServer_reset(
    SeosTlsRpcServer_Handle handle);

seos_err_t
SeosTlsRpcServer_free(
    SeosTlsRpcServer* self);