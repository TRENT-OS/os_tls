/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi_Impl.h"

seos_err_t
SeosTlsRpcServer_init(
    SeosTlsRpcServer_Context*      ctx,
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
SeosTlsRpcServer_free(
    SeosTlsRpcServer_Context* ctx);