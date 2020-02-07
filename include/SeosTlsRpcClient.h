/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi_Impl.h"

seos_err_t
SeosTlsRpcClient_init(
    SeosTlsRpcClient_Context*      ctx,
    const SeosTlsRpcClient_Config* cfg);

seos_err_t
SeosTlsRpcClient_handshake(
    SeosTlsRpcClient_Context* ctx);

seos_err_t
SeosTlsRpcClient_write(
    SeosTlsRpcClient_Context* ctx,
    const void*               data,
    const size_t              dataSize);

seos_err_t
SeosTlsRpcClient_read(
    SeosTlsRpcClient_Context* ctx,
    void*                     data,
    size_t*                   dataSize);

seos_err_t
SeosTlsRpcClient_free(
    SeosTlsRpcClient_Context* ctx);