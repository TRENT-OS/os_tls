/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi_Impl.h"

seos_err_t
SeosTlsLib_init(
    SeosTlsLib_Context*      ctx,
    const SeosTlsLib_Config* cfg);

seos_err_t
SeosTlsLib_handshake(
    SeosTlsLib_Context* ctx);

seos_err_t
SeosTlsLib_write(
    SeosTlsLib_Context* ctx,
    const void*         data,
    const size_t        dataSize);

seos_err_t
SeosTlsLib_read(
    SeosTlsLib_Context* ctx,
    void*               data,
    size_t*             dataSize);

seos_err_t
SeosTlsLib_reset(
    SeosTlsLib_Context* ctx);

seos_err_t
SeosTlsLib_free(
    SeosTlsLib_Context* ctx);