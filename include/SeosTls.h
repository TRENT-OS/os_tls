/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosTls.h
 *
 * @brief SEOS TLS context and functions
 *
 */
#pragma once

#include "compiler.h"
#include "seos_err.h"

typedef struct {
    int test;
} SeosTlsCtx;

seos_err_t
SeosTls_init(SeosTlsCtx* self);

seos_err_t
SeosTls_free(SeosTlsCtx* api);

/** @} */
