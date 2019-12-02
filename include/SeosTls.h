/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosTls.h
 *
 * @brief SEOS TLS implementation functions
 *
 */

#pragma once

#include "SeosTlsApi_Impl.h"

seos_err_t
SeosTls_init(SeosTls_Context*           ctx,
             const SeosTls_Config*      cfg);

seos_err_t
SeosTls_free(SeosTls_Context*           ctx);

seos_err_t
SeosTls_handshake(SeosTls_Context*      ctx);

seos_err_t
SeosTls_write(SeosTls_Context*          ctx,
              const void*               data,
              const size_t              dataSize);

seos_err_t
SeosTls_read(SeosTls_Context*           ctx,
             void*                      data,
             size_t*                    dataSize);

/** @} */