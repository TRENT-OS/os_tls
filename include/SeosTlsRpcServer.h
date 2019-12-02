/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosTlsRpcServer.h
 *
 * @brief SEOS TLS internal RPC server API
 *
 */

#pragma once

#include "SeosTlsApi_Impl.h"

seos_err_t
SeosTlsRpcServer_init(SeosTlsRpcServer_Context*         ctx,
                      const SeosTlsRpcServer_Config*    cfg);

seos_err_t
SeosTlsRpcServer_free(SeosTlsRpcServer_Context*         ctx);

seos_err_t
SeosTlsRpcServer_handshake(SeosTlsRpcServer_Handle      handle);

seos_err_t
SeosTlsRpcServer_write(SeosTlsRpcServer_Handle          handle,
                       size_t                           dataSize);

seos_err_t
SeosTlsRpcServer_read(SeosTlsRpcServer_Handle           handle,
                      size_t*                           dataSize);

/** @} */