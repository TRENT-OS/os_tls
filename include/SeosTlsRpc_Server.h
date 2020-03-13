/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi.h"

typedef struct SeosTlsRpc_Server SeosTlsRpc_Server;

seos_err_t
SeosTlsRpc_Server_init(
    SeosTlsRpc_Server**             self,
    const SeosTlsRpc_Server_Config* cfg);

seos_err_t
SeosTlsRpc_Server_handshake(
    void);

seos_err_t
SeosTlsRpc_Server_write(
    size_t dataSize);

seos_err_t
SeosTlsRpc_Server_read(
    size_t* dataSize);

seos_err_t
SeosTlsRpc_Server_reset(
    void);

seos_err_t
SeosTlsRpc_Server_free(
    SeosTlsRpc_Server* self);