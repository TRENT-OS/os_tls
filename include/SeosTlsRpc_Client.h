/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosTlsApi.h"

typedef struct SeosTlsRpc_Client SeosTlsRpc_Client;

seos_err_t
SeosTlsRpc_Client_init(
    SeosTlsRpc_Client**             self,
    const SeosTlsRpc_Client_Config* cfg);

seos_err_t
SeosTlsRpc_Client_handshake(
    SeosTlsRpc_Client* self);

seos_err_t
SeosTlsRpc_Client_write(
    SeosTlsRpc_Client* self,
    const void*        data,
    const size_t       dataSize);

seos_err_t
SeosTlsRpc_Client_read(
    SeosTlsRpc_Client* self,
    void*              data,
    size_t*            dataSize);

seos_err_t
SeosTlsRpc_Client_reset(
    SeosTlsRpc_Client* self);

seos_err_t
SeosTlsRpc_Client_free(
    SeosTlsRpc_Client* self);