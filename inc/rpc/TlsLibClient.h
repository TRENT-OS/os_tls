/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Tls.h"

typedef struct TlsLibClient TlsLibClient_t;

seos_err_t
TlsLibClient_init(
    TlsLibClient_t**             self,
    const TlsLibClient_Config_t* cfg);

seos_err_t
TlsLibClient_handshake(
    TlsLibClient_t* self);

seos_err_t
TlsLibClient_write(
    TlsLibClient_t* self,
    const void*     data,
    const size_t    dataSize);

seos_err_t
TlsLibClient_read(
    TlsLibClient_t* self,
    void*           data,
    size_t*         dataSize);

seos_err_t
TlsLibClient_reset(
    TlsLibClient_t* self);

seos_err_t
TlsLibClient_free(
    TlsLibClient_t* self);