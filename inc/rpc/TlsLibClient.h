/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Tls.h"

typedef struct TlsLibClient TlsLibClient_t;

OS_Error_t
TlsLibClient_init(
    TlsLibClient_t**   self,
    const if_OS_Tls_t* rpc);

OS_Error_t
TlsLibClient_handshake(
    TlsLibClient_t* self);

OS_Error_t
TlsLibClient_write(
    TlsLibClient_t* self,
    const void*     data,
    size_t*         dataSize);

OS_Error_t
TlsLibClient_read(
    TlsLibClient_t* self,
    void*           data,
    size_t*         dataSize);

OS_Error_t
TlsLibClient_reset(
    TlsLibClient_t* self);

OS_Error_t
TlsLibClient_free(
    TlsLibClient_t* self);