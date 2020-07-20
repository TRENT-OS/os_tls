/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Tls.h"

#include "lib/TlsLib.h"

typedef struct TlsLibServer TlsLibServer_t;

OS_Error_t
TlsLibServer_init(
    TlsLibServer_t**     self,
    TlsLib_t*            library,
    const OS_Dataport_t* dataport);

OS_Error_t
TlsLibServer_free(
    TlsLibServer_t* self);

OS_Error_t
tls_rpc_handshake(
    void);

OS_Error_t
tls_rpc_write(
    size_t dataSize);

OS_Error_t
tls_rpc_read(
    size_t* dataSize);

OS_Error_t
tls_rpc_reset(
    void);