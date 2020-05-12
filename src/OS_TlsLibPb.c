/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_Tls.h"

#include "OS_TlsLib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct OS_TlsLib
{
    int dummy;
};

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
OS_TlsLib_init(
    OS_TlsLib_t**             self,
    const OS_TlsLib_Config_t* cfg)
{
    return SEOS_ERROR_NOT_IMPLEMENTED;
}

seos_err_t
OS_TlsLib_free(
    OS_TlsLib_t* self)
{
    return SEOS_ERROR_NOT_IMPLEMENTED;
}

seos_err_t
OS_TlsLib_handshake(
    OS_TlsLib_t* self)
{
    return SEOS_ERROR_NOT_IMPLEMENTED;
}

seos_err_t
OS_TlsLib_write(
    OS_TlsLib_t* self,
    const void*  data,
    const size_t dataSize)
{
    return SEOS_ERROR_NOT_IMPLEMENTED;
}

seos_err_t
OS_TlsLib_read(
    OS_TlsLib_t* self,
    void*        data,
    size_t*      dataSize)
{
    return SEOS_ERROR_NOT_IMPLEMENTED;
}

seos_err_t
OS_TlsLib_reset(
    OS_TlsLib_t* self)
{
    return SEOS_ERROR_NOT_IMPLEMENTED;
}