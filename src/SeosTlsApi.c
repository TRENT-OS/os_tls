/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosTls.h"

#include "LibDebug/Debug.h"

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
SeosTlsApi_init(SeosTlsCtx *ctx)
{
    return SeosTls_init(ctx);
}

seos_err_t
SeosTlsApi_free(SeosTlsCtx* ctx)
{
    return SeosTls_free(ctx);
}

