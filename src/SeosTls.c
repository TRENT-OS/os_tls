/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosTls.h"

#include "LibDebug/Debug.h"

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
SeosTls_init(SeosTlsCtx *ctx)
{
    Debug_ASSERT_SELF(ctx);
    return SEOS_SUCCESS;
}

seos_err_t
SeosTls_free(SeosTlsCtx* ctx)
{
    Debug_ASSERT_SELF(ctx);
    return SEOS_SUCCESS; 
}

