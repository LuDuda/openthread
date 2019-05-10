/*
 *  Copyright (c) 2019, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements an entropy based on TRNG.
 *
 */

#include "trng.h"

#include <utils/code_utils.h>

#include <openthread/error.h>

#ifndef OPENTHREAD_RADIO

#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>

static mbedtls_entropy_context sEntropy;

static int HandleMbedtlsEntropyPoll(void *aData, unsigned char *aOutput, size_t aInLen, size_t *aOutLen)
{
    OT_UNUSED_VARIABLE(aData);

    otError error;
    int     rval = 0;

    error = utilsEntropyGet((uint8_t *)aOutput, (uint16_t)aInLen);
    otEXPECT(error == OT_ERROR_NONE);

    if (aOutLen != NULL)
    {
        *aOutLen = aInLen;
    }

exit:

    if (error != OT_ERROR_NONE)
    {
        rval = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    return rval;
}

void otPlatEntropyInit(void)
{
    mbedtls_entropy_init(&sEntropy);
    mbedtls_entropy_add_source(&sEntropy, &HandleMbedtlsEntropyPoll, NULL, MBEDTLS_ENTROPY_MIN_HARDWARE,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
}

void otPlatEntropyDeinit(void)
{
    mbedtls_entropy_free(&sEntropy);
}

mbedtls_entropy_context *otPlatEntropyMbedTlsContextGet(void)
{
    return &sEntropy;
}

#else  // OPENTHREAD_RADIO

void otPlatEntropyInit(void)
{
    // Intentionally empty
}

void otPlatEntropyDeinit(void)
{
    // Intentionally empty
}

#endif // OPENTHREAD_RADIO

otError otPlatEntropyGetUint32(uint32_t *aVal)
{
    otError error = utilsEntropyGet((uint8_t *)aVal, sizeof(*aVal));

    return error;
}
