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
 *   This file provides an implementation of entropy source.
 */

#include "entropy.hpp"

#include <mbedtls/entropy.h>
#include <openthread/platform/entropy.h>

#include "debug.hpp"

namespace ot {
namespace Entropy {

static bool sInitialized;

void Init(void)
{
    assert(!sInitialized);

    otPlatEntropyInit();

    sInitialized = true;
}

void Deinit(void)
{
    assert(sInitialized);

    otPlatEntropyDeinit();

    sInitialized = false;
}

#ifndef OPENTHREAD_RADIO

mbedtls_entropy_context *MbedTlsContextGet(void)
{
    assert(sInitialized);
    return otPlatEntropyMbedTlsContextGet();
}

#endif // OPENTHREAD_RADIO

otError GetUint32(uint32_t *aVal)
{
    assert(sInitialized);
    return otPlatEntropyGetUint32(aVal);
}

} // namespace Entropy
} // namespace ot
