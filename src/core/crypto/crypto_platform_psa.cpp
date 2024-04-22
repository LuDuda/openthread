/*
 *    Copyright (c) 2021, The OpenThread Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 *    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements the Crypto platform callbacks into OpenThread and default/weak Crypto platform APIs.
 */

#include "openthread-core-config.h"

#include <string.h>

#if defined(CONFIG_OPENTHREAD_ECDSA)
#include <mbedtls/asn1.h>
#endif
#include <mbedtls/version.h>

#include <psa/crypto.h>

#include <openthread/instance.h>
#include <openthread/platform/crypto.h>
#include <openthread/platform/entropy.h>
#include <openthread/platform/time.h>

#include "common/code_utils.hpp"
#include "common/debug.hpp"
#include "common/new.hpp"
#include "config/crypto.h"
#include "crypto/ecdsa.hpp"
#include "crypto/hmac_sha256.hpp"
#include "crypto/storage.hpp"
#include "instance/instance.hpp"

using namespace ot;
using namespace Crypto;

#if OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_PSA

//---------------------------------------------------------------------------------------------------------------------
// Default/weak implementation of crypto platform APIs

static otError psaToOtError(psa_status_t aStatus)
{
    switch (aStatus) {
    case PSA_SUCCESS:
        return kErrorNone;
    case PSA_ERROR_INVALID_ARGUMENT:
        return kErrorInvalidArgs;
    case PSA_ERROR_BUFFER_TOO_SMALL:
        return kErrorNoBufs;
    default:
        return kErrorFailed;
    }
}

static psa_key_type_t toPsaKeyType(otCryptoKeyType aType)
{
    switch (aType) {
    case Storage::kKeyTypeRaw:
        return PSA_KEY_TYPE_RAW_DATA;
    case Storage::kKeyTypeAes:
        return PSA_KEY_TYPE_AES;
    case Storage::kKeyTypeHmac:
        return PSA_KEY_TYPE_HMAC;
    case Storage::kKeyTypeEcdsa:
        return PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    default:
        return PSA_KEY_TYPE_NONE;
    }
}

static psa_algorithm_t toPsaAlgorithm(otCryptoKeyAlgorithm aAlgorithm)
{
    switch (aAlgorithm) {
    case Storage::kKeyAlgorithmAesEcb:
        return PSA_ALG_ECB_NO_PADDING;
    case Storage::kKeyAlgorithmHmacSha256:
        return PSA_ALG_HMAC(PSA_ALG_SHA_256);
    case Storage::kKeyAlgorithmEcdsa:
        return PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
    default:
        return PSA_ALG_NONE;
    }
}

static psa_key_usage_t toPsaKeyUsage(int aUsage)
{
    psa_key_usage_t usage = 0;

    if (aUsage & Storage::kUsageExport) {
        usage |= PSA_KEY_USAGE_EXPORT;
    }

    if (aUsage & Storage::kUsageEncrypt) {
        usage |= PSA_KEY_USAGE_ENCRYPT;
    }

    if (aUsage & Storage::kUsageDecrypt) {
        usage |= PSA_KEY_USAGE_DECRYPT;
    }

    if (aUsage & Storage::kUsageSignHash) {
        usage |= PSA_KEY_USAGE_SIGN_HASH;
    }

    if (aUsage & Storage::kUsageVerifyHash) {
        usage |= PSA_KEY_USAGE_VERIFY_HASH;
    }

    return usage;
}

static bool checkKeyUsage(int aUsage)
{
    /* Check if only supported flags have been passed */
    int supportedFlags = Storage::kUsageExport | Storage::kUsageEncrypt | Storage::kUsageDecrypt |
                         Storage::kUsageSignHash | Storage::kUsageVerifyHash;

    return (aUsage & ~supportedFlags) == 0;
}

static bool checkContext(otCryptoContext *aContext, size_t aMinSize)
{
    /* Verify that the passed context is initialized and points to a big enough buffer */
    return aContext != nullptr && aContext->mContext != nullptr && aContext->mContextSize >= aMinSize;
}

OT_TOOL_WEAK void otPlatCryptoInit(void)
{
    psa_crypto_init();
}

// Key storage
OT_TOOL_WEAK otError otPlatCryptoImportKey(otCryptoKeyRef *aKeyRef, otCryptoKeyType aKeyType,
                                           otCryptoKeyAlgorithm aKeyAlgorithm, int aKeyUsage,
                                           otCryptoKeyStorage aKeyPersistence, const uint8_t *aKey,
                                           size_t aKeyLen)
{
#if defined(CONFIG_OPENTHREAD_ECDSA)
    int version;
    size_t len;
    unsigned char *p = (unsigned char *)aKey;
    unsigned char *end;
#endif

    Error error = kErrorNone;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status = PSA_SUCCESS;

    VerifyOrExit(checkKeyUsage(aKeyUsage), error = kErrorInvalidArgs);
    VerifyOrExit(aKeyRef != nullptr && aKey != nullptr, error = kErrorInvalidArgs);

#if defined(CONFIG_OPENTHREAD_ECDSA)
    /* Check if key is ECDSA pair and extract private key from it since PSA expects it. */
    if (aKeyType == OT_CRYPTO_KEY_TYPE_ECDSA) {

        end = p + aKeyLen;
        int ret = mbedtls_asn1_get_tag(&p, end, &len,
                          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        VerifyOrExit(ret == 0, error = MbedTls::MapError(ret));

        end = p + len;
        ret = mbedtls_asn1_get_int(&p, end, &version);
        VerifyOrExit(ret == 0, error = MbedTls::MapError(ret));

        ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
        VerifyOrExit(ret == 0 || ret == 32, error = MbedTls::MapError(ret));

        aKey = p;
        aKeyLen = len;
    }
#endif

    psa_set_key_type(&attributes, toPsaKeyType(aKeyType));
    psa_set_key_algorithm(&attributes, toPsaAlgorithm(aKeyAlgorithm));
    psa_set_key_usage_flags(&attributes, toPsaKeyUsage(aKeyUsage));

    switch (aKeyPersistence) {
    case Storage::kTypePersistent:
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_id(&attributes, *aKeyRef);
        break;
    case Storage::kTypeVolatile:
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
        break;
    }

    status = psa_import_key(&attributes, aKey, aKeyLen, aKeyRef);
    psa_reset_key_attributes(&attributes);

exit:
    psa_reset_key_attributes(&attributes);

    if (error != kErrorNone)
    {
        return error;
    }

    return psaToOtError(status);
}

OT_TOOL_WEAK otError otPlatCryptoExportKey(otCryptoKeyRef aKeyRef, uint8_t *aBuffer, size_t aBufferLen,
                                           size_t *aKeyLen)
{
    Error error = kErrorNone;

    VerifyOrExit(aBuffer != nullptr && aKeyLen != nullptr, error = kErrorInvalidArgs);

    error = psaToOtError(psa_export_key(aKeyRef, aBuffer, aBufferLen, aKeyLen));

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoDestroyKey(otCryptoKeyRef aKeyRef)
{
    return psaToOtError(psa_destroy_key(aKeyRef));
}

OT_TOOL_WEAK bool otPlatCryptoHasKey(otCryptoKeyRef aKeyRef)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    status = psa_get_key_attributes(aKeyRef, &attributes);
    psa_reset_key_attributes(&attributes);

    return status == PSA_SUCCESS;
}

// AES Implementation
OT_TOOL_WEAK otError otPlatCryptoAesInit(otCryptoContext *aContext)
{
    Error error = kErrorNone;
    psa_key_id_t *keyRef;

    VerifyOrExit(aContext != nullptr, error = kErrorInvalidArgs);

    keyRef = static_cast<psa_key_id_t *>(aContext->mContext);
    *keyRef = PSA_KEY_ID_NULL;

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoAesSetKey(otCryptoContext *aContext, const otCryptoKey *aKey)
{
    Error error = kErrorNone;
    psa_key_id_t *keyRef;

    VerifyOrExit(checkContext(aContext, sizeof(psa_key_id_t)), error = kErrorInvalidArgs);
    VerifyOrExit(aKey != nullptr, error = kErrorInvalidArgs);

    keyRef = static_cast<psa_key_id_t *>(aContext->mContext);
    *keyRef = aKey->mKeyRef;

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoAesEncrypt(otCryptoContext *aContext, const uint8_t *aInput, uint8_t *aOutput)
{
    Error error = kErrorNone;
    const size_t blockSize = PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES);
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t *keyRef;
    size_t cipherLen;

    VerifyOrExit(checkContext(aContext, sizeof(psa_key_id_t)), error = kErrorInvalidArgs);
    VerifyOrExit(aInput != nullptr && aOutput != nullptr, error = kErrorInvalidArgs);

    keyRef = static_cast<psa_key_id_t *>(aContext->mContext);
    status = psa_cipher_encrypt(*keyRef, PSA_ALG_ECB_NO_PADDING, aInput, blockSize, aOutput,
                                blockSize, &cipherLen);

    error = psaToOtError(status);

exit:
    return error;
}


OT_TOOL_WEAK otError otPlatCryptoAesFree(otCryptoContext *aContext)
{
    OT_UNUSED_VARIABLE(aContext);

    return OT_ERROR_NONE;
}

#if !OPENTHREAD_RADIO

// HMAC implementations
OT_TOOL_WEAK otError otPlatCryptoHmacSha256Init(otCryptoContext *aContext)
{
    Error error = kErrorNone;
    psa_mac_operation_t *operation;

    VerifyOrExit(checkContext(aContext, sizeof(psa_mac_operation_t)), error = kErrorInvalidArgs);

    operation = static_cast<psa_mac_operation_t *>(aContext->mContext);

    *operation = psa_mac_operation_init();

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoHmacSha256Deinit(otCryptoContext *aContext)
{
    Error error = kErrorNone;
    psa_mac_operation_t *operation;

    VerifyOrExit(checkContext(aContext, sizeof(psa_mac_operation_t)), error = kErrorInvalidArgs);

    operation = static_cast<psa_mac_operation_t *>(aContext->mContext);

    error = psaToOtError(psa_mac_abort(operation));

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoHmacSha256Start(otCryptoContext *aContext, const otCryptoKey *aKey)
{
    Error error = kErrorNone;
    psa_mac_operation_t *operation;

    VerifyOrExit(checkContext(aContext, sizeof(psa_mac_operation_t)), error = kErrorInvalidArgs);
    VerifyOrExit(aKey != nullptr, error = kErrorInvalidArgs);

    operation = static_cast<psa_mac_operation_t *>(aContext->mContext);

    error = psaToOtError(psa_mac_sign_setup(operation, aKey->mKeyRef, PSA_ALG_HMAC(PSA_ALG_SHA_256)));

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoHmacSha256Update(otCryptoContext *aContext, const void *aBuf,
                     uint16_t aBufLength)
{
    Error error = kErrorNone;
    psa_mac_operation_t *operation;

    VerifyOrExit(checkContext(aContext, sizeof(psa_mac_operation_t)), error = kErrorInvalidArgs);
    VerifyOrExit(aBuf != nullptr, error = kErrorInvalidArgs);

    operation = static_cast<psa_mac_operation_t *>(aContext->mContext);

    error = psaToOtError(psa_mac_update(operation, (const uint8_t *)aBuf, aBufLength));

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoHmacSha256Finish(otCryptoContext *aContext, uint8_t *aBuf, size_t aBufLength)
{
    Error error = kErrorNone;
    psa_mac_operation_t *operation;
    size_t mac_length;

    VerifyOrExit(checkContext(aContext, sizeof(psa_mac_operation_t)), error = kErrorInvalidArgs);
    VerifyOrExit(aBuf != nullptr, error = kErrorInvalidArgs);

    operation = static_cast<psa_mac_operation_t *>(aContext->mContext);

    error = psaToOtError(psa_mac_sign_finish(operation, aBuf, aBufLength, &mac_length));

exit:
    return error;
}

// HKDF implementations
OT_TOOL_WEAK otError otPlatCryptoHkdfInit(otCryptoContext *aContext)
{
    Error error = kErrorNone;

    VerifyOrExit(checkContext(aContext, sizeof(HmacSha256::Hash)), error = kErrorInvalidArgs);

    new (aContext->mContext) HmacSha256::Hash();

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoHkdfExpand(otCryptoContext *aContext,
                                            const uint8_t   *aInfo,
                                            uint16_t         aInfoLength,
                                            uint8_t         *aOutputKey,
                                            uint16_t         aOutputKeyLength)
{
    Error             error = kErrorNone;
    HmacSha256        hmac;
    HmacSha256::Hash  hash;
    uint8_t           iter = 0;
    uint16_t          copyLength;
    HmacSha256::Hash *prk;

    VerifyOrExit(checkContext(aContext, sizeof(HmacSha256::Hash)), error = kErrorInvalidArgs);

    prk = static_cast<HmacSha256::Hash *>(aContext->mContext);

    // The aOutputKey is calculated as follows [RFC5889]:
    //
    //   N = ceil( aOutputKeyLength / HashSize)
    //   T = T(1) | T(2) | T(3) | ... | T(N)
    //   aOutputKey is first aOutputKeyLength of T
    //
    // Where:
    //   T(0) = empty string (zero length)
    //   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    //   T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    //   T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
    //   ...

    while (aOutputKeyLength > 0)
    {
        Key cryptoKey;

        cryptoKey.Set(prk->GetBytes(), sizeof(HmacSha256::Hash));
        hmac.Start(cryptoKey);

        if (iter != 0)
        {
            hmac.Update(hash);
        }

        hmac.Update(aInfo, aInfoLength);

        iter++;
        hmac.Update(iter);
        hmac.Finish(hash);

        copyLength = Min(aOutputKeyLength, static_cast<uint16_t>(sizeof(hash)));

        memcpy(aOutputKey, hash.GetBytes(), copyLength);
        aOutputKey += copyLength;
        aOutputKeyLength -= copyLength;
    }

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoHkdfExtract(otCryptoContext   *aContext,
                                             const uint8_t     *aSalt,
                                             uint16_t           aSaltLength,
                                             const otCryptoKey *aInputKey)
{
    Error             error = kErrorNone;
    HmacSha256        hmac;
    Key               cryptoKey;
    HmacSha256::Hash *prk;
    const LiteralKey  inputKey(*static_cast<const Key *>(aInputKey));

    VerifyOrExit(checkContext(aContext, sizeof(HmacSha256::Hash)), error = kErrorInvalidArgs);

    prk = static_cast<HmacSha256::Hash *>(aContext->mContext);

    cryptoKey.Set(aSalt, aSaltLength);
    // PRK is calculated as HMAC-Hash(aSalt, aInputKey)
    hmac.Start(cryptoKey);
    hmac.Update(inputKey.GetBytes(), inputKey.GetLength());
    hmac.Finish(*prk);

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoHkdfDeinit(otCryptoContext *aContext)
{
    Error             error = kErrorNone;
    HmacSha256::Hash *prk;

    VerifyOrExit(checkContext(aContext, sizeof(HmacSha256::Hash)), error = kErrorInvalidArgs);

    prk = static_cast<HmacSha256::Hash *>(aContext->mContext);
    prk->~Hash();
    aContext->mContext     = nullptr;
    aContext->mContextSize = 0;

exit:
    return error;
}

// SHA256 platform implementations
OT_TOOL_WEAK otError otPlatCryptoSha256Init(otCryptoContext *aContext)
{
    Error error = kErrorNone;
    psa_hash_operation_t *operation;

    VerifyOrExit(checkContext(aContext, sizeof(psa_hash_operation_t)), error = kErrorInvalidArgs);

    operation = static_cast<psa_hash_operation_t *>(aContext->mContext);
    *operation = psa_hash_operation_init();

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoSha256Deinit(otCryptoContext *aContext)
{
    Error error = kErrorNone;
    psa_hash_operation_t *operation;

    VerifyOrExit(checkContext(aContext, sizeof(psa_hash_operation_t)), error = kErrorInvalidArgs);

    operation = static_cast<psa_hash_operation_t *>(aContext->mContext);

    error = psaToOtError(psa_hash_abort(operation));

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoSha256Start(otCryptoContext *aContext)
{
    Error error = kErrorNone;
    psa_hash_operation_t *operation;

    VerifyOrExit(checkContext(aContext, sizeof(psa_hash_operation_t)), error = kErrorInvalidArgs);

    operation = static_cast<psa_hash_operation_t *>(aContext->mContext);

    error = psaToOtError(psa_hash_setup(operation, PSA_ALG_SHA_256));

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoSha256Update(otCryptoContext *aContext, const void *aBuf, uint16_t aBufLength)
{
    Error error = kErrorNone;
    psa_hash_operation_t *operation;

    VerifyOrExit(checkContext(aContext, sizeof(psa_hash_operation_t)), error = kErrorInvalidArgs);
    VerifyOrExit(aBuf != nullptr, error = kErrorInvalidArgs);

    operation = static_cast<psa_hash_operation_t *>(aContext->mContext);

    error = psaToOtError(psa_hash_update(operation, (const uint8_t *)aBuf, aBufLength));

exit:
    return error;
}

OT_TOOL_WEAK otError otPlatCryptoSha256Finish(otCryptoContext *aContext, uint8_t *aHash, uint16_t aHashSize)
{
    Error error = kErrorNone;
    psa_hash_operation_t *operation;
    size_t hashSize;

    VerifyOrExit(checkContext(aContext, sizeof(psa_hash_operation_t)), error = kErrorInvalidArgs);
    VerifyOrExit(aHash != nullptr, error = kErrorInvalidArgs);

    operation = static_cast<psa_hash_operation_t *>(aContext->mContext);

    error =  psaToOtError(psa_hash_finish(operation, aHash, aHashSize, &hashSize));

exit:
    return error;
}

OT_TOOL_WEAK void otPlatCryptoRandomInit(void)
{
    psa_crypto_init();
}

OT_TOOL_WEAK void otPlatCryptoRandomDeinit(void)
{
    // Intentionally empty
}

OT_TOOL_WEAK otError otPlatCryptoRandomGet(uint8_t *aBuffer, uint16_t aSize)
{
    return psaToOtError(psa_generate_random(aBuffer, aSize));
}

#if OPENTHREAD_CONFIG_ECDSA_ENABLE

OT_TOOL_WEAK otError otPlatCryptoEcdsaGenerateKey(otPlatCryptoEcdsaKeyPair *aKeyPair)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t keyId = 0;
    psa_status_t status;
    size_t exportedLen;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    status = psa_generate_key(&attributes, &keyId);
    VerifyOrExit(status == PSA_SUCCESS);

    status = psa_export_key(keyId, aKeyPair->mDerBytes, OT_CRYPTO_ECDSA_MAX_DER_SIZE,
                &exportedLen);
    VerifyOrExit(status == PSA_SUCCESS);

    aKeyPair->mDerLength = exportedLen;

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(keyId);

    return psaToOtError(status);
}

OT_TOOL_WEAK otError otPlatCryptoEcdsaSign(const otPlatCryptoEcdsaKeyPair *aKeyPair,
                  const otPlatCryptoSha256Hash *aHash,
                  otPlatCryptoEcdsaSignature *aSignature)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t keyId;
    psa_status_t status;
    size_t signatureLen;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    status = psa_import_key(&attributes, aKeyPair->mDerBytes, aKeyPair->mDerLength, &keyId);
    VerifyOrExit(status == PSA_SUCCESS);

    status = psa_sign_hash(keyId, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), aHash->m8,
                   OT_CRYPTO_SHA256_HASH_SIZE, aSignature->m8,
                   OT_CRYPTO_ECDSA_SIGNATURE_SIZE, &signatureLen);
    VerifyOrExit(status == PSA_SUCCESS);

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(keyId);

    return psaToOtError(status);
}

OT_TOOL_WEAK otError otPlatCryptoEcdsaVerify(const otPlatCryptoEcdsaPublicKey *aPublicKey,
                const otPlatCryptoSha256Hash *aHash,
                const otPlatCryptoEcdsaSignature *aSignature)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t keyId;
    psa_status_t status;
    uint8_t buffer[1 + OT_CRYPTO_ECDSA_PUBLIC_KEY_SIZE];

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    /*
     * `psa_import_key` expects a key format as specified by SEC1 &sect;2.3.3 for the
     * uncompressed representation of the ECPoint.
     */
    buffer[0] = 0x04;
    memcpy(buffer + 1, aPublicKey->m8, OT_CRYPTO_ECDSA_PUBLIC_KEY_SIZE);

    status = psa_import_key(&attributes, buffer, sizeof(buffer), &keyId);
    VerifyOrExit(status == PSA_SUCCESS);

    status = psa_verify_hash(keyId, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), aHash->m8,
                 OT_CRYPTO_SHA256_HASH_SIZE, aSignature->m8,
                 OT_CRYPTO_ECDSA_SIGNATURE_SIZE);
    VerifyOrExit(status == PSA_SUCCESS);

exit:
    psa_reset_key_attributes(&attributes);
    psa_destroy_key(keyId);

    return psaToOtError(status);
}

OT_TOOL_WEAK otError otPlatCryptoEcdsaGenerateAndImportKey(otCryptoKeyRef aKeyRef)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    psa_key_id_t keyId = static_cast<psa_key_id_t>(aKeyRef);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attributes, keyId);
    psa_set_key_bits(&attributes, 256);

    status = psa_generate_key(&attributes, &keyId);
    VerifyOrExit(status == PSA_SUCCESS);

exit:
    psa_reset_key_attributes(&attributes);

    return psaToOtError(status);
}

OT_TOOL_WEAK otError otPlatCryptoEcdsaExportPublicKey(otCryptoKeyRef aKeyRef,
                                                      otPlatCryptoEcdsaPublicKey *aPublicKey)
{
    psa_status_t status;
    size_t exportedLen;
    uint8_t buffer[1 + OT_CRYPTO_ECDSA_PUBLIC_KEY_SIZE];

    status = psa_export_public_key(aKeyRef, buffer, sizeof(buffer), &exportedLen);
    VerifyOrExit(status == PSA_SUCCESS);

    OT_ASSERT(exportedLen == sizeof(buffer));
    memcpy(aPublicKey->m8, buffer + 1, OT_CRYPTO_ECDSA_PUBLIC_KEY_SIZE);

exit:
    return psaToOtError(status);
}

OT_TOOL_WEAK otError otPlatCryptoEcdsaSignUsingKeyRef(otCryptoKeyRef aKeyRef,
                     const otPlatCryptoSha256Hash *aHash,
                     otPlatCryptoEcdsaSignature *aSignature)
{
    psa_status_t status;
    size_t signatureLen;

    status = psa_sign_hash(aKeyRef, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), aHash->m8,
                   OT_CRYPTO_SHA256_HASH_SIZE, aSignature->m8,
                   OT_CRYPTO_ECDSA_SIGNATURE_SIZE, &signatureLen);
    VerifyOrExit(status == PSA_SUCCESS);

    OT_ASSERT(signatureLen == OT_CRYPTO_ECDSA_SIGNATURE_SIZE);

exit:
    return psaToOtError(status);
}

OT_TOOL_WEAK otError otPlatCryptoEcdsaVerifyUsingKeyRef(otCryptoKeyRef aKeyRef,
                       const otPlatCryptoSha256Hash *aHash,
                       const otPlatCryptoEcdsaSignature *aSignature)
{
    psa_status_t status;

    status = psa_verify_hash(aKeyRef, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), aHash->m8,
                 OT_CRYPTO_SHA256_HASH_SIZE, aSignature->m8,
                 OT_CRYPTO_ECDSA_SIGNATURE_SIZE);
    VerifyOrExit(status == PSA_SUCCESS);

exit:
    return psaToOtError(status);
}

OT_TOOL_WEAK otError otPlatCryptoEcdsaGetPublicKey(const otPlatCryptoEcdsaKeyPair *aKeyPair,
                                                   otPlatCryptoEcdsaPublicKey     *aPublicKey)
{
    Error                error = kErrorNone;
    mbedtls_pk_context   pk;
    mbedtls_ecp_keypair *keyPair;
    int                  ret;

    mbedtls_pk_init(&pk);

    VerifyOrExit(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0, error = kErrorFailed);

#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
    VerifyOrExit(mbedtls_pk_parse_key(&pk, aKeyPair->mDerBytes, aKeyPair->mDerLength, nullptr, 0,
                                      MbedTls::CryptoSecurePrng, nullptr) == 0,
                 error = kErrorParse);
#else
    VerifyOrExit(mbedtls_pk_parse_key(&pk, aKeyPair->mDerBytes, aKeyPair->mDerLength, nullptr, 0) == 0,
                 error = kErrorParse);
#endif

    keyPair = mbedtls_pk_ec(pk);

    ret = mbedtls_mpi_write_binary(&keyPair->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), aPublicKey->m8,
                                   Ecdsa::P256::kMpiSize);
    VerifyOrExit(ret == 0, error = MbedTls::MapError(ret));

    ret = mbedtls_mpi_write_binary(&keyPair->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y),
                                   aPublicKey->m8 + Ecdsa::P256::kMpiSize, Ecdsa::P256::kMpiSize);
    VerifyOrExit(ret == 0, error = MbedTls::MapError(ret));

exit:
    mbedtls_pk_free(&pk);
    return error;
}

#endif // #if OPENTHREAD_CONFIG_ECDSA_ENABLE

#endif // #if !OPENTHREAD_RADIO

#if OPENTHREAD_FTD

OT_TOOL_WEAK otError otPlatCryptoPbkdf2GenerateKey(const uint8_t *aPassword,
                                                   uint16_t       aPasswordLen,
                                                   const uint8_t *aSalt,
                                                   uint16_t       aSaltLen,
                                                   uint32_t       aIterationCounter,
                                                   uint16_t       aKeyLen,
                                                   uint8_t       *aKey)
{
#if (MBEDTLS_VERSION_NUMBER >= 0x03050000)
    const size_t kBlockSize = MBEDTLS_CMAC_MAX_BLOCK_SIZE;
#else
    const size_t kBlockSize = MBEDTLS_CIPHER_BLKSIZE_MAX;
#endif
    uint8_t  prfInput[OT_CRYPTO_PBDKF2_MAX_SALT_SIZE + 4]; // Salt || INT(), for U1 calculation
    long     prfOne[kBlockSize / sizeof(long)];
    long     prfTwo[kBlockSize / sizeof(long)];
    long     keyBlock[kBlockSize / sizeof(long)];
    uint32_t blockCounter = 0;
    uint8_t *key          = aKey;
    uint16_t keyLen       = aKeyLen;
    uint16_t useLen       = 0;
    Error    error        = kErrorNone;
    int      ret;

    OT_ASSERT(aSaltLen <= sizeof(prfInput));
    memcpy(prfInput, aSalt, aSaltLen);
    OT_ASSERT(aIterationCounter % 2 == 0);
    aIterationCounter /= 2;

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // limit iterations to avoid OSS-Fuzz timeouts
    aIterationCounter = 2;
#endif

    while (keyLen)
    {
        ++blockCounter;
        prfInput[aSaltLen + 0] = static_cast<uint8_t>(blockCounter >> 24);
        prfInput[aSaltLen + 1] = static_cast<uint8_t>(blockCounter >> 16);
        prfInput[aSaltLen + 2] = static_cast<uint8_t>(blockCounter >> 8);
        prfInput[aSaltLen + 3] = static_cast<uint8_t>(blockCounter);

        // Calculate U_1
        ret = mbedtls_aes_cmac_prf_128(aPassword, aPasswordLen, prfInput, aSaltLen + 4,
                                       reinterpret_cast<uint8_t *>(keyBlock));
        VerifyOrExit(ret == 0, error = MbedTls::MapError(ret));

        // Calculate U_2
        ret = mbedtls_aes_cmac_prf_128(aPassword, aPasswordLen, reinterpret_cast<const uint8_t *>(keyBlock), kBlockSize,
                                       reinterpret_cast<uint8_t *>(prfOne));
        VerifyOrExit(ret == 0, error = MbedTls::MapError(ret));

        for (uint32_t j = 0; j < kBlockSize / sizeof(long); ++j)
        {
            keyBlock[j] ^= prfOne[j];
        }

        for (uint32_t i = 1; i < aIterationCounter; ++i)
        {
            // Calculate U_{2 * i - 1}
            ret = mbedtls_aes_cmac_prf_128(aPassword, aPasswordLen, reinterpret_cast<const uint8_t *>(prfOne),
                                           kBlockSize, reinterpret_cast<uint8_t *>(prfTwo));
            VerifyOrExit(ret == 0, error = MbedTls::MapError(ret));
            // Calculate U_{2 * i}
            ret = mbedtls_aes_cmac_prf_128(aPassword, aPasswordLen, reinterpret_cast<const uint8_t *>(prfTwo),
                                           kBlockSize, reinterpret_cast<uint8_t *>(prfOne));
            VerifyOrExit(ret == 0, error = MbedTls::MapError(ret));

            for (uint32_t j = 0; j < kBlockSize / sizeof(long); ++j)
            {
                keyBlock[j] ^= prfOne[j] ^ prfTwo[j];
            }
        }

        useLen = Min(keyLen, static_cast<uint16_t>(kBlockSize));
        memcpy(key, keyBlock, useLen);
        key += useLen;
        keyLen -= useLen;
    }

exit:
    return error;
}

#endif // #if OPENTHREAD_FTD

#endif // #if OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_PSA
