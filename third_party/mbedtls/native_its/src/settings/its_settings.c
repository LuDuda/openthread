/*
 *    Copyright (c) 2024, The OpenThread Authors.
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
 *   This file implements the Crypto TBD TBD..
 */

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_PSA

#include "psa/error.h"
#include "psa/internal_trusted_storage.h"

//---------------------------------------------------------------------------------------------------------------------
// Example implementation of crypto storage (Native ITS) platform APIs.

#if !OPENTHREAD_RADIO

+// #define ITS_MAX_ENTRY_SIZE 128
+// static uint16_t getKeyFromPsaUid(psa_storage_uid_t uid)
+// {
+//     return OT_SETTINGS_KEY_PSA_ITS_MIN + (uid) - OPENTHREAD_CONFIG_PSA_ITS_NVM_OFFSET;
+// }
+
+// static psa_status_t otErrorToPsa(otError error)
+// {
+//     switch (error)
+//     {
+//     case OT_ERROR_NONE:
+//         return PSA_SUCCESS;
+//     case OT_ERROR_NOT_FOUND:
+//         return PSA_ERROR_DOES_NOT_EXIST;
+//     default:
+//         return PSA_ERROR_GENERIC_ERROR;
+//     }
+// }
+
+// extern "C" psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info)
+// {
+//     if (!p_info)
+//     {
+//         return PSA_ERROR_INVALID_ARGUMENT;
+//     }
+
+//     size_t length = 0;
+//     psa_status_t status = psa_its_get(uid, 0, 0, nullptr, &length);
+
+//     if (status == PSA_SUCCESS)
+//     {
+//         p_info->size  = static_cast<uint32_t>(length);
+//         p_info->flags = PSA_STORAGE_FLAG_NONE; 
+//     }
+
+//     return status; 
+// }
+
+// extern "C" psa_status_t psa_its_get(psa_storage_uid_t  uid,
+//                                     uint32_t           data_offset,
+//                                     uint32_t           data_length,
+//                                     void              *p_data,
+//                                     size_t            *p_data_length)
+// {
+//     if (!p_data_length || ((p_data == nullptr) && (data_length > 0)))
+//     {
+//         return PSA_ERROR_INVALID_ARGUMENT; 
+//     }
+
+//     uint8_t tmpBuffer[ITS_MAX_ENTRY_SIZE];
+//     uint16_t actualLen = ITS_MAX_ENTRY_SIZE;  
+
+//     otError error = otPlatSettingsGet(nullptr,
+//                                       getKeyFromPsaUid(uid),
+//                                       0,
+//                                       tmpBuffer,
+//                                       &actualLen);
+
+//     psa_status_t status = otErrorToPsa(error);
+//     if (status != PSA_SUCCESS)
+//     {
+//         return status;
+//     }
+
+//     if (data_offset > actualLen)
+//     {
+//         return PSA_ERROR_INVALID_ARGUMENT;
+//     }
+
+//     uint32_t bytesToCopy = data_length;
+//     if (data_offset + data_length > actualLen)
+//     {
+//         bytesToCopy = actualLen - data_offset;
+//     }
+
+//     if (bytesToCopy > 0)
+//     {
+//         memcpy(p_data, &tmpBuffer[data_offset], bytesToCopy);
+//     }
+
+//     *p_data_length = bytesToCopy;
+
+//     return PSA_SUCCESS;
+// }
+
+// extern "C" psa_status_t psa_its_set(psa_storage_uid_t           uid,
+//                                     uint32_t                    data_length,
+//                                     const void                 *p_data, 
+//                                     psa_storage_create_flags_t  create_flags)
+// {
+//     OT_UNUSED_VARIABLE(create_flags);
+
+//     if ((p_data == nullptr && data_length > 0) || (data_length > ITS_MAX_ENTRY_SIZE))
+//     {
+//         return PSA_ERROR_INVALID_ARGUMENT;
+//     }
+
+//     otError error = otPlatSettingsAdd(nullptr,
+//                                       getKeyFromPsaUid(uid),
+//                                       static_cast<const uint8_t *>(p_data),
+//                                       static_cast<uint16_t>(data_length));
+
+//     return otErrorToPsa(error);
+// }
+
+// extern "C" psa_status_t psa_its_remove(psa_storage_uid_t uid)
+// {
+//     otError error = OT_ERROR_NONE;
+
+//     error = otPlatSettingsDelete(NULL, getKeyFromPsaUid(uid), 0);
+
+//     return (error == OT_ERROR_NONE) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
+// }

#endif // #if !OPENTHREAD_RADIO

#endif // #if OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_PSA
