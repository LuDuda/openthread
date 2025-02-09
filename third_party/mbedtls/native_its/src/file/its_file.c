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

//#if OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_PSA

#include "psa/error.h"
#include "psa/internal_trusted_storage.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// #if !OPENTHREAD_RADIO

#define VerifyOrExit(aCondition, aAction) \
    do                                    \
    {                                     \
        if (!(aCondition))                \
        {                                 \
            aAction;                      \
            goto exit;                    \
        }                                 \
    } while (0)


/**
 * @def ITS_FILE_DEFAULT_FILE_PREFIX
 *
 * The default directory prefix if the user does not override it by changing
 * the global variable @c gItsFileNamePrefix.
 */
#define ITS_FILE_DEFAULT_FILE_PREFIX "tmp/"

/**
 * @def ITS_FILE_PATH_MAX
 *
 * The maximum allowed length (in bytes) for file paths.
 */
#define ITS_FILE_PATH_MAX 256

/**
 * @def ITS_DIR_MODE
 *
 * The mode used when creating directories (0777 gives full permissions to owner,
 * group, and others).
 */
#define ITS_DIR_MODE 0777

/**
 * @def ITS_FILE_HEADER_SIZE
 *
 * The size (in bytes) of the file header: 4 bytes for flags plus 4 bytes for total data length.
 */
#define ITS_FILE_HEADER_SIZE (sizeof(uint32_t) + sizeof(uint32_t))

/**
 * @def ITS_FILE_NAME_FORMAT
 *
 * The format string for building the file path.
 */
#define ITS_FILE_NAME_FORMAT "%suid_%llu.psa_its"

/**
 * A global variable that determines where PSA ITS files are stored.
 *
 * By default, it is @ref ITS_FILE_DEFAULT_FILE_PREFIX. You can override
 * it at runtime:
 * @code
 *   gItsFileNamePrefix = "tmp/its_node_3_offset_12";
 * @endcode
 */
const char *gItsFileNamePrefix = ITS_FILE_DEFAULT_FILE_PREFIX;


/**
 * Ensures that the directory (specified by `gItsFileNamePrefix`) exists.
 */
bool EnsureDirectoryExists(void)
{
    bool        success = true;
    struct stat st;

    // 1) Check if path already exists
    if (stat(gItsFileNamePrefix, &st) == 0)
    {
        // Exists - must be a directory
        if (!S_ISDIR(st.st_mode))
        {
            success = false;
        }
    }
    else
    {
        // Path doesn't exist, attempt to create one.
        if (mkdir(gItsFileNamePrefix, ITS_DIR_MODE) != 0)
        {
            // Retry with stat again.
            if (stat(gItsFileNamePrefix, &st) != 0 || !S_ISDIR(st.st_mode))
            {
                success = false;
            }
        }
    }

    return success;
}

/**
 * Builds the file path for a given UID.
 * Returns 0 on success, -1 on error.
 */
static int buildFilePath(psa_storage_uid_t aUid, char *aPath, size_t aPathSize)
{
    int result = 0;

    // Attempt to format
    int ret = snprintf(aPath, aPathSize, ITS_FILE_NAME_FORMAT,
                       gItsFileNamePrefix, (unsigned long long)aUid);

    // If ret < 0 or ret >= aPathSize, return an error.
    VerifyOrExit((ret >= 0) && ((size_t)ret < aPathSize), result = -1);

exit:
    return result;
}

/**
 * Reads an 8-byte header from the given file:
 * - 4 bytes for flags (psa_storage_create_flags_t)
 * - 4 bytes for data length
 *
 * Returns 0 on success, -1 on error.
 */
static int readHeader(FILE *aFile, psa_storage_create_flags_t *aFlags, uint32_t *aDataLen)
{
    int result = 0;
    uint32_t flagsTmp;
    uint32_t lenTmp;

    // Read flags
    VerifyOrExit(fread(&flagsTmp, sizeof(flagsTmp), 1, aFile) == 1, result = -1);

    // Read length
    VerifyOrExit(fread(&lenTmp, sizeof(lenTmp), 1, aFile) == 1, result = -1);

    *aFlags   = flagsTmp;
    *aDataLen = lenTmp;

exit:
    return result;
}

/**
 * Writes an 8-byte header to the given file:
 * - 4 bytes for flags
 * - 4 bytes for data length
 *
 * Returns 0 on success, -1 on error.
 */
static int writeHeader(FILE *aFile, psa_storage_create_flags_t aFlags, uint32_t aDataLen)
{
    int result = 0;

    // Write flags
    VerifyOrExit(fwrite(&aFlags, sizeof(aFlags), 1, aFile) == 1, result = -1);

    // Write length
    VerifyOrExit(fwrite(&aDataLen, sizeof(aDataLen), 1, aFile) == 1, result = -1);

exit:
    return result;
}

psa_status_t psa_its_set(psa_storage_uid_t           uid,
                         uint32_t                    data_length,
                         const void                 *p_data,
                         psa_storage_create_flags_t  create_flags)
{
    psa_status_t status = PSA_SUCCESS;
    FILE        *file   = NULL;
    char         path[ITS_FILE_PATH_MAX];

    // Validate arguments
    VerifyOrExit(!(p_data == NULL && data_length > 0), status = PSA_ERROR_INVALID_ARGUMENT);
    // Only NONE or WRITE_ONCE => no other flags supported
    VerifyOrExit((create_flags & ~(PSA_STORAGE_FLAG_WRITE_ONCE)) == 0, status = PSA_ERROR_NOT_SUPPORTED);

    // Ensure directory
    VerifyOrExit(EnsureDirectoryExists(), status = PSA_ERROR_GENERIC_ERROR);

    // Build path
    VerifyOrExit(buildFilePath(uid, path, sizeof(path)) == 0, status = PSA_ERROR_GENERIC_ERROR);

    // If file exists, check WRITE_ONCE
    file = fopen(path, "rb");
    if (file)
    {
        psa_storage_create_flags_t oldFlags;
        uint32_t                   oldLen;

        if (readHeader(file, &oldFlags, &oldLen) == 0)
        {
            VerifyOrExit(!(oldFlags & PSA_STORAGE_FLAG_WRITE_ONCE), status = PSA_ERROR_NOT_PERMITTED);
        }

        fclose(file);
        file = NULL;
    }

    // Create/overwrite
    file = fopen(path, "wb");
    VerifyOrExit(file != NULL, status = PSA_ERROR_GENERIC_ERROR);

    // Write header
    VerifyOrExit(writeHeader(file, create_flags, data_length) == 0, status = PSA_ERROR_GENERIC_ERROR);

    // Write data
    if (data_length > 0 && p_data != NULL)
    {
        size_t written = fwrite(p_data, 1, data_length, file);
        VerifyOrExit(written == data_length, status = PSA_ERROR_GENERIC_ERROR);
    }

exit:
    if (file)
    {
        fclose(file);
    }

    return status;
}

psa_status_t psa_its_get(psa_storage_uid_t  uid,
                         uint32_t           data_offset,
                         uint32_t           data_length,
                         void              *p_data,
                         size_t            *p_data_length)
{
    psa_status_t status = PSA_SUCCESS;
    FILE        *file   = NULL;
    char         path[ITS_FILE_PATH_MAX];

    // Validate pointers
    VerifyOrExit(p_data_length != NULL, status = PSA_ERROR_INVALID_ARGUMENT);

    if (data_length > 0)
    {
        VerifyOrExit(p_data != NULL, status = PSA_ERROR_INVALID_ARGUMENT);
    }

    VerifyOrExit(buildFilePath(uid, path, sizeof(path)) == 0, status = PSA_ERROR_GENERIC_ERROR);

    file = fopen(path, "rb");
    VerifyOrExit(file != NULL, status = PSA_ERROR_DOES_NOT_EXIST);

    {
        psa_storage_create_flags_t flags;
        uint32_t                   totalLen;

        VerifyOrExit(readHeader(file, &flags, &totalLen) == 0, status = PSA_ERROR_GENERIC_ERROR);

        // offset check
        VerifyOrExit(data_offset <= totalLen, status = PSA_ERROR_INVALID_ARGUMENT);

        // read portion
        {
            size_t available = totalLen - data_offset;
            size_t toCopy    = (data_length <= available) ? data_length : available;

            VerifyOrExit(fseek(file, data_offset, SEEK_CUR) == 0, status = PSA_ERROR_GENERIC_ERROR);

            if (toCopy > 0 && p_data != NULL)
            {
                VerifyOrExit(fread(p_data, 1, toCopy, file) == toCopy, status = PSA_ERROR_GENERIC_ERROR);
            }

            *p_data_length = toCopy;
        }
    }

exit:
    if (file)
    {
        fclose(file);
    }
    return status;
}

psa_status_t psa_its_get_info(psa_storage_uid_t          uid,
                              struct psa_storage_info_t *p_info)
{
    psa_status_t status = PSA_SUCCESS;
    FILE        *file   = NULL;
    char         path[ITS_FILE_PATH_MAX];

    VerifyOrExit(p_info != NULL, status = PSA_ERROR_INVALID_ARGUMENT);

    VerifyOrExit(buildFilePath(uid, path, sizeof(path)) == 0, status = PSA_ERROR_GENERIC_ERROR);

    file = fopen(path, "rb");
    VerifyOrExit(file != NULL, status = PSA_ERROR_DOES_NOT_EXIST);

    {
        psa_storage_create_flags_t flags;
        uint32_t                   totalLen;
        VerifyOrExit(readHeader(file, &flags, &totalLen) == 0, status = PSA_ERROR_GENERIC_ERROR);

        p_info->size  = totalLen;
        p_info->flags = flags;
    }

exit:
    if (file)
    {
        fclose(file);
    }
    return status;
}

psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
    psa_status_t status = PSA_SUCCESS;
    FILE        *file   = NULL;
    char         path[ITS_FILE_PATH_MAX];

    VerifyOrExit(buildFilePath(uid, path, sizeof(path)) == 0, status = PSA_ERROR_GENERIC_ERROR);

    file = fopen(path, "rb");
    VerifyOrExit(file != NULL, status = PSA_ERROR_DOES_NOT_EXIST);

    {
        psa_storage_create_flags_t flags;
        uint32_t                   totalLen;
        VerifyOrExit(readHeader(file, &flags, &totalLen) == 0, status = PSA_ERROR_GENERIC_ERROR);

        // If WRITE_ONCE is set, we cannot remove it.
        VerifyOrExit(!(flags & PSA_STORAGE_FLAG_WRITE_ONCE), status = PSA_ERROR_NOT_PERMITTED);
    }

    fclose(file);
    file = NULL;

    VerifyOrExit((unlink(path) == 0), status = PSA_ERROR_GENERIC_ERROR);

exit:
    if (file)
    {
        fclose(file);
    }
    return status;
}

// #endif // #if !OPENTHREAD_RADIO

// #endif // #if OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_PSA
