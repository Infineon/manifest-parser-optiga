/**
* \copyright
* MIT License
*
* Copyright (c) 2019 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
* \endcopyright
*
* \author Infineon Technologies AG
*
* \file optiga_manifest_parser.h
*
*/
#include <stdint.h>


/*
 * Signature Algorithm Part
 */
typedef enum signature_algo
{
	eINVALID_SIGNATURE           = 0x00,
	eES_SHA                      = -7,
	eRSA_SSA_PKCS1_V1_5_SHA_256  = -65700,
}signature_algo_t;

/*
 * Digest Algorithm Part
 */
typedef enum digest_algo
{
	eINVALID_DIGEST              = 0x00,
	eSHA_256                     = 41,
}digest_algo_t;


typedef enum optiga_manifest_error
{
	OPTIGA_MANIFEST_OK = 0x00,
	OPTIGA_MANIFEST_BAD_PARAMETERS = 0x01,
	OPTIGA_MANIFEST_SIGNATURE_CODE_IS_TOO_LONG = 0x02,
	OPTIGA_MANIFEST_ENCODED_SIGNATURE_LENGTH_TOO_LONG = 0x03,
	OPTIGA_MANIFEST_INVALID_SIGNATURE_ALGORITHM = 0x04,
	OPTIGA_MANIFEST_INVALID_TRUST_ANCHOR = 0x05,
	OPTIGA_MANIFEST_UNSUPPORTED_MANIFEST_VERSION = 0x06,
	OPTIGA_MANIFEST_ENCODED_DIGEST_LENGTH_TOO_LONG = 0x07,
	OPTIGA_MANIFEST_INVALID_DIGEST_ALGORITHM = 0x08,
	OPTIGA_MANIFEST_INVALID_TARGET_OID = 0x09,
	OPTIGA_MANIFEST_LENGTHS_DONT_MATCH = 0x0a,
}optiga_parser_error_t;

typedef struct optiga_manifest
{
	uint8_t version;
	uint16_t payload_version;
	uint16_t payload_length;
	uint16_t trust_anchor_oid;
	uint16_t target_oid;
	uint16_t offset_in_oid;
	signature_algo_t signature_algo;
	uint8_t* p_signature;
	uint16_t signature_length;
	digest_algo_t digest_algo;
	uint8_t* p_digest;
	uint16_t digest_length;
	uint8_t* p_raw_manifest;
	uint16_t raw_manifest_length;
	uint16_t write_type;
} optiga_manifest_t;


char* optiga_manifest_get_name_by_digest(digest_algo_t digest_algo);
char* optiga_manifest_get_name_by_signature(signature_algo_t signature_algo);
optiga_parser_error_t optiga_manifest_parse_raw(uint8_t* p_in, uint16_t in_len, optiga_manifest_t* p_out);
