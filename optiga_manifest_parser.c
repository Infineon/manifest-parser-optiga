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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cbor.h"
#include "optiga_manifest_parser.h"


#define PROTECT_UPDATE_MANIFEST_VERSION				(1U)
#define TA_1                       					0xE0E8
#define TA_2                       					0xE0E9
#define TA_3                      			 		0xE0EF
#define TA_4                       					0xE0E0
#define TA_5                       					0xE0E1
#define TA_6                       					0xE0E2
#define TA_7                       					0xE0E3

#define LEAST_UPDATABLE_TARGET_OID                  0xE0C0
#define LAST_UPDATABLE_TARGET_OID                   0xF1E1
#define COSE										0x04

extern inline uint32_t cbor_decode_data(uint8_t* buffer, uint16_t* offset, uint8_t major_type);
extern inline uint32_t cbor_get_array_of_data(uint8_t* buffer, uint16_t* offset);
extern inline uint32_t cbor_get_unsigned_integer( uint8_t* buffer, uint16_t* offset );
extern inline int32_t cbor_get_signed_integer( uint8_t* p_buffer, uint16_t* p_offset);
extern inline uint32_t cbor_get_byte_string( uint8_t* buffer, uint16_t* offset );
extern inline uint32_t cbor_get_mapped(uint8_t* p_buffer, uint8_t* p_map_number, uint32_t* p_key_data_item, void * p_value_data_item, uint16_t value_data_item_len, uint16_t* p_offset, uint8_t value_data_type);



typedef struct map_algo
{
	char*				name;
	int32_t             code;
}map_algo_t;

/*
 * Add new signature algorithms here
 */
#define MAXIMUM_SIGNATURE_LENGTH 0x100
map_algo_t map_signature_algo[] =
{
	// By adding new algorithms here, consider updating the MAXIMUM_SIGNATURE_LENGTH macro
	{ "ES_SHA", eES_SHA},
	{ "RSA_SSA_PKCS1_V1_5_SHA_256", eRSA_SSA_PKCS1_V1_5_SHA_256}
};

/*
 * Add new hashes here
 */
#define MAXIMUM_DIGEST_LENGTH 0x20
map_algo_t map_digest_algo[] =
{
	// By adding new algorithms here, consider updating the MAXIMUM_DIGEST_LENGTH macro
	{"SHA256", eSHA_256}
};

static char* optiga_manifest_get_name_by_code(void* p_map, int32_t code)
{
	map_algo_t* _p_map = (map_algo_t*)p_map;
	if ( _p_map == NULL )
		return "INVALID";

	for (int i = 0; i < (sizeof(_p_map)/2); i++)
	{
		if (_p_map[i].code == code)
		{
			return _p_map[i].name;
		}
	}

	return "INVALID";
}

char* optiga_manifest_get_name_by_digest(digest_algo_t digest_algo)
{
	return (optiga_manifest_get_name_by_code(map_digest_algo, digest_algo));
}
char* optiga_manifest_get_name_by_signature(signature_algo_t signature_algo)
{
	return (optiga_manifest_get_name_by_code(map_signature_algo, signature_algo));
}


optiga_parser_error_t optiga_manifest_parse_raw(uint8_t* p_in, uint16_t in_len, optiga_manifest_t* p_out)
{
	// Non-zero value means error
	optiga_parser_error_t err_code = OPTIGA_MANIFEST_OK;
	uint32_t temp_data = 0;
	uint16_t offset = 0;
	do
	{
		if ( ( NULL == p_in ) || ( 0 == in_len ) || ( NULL == p_out ) )
		{
			err_code = OPTIGA_MANIFEST_BAD_PARAMETERS;
			break;
		}

		// Assign a raw values to the manifest structure
		p_out->p_raw_manifest = p_in;
		p_out->raw_manifest_length = in_len;

		// 1.COSE
		if ( COSE != cbor_get_array_of_data(p_in, &offset) )
		{
			err_code = OPTIGA_MANIFEST_BAD_PARAMETERS;
			break;
		}

		// 2.protected signed header trust
		temp_data = cbor_get_byte_string(p_in, &offset);
		temp_data = cbor_get_mapped(p_in, NULL, NULL, &p_out->signature_algo, 0x01, &offset, CBOR_MAJOR_TYPE_1);

		// 3.unprotected -signed header Trust
		// Trust Anchor OID
		cbor_get_mapped(p_in, NULL, NULL, (uint8_t*)&p_out->trust_anchor_oid, 0x02, &offset, CBOR_MAJOR_TYPE_2);

		// Trust Anchor OID should be more than a first certificate slot and less than
		if (p_out->trust_anchor_oid != TA_1 && p_out->trust_anchor_oid != TA_2 &&
			p_out->trust_anchor_oid != TA_3 && p_out->trust_anchor_oid != TA_4 &&
			p_out->trust_anchor_oid != TA_5 && p_out->trust_anchor_oid != TA_6 && p_out->trust_anchor_oid != TA_7)
		{
			err_code = OPTIGA_MANIFEST_INVALID_TRUST_ANCHOR;
			break;
		}

		// 4.Payload
		temp_data = cbor_get_byte_string(p_in, &offset);

		// 4.1 Trust manifest
		temp_data = cbor_get_array_of_data(p_in, &offset);

		// manifest version
		// Should be equal to PROTECT_UPDATE_MANIFEST_VERSION
		if (PROTECT_UPDATE_MANIFEST_VERSION != (p_out->version = cbor_get_unsigned_integer(p_in, &offset)))
		{
			err_code = OPTIGA_MANIFEST_UNSUPPORTED_MANIFEST_VERSION;
			break;
		}
		offset+=2;
		temp_data = cbor_get_array_of_data(p_in,&offset);

		temp_data = cbor_get_signed_integer(p_in, &offset);

		p_out->payload_length = cbor_get_unsigned_integer(p_in, &offset);
		p_out->payload_version = cbor_get_unsigned_integer(p_in, &offset);

		temp_data = cbor_get_array_of_data(p_in, &offset);
		p_out->offset_in_oid = cbor_get_unsigned_integer(p_in, &offset);
		p_out->write_type = cbor_get_unsigned_integer(p_in, &offset);;

		// Both should be equal to 2
		temp_data = cbor_get_array_of_data(p_in, &offset);
		temp_data = cbor_get_array_of_data(p_in, &offset);
		// Skip one byte
		temp_data = cbor_get_signed_integer(p_in, &offset);

		// Digest length
		temp_data = cbor_get_byte_string(p_in, &offset);

		// Should return 2
		cbor_get_array_of_data(p_in, &offset);

		// Digest algorithm
		p_out->digest_algo = cbor_get_unsigned_integer(p_in, &offset);
		if ( eINVALID_DIGEST == p_out->digest_algo)
		{
			err_code = OPTIGA_MANIFEST_INVALID_DIGEST_ALGORITHM;
			break;
		}

		// Digest length
		p_out->digest_length = cbor_get_byte_string(p_in, &offset);
		if ( MAXIMUM_DIGEST_LENGTH < p_out->digest_length)
		{
			err_code = OPTIGA_MANIFEST_ENCODED_DIGEST_LENGTH_TOO_LONG;
			break;
		}
		// Digest
		p_out->p_digest = &p_in[offset];
		offset += p_out->digest_length;
		// Skip one byte
		offset += 1;

		// Target OID
		cbor_get_array_of_data(p_in, &offset);
		cbor_get_byte_string(p_in, &offset);
		cbor_get_byte_string(p_in, &offset);
		p_out->target_oid = (p_in[offset] << 8) & 0xFF00;
		offset++;
		p_out->target_oid +=  p_in[offset];
		offset++;
		if (p_out->target_oid < LEAST_UPDATABLE_TARGET_OID ||
			p_out->target_oid > LAST_UPDATABLE_TARGET_OID)
		{
			err_code = OPTIGA_MANIFEST_INVALID_TARGET_OID;
			break;
		}

		// Signature
		p_out->signature_length = cbor_get_byte_string(p_in, &offset);
		if (MAXIMUM_SIGNATURE_LENGTH < p_out->signature_length)
		{
			err_code = OPTIGA_MANIFEST_INVALID_TARGET_OID;
			break;
		}
		p_out->p_signature = &p_in[offset];
		if ((p_out->p_signature + p_out->signature_length) != (p_in + in_len))
		{
			err_code = OPTIGA_MANIFEST_LENGTHS_DONT_MATCH;
			break;
		}

	}while(0);

	if (err_code != OPTIGA_MANIFEST_OK)
	{
		p_out->digest_algo = 0;
		p_out->digest_length = 0;
		p_out->offset_in_oid = 0;
		p_out->p_digest = NULL;
		p_out->p_raw_manifest = NULL;
		p_out->p_signature = NULL;
		p_out->payload_length = 0;
		p_out->payload_version = 0;
		p_out->raw_manifest_length = 0;
		p_out->signature_algo = 0;
		p_out->signature_length = 0;
		p_out->target_oid= 0;
		p_out->trust_anchor_oid = 0;
		p_out->version = 0;
		p_out->write_type = 0;
	}

	return err_code;
}
