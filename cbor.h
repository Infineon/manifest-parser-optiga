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
* \file cbor.h
*
*/
#include <stdint.h>

/*
 * CBOR types
 */
#define CBOR_MAJOR_TYPE_0                   (0x00)
#define CBOR_MAJOR_TYPE_1                   (0x20)
#define CBOR_MAJOR_TYPE_2                   (0x40)
#define CBOR_MAJOR_TYPE_3                   (0x60)
#define CBOR_MAJOR_TYPE_4                   (0x80)
#define CBOR_MAJOR_TYPE_5					(0xA0)
#define CBOR_MAJOR_TYPE_7                   (0xF6)

#define CBOR_ADDITIONAL_TYPE_0x17           (0x17)
#define CBOR_ADDITIONAL_TYPE_0x18           (0x18)
#define CBOR_ADDITIONAL_TYPE_0x19           (0x19)
#define CBOR_ADDITIONAL_TYPE_0x1A           (0x1A)

inline uint32_t cbor_decode_data(uint8_t* p_buffer, uint16_t* p_offset, uint8_t major_type)
{
	uint32_t value = 0;

	value = ( p_buffer[*p_offset] & ( ( uint32_t )( ~major_type ) ) );
	(*p_offset)++;

	if ( value == CBOR_ADDITIONAL_TYPE_0x18 )
	{
		value = p_buffer[*p_offset];
		( *p_offset )++;
	}
	else if ( value == CBOR_ADDITIONAL_TYPE_0x19 )
	{
		value = (p_buffer[*p_offset] << 8)  & 0xFF00;
		( *p_offset )++;
		value += p_buffer[*p_offset];
		( *p_offset )++;
	}
	else if ( value == CBOR_ADDITIONAL_TYPE_0x1A )
	{
		value = (p_buffer[*p_offset] << 24)  & 0xFF000000;
		( *p_offset )++;
		value += (p_buffer[*p_offset] << 16)  & 0x00FF0000;
		( *p_offset )++;
		value += (p_buffer[*p_offset] << 8)  & 0xFF00;
		( *p_offset )++;
		value += p_buffer[*p_offset];
		( *p_offset )++;
	}

	return value;
}


inline uint32_t cbor_get_array_of_data(uint8_t* p_buffer, uint16_t* p_offset)
{
	uint32_t value = p_buffer[*p_offset] & ( (uint32_t)( ~CBOR_MAJOR_TYPE_4 ) );
	( *p_offset )++;
	return value;
}

inline uint32_t cbor_get_unsigned_integer( uint8_t* p_buffer, uint16_t* p_offset )
{
	return ( cbor_decode_data( p_buffer, p_offset, CBOR_MAJOR_TYPE_0 ) );
}

inline int32_t cbor_get_signed_integer( uint8_t* p_buffer, uint16_t* p_offset)
{
    /* adapted from code in RFC 7049 appendix C (pseudocode) */
    int32_t temp_value = (int32_t)cbor_decode_data(p_buffer, p_offset, CBOR_MAJOR_TYPE_1);
	return ( temp_value ^ (int32_t)(-1) );
}

inline uint32_t cbor_get_byte_string( uint8_t* p_buffer, uint16_t* p_offset )
{
	return ( cbor_decode_data(p_buffer, p_offset, CBOR_MAJOR_TYPE_2 ) );
}

inline uint32_t cbor_get_mapped(uint8_t* p_buffer, uint8_t* p_map_number, uint32_t* p_key_data_item, void * p_value_data_item, uint16_t value_data_item_len, uint16_t* p_offset, uint8_t value_data_type)
{
	int index = 0;
	uint16_t item_len = 0;
	uint32_t temp_value = 0;
	
	temp_value = cbor_decode_data(p_buffer, p_offset, CBOR_MAJOR_TYPE_5);
	if ( NULL != p_map_number )
		*p_map_number = temp_value;
	
	temp_value = cbor_get_unsigned_integer(p_buffer, p_offset);
	if ( NULL != p_key_data_item )
		*p_key_data_item = temp_value;
	
	switch(value_data_type)
	{
	case CBOR_MAJOR_TYPE_0 :
		temp_value = cbor_get_unsigned_integer(p_buffer, p_offset);
		if ( NULL != p_value_data_item)
			*(uint32_t*)p_value_data_item = temp_value;
		
		break;
	case CBOR_MAJOR_TYPE_1 : 
		temp_value = cbor_get_signed_integer(p_buffer, p_offset);
		if ( NULL != p_value_data_item)
			*(int32_t*)p_value_data_item = (int32_t)temp_value;
		
		break;
	case CBOR_MAJOR_TYPE_2 : 
		item_len = (uint16_t)cbor_get_byte_string(p_buffer, p_offset);
	
		if ( (NULL != p_value_data_item) && (item_len <= value_data_item_len) )
		{
			for(index = item_len-1; index >= 0; index--)
			{
				temp_value = p_buffer[*p_offset];
				(*p_offset)++;
				*((uint8_t*)p_value_data_item + index) = temp_value;
			}
		}

		break;
	}
	return 0;
}
