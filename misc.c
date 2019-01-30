/*!	\file celia.h
 *
 *	\brief Miscellaneous Utility routines related to GPSW07 scheme
 *
 *	Copyright 2011 Yao Zheng.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pbc.h>
#include <mbedtls/aes.h>

#include "celia.h"


/********************************************************************************
 * Utility functions
 ********************************************************************************/

/*!
 * Initialize parameters for AES symmetric-key encryption
 *
 * @param ctx                        Pointer to the aes context
 * @param k				Sercet message from KP-ABE
 * @param enc                       1 if we have to encrypt, 0 otherwise
 * @param iv			        Salt
 * @return				None
 */

void
init_aes( mbedtls_aes_context* ctx, element_t k, int enc, unsigned char* iv )
{
	int key_len;

	key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
	unsigned char key_buf[key_len];
	element_to_bytes(key_buf, k);

	if(enc)
		mbedtls_aes_setkey_enc(ctx, key_buf + 1, 128);
	else
		mbedtls_aes_setkey_dec(ctx, key_buf + 1, 128);

	memset(iv, 0, 16);
}

/*!
 * AES 128bit CBC mode encryption
 *
 * @param ct                 Byte arrary of ciphertext
 * @param pt			Byte arrary of plaintext
 * @param pt_len		Length of plaintext          
 * @param k				Sercet message from KP-ABE
 * @return			        size of ciphertext
 */

void
aes_128_cbc_encrypt( char ct[AES_LEN_CELIA], char pt[MSG_LEN_CELIA+1], element_t k )
{
	unsigned char iv[16];

	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	init_aes(&ctx, k, 1, iv);

	/* TODO make less crufty */

	/* stuff in real length (big endian) before padding */
	unsigned char pt_final[AES_LEN_CELIA];
	memset(pt_final, 0, AES_LEN_CELIA);

	pt_final[0] = ((MSG_LEN_CELIA+1) & 0xff000000)>>24;
	pt_final[1] = ((MSG_LEN_CELIA+1) & 0xff0000)>>16;
	pt_final[2] = ((MSG_LEN_CELIA+1) & 0xff00)>>8;
	pt_final[3] = ((MSG_LEN_CELIA+1) & 0xff)>>0;

	memcpy(pt_final + 4, pt, MSG_LEN_CELIA+1);
	
	mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, AES_LEN_CELIA, iv,
			      (unsigned char*) pt_final,
			      (unsigned char*) ct);
	
	mbedtls_aes_free(&ctx);
}

/*!
 * AES 128bit CBC mode decryption
 *
 * @param pt			GByteArrary of ciphertext
 * @param k				Sercet message from KP-ABE
 * @return				GByteArray of plaintext
 */

void
aes_128_cbc_decrypt( char pt[MSG_LEN_CELIA+1], char ct[AES_LEN_CELIA], element_t k )
{
	unsigned char iv[16];
	unsigned int len;

	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	init_aes(&ctx, k, 0, iv);

	unsigned char pt_final[AES_LEN_CELIA];

	if(mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, AES_LEN_CELIA, iv,
			      (unsigned char*) ct,
				 pt_final) == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH)		
		return;

	/* TODO make less crufty */

	/* get real length */
	len = 0;
	len = len
	    | ((pt_final[0])<<24) | ((pt_final[1])<<16)
	    | ((pt_final[2])<<8)  | ((pt_final[3])<<0);
	
	/* truncate any garbage from the padding */
	memcpy(pt, pt_final + 4, len);

	return;
}

/*!
 * Serialize a 32 bit unsign integer to a GByteArray.
 *
 * @param b                                   resulting byte array
 * @param k					Unsign integer
 * @return					
 */

void
serialize_uint32( char* b, uint32_t k )
{
	int i;
	uint8_t byte;

	for( i = 3; i >= 0; i-- )
	{
		byte = (k & 0xff<<(i*8))>>(i*8);
		b[3-i] = byte;
	}
}

/*!
 * Unserialize a 32 bit unsign integer from a byte array.
 *
 * @param b					byte array
 * @param offset			        offset of the integer
 * @return					Unsign integer
 */

uint32_t
unserialize_uint32( char* b, int* offset )
{
	int i;
	uint32_t r;
	uint8_t tmp;

	r = 0;
	for( i = 3; i >= 0; i-- ) {
		tmp = b[(*offset)++];
		r |= tmp<<(i*8);
	}

	return r;
}

/*!
 * Serialize a PBC element_t to a GByteArray.
 *
 * @param b                                   resulting byte array
 * @param e					element_t data type
 * @return					size of b
 */

void
serialize_element( char* b, element_t e )
{
	uint32_t len;

	len = element_length_in_bytes(e);

	char buf1[4];
	serialize_uint32(buf1, len);
	memcpy(b, buf1, 4);

	unsigned char buf2[len];
	element_to_bytes(buf2, e);
	memcpy(b + 4, buf2, len);
}

/*!
 * Unserialize a 32 PBC element_t from a GByteArray.
 *
 * @param b				        Byte array containing serialized element
 * @param offset			        offset of element_t within 'b'
 * @param e					element_t
 * @return					None
 */

void
unserialize_element( char* b, int* offset, element_t e )
{
	uint32_t len;

	len = unserialize_uint32(b, offset);

	unsigned char buf[len];
	memcpy(buf, b + *offset, len);
	*offset += len;

	element_from_bytes(e, buf);
}

/*!
 * Serialize a public key data structure to a byte array.
 *
 * @param b					Will contain resulting byte array
 * @param pub				Public key data structure
 * @return						The size of the byte array
 */
size_t
kpabe_pub_serialize( char* b, kpabe_pub_t* pub ) /* TODO: b */
{
	int i;
	size_t final_len = 0;

	char buf1[strlen(pub->pairing_desc) + 1];
	strcpy(buf1, pub->pairing_desc);
	size_t buf1_len = strlen(buf1) + 1;
	final_len += buf1_len;
	char* buf2 = NULL; /* TODO */
	serialize_element(buf2, pub->g);
	final_len += 1 /* TODO */;
	char* buf3 = NULL; /* TODO */
	serialize_element(buf3, pub->Y);
	final_len += 1 /* TODO */;
	char buf4[4]; /* TODO */
	serialize_uint32(buf4, pub->comps_len);
	final_len += 4;

	char buf5[pub->comps_len][ATTR_LEN_CELIA + 1];
	char* buf6[pub->comps_len]; /* TODO */
	for( i = 0; i < pub->comps_len; i++ )
	{
		strcpy(buf5[i], pub->comps[i].attr);
		serialize_element(buf6[i], pub->comps[i].T);
		final_len += 1 /* TODO: buf6[i] length */ + ATTR_LEN_CELIA + 1;
	}

	size_t a = 0;

	memcpy(b, buf1, buf1_len);
	a += buf1_len;

	memcpy(b + a, buf2, 1);
	a += 1; /* TODO */

	memcpy(b + a, buf3, 1);
	a += 1; /* TODO */

	memcpy(b + a, buf4, 4);
	a += 4;

	for( i = 0; i < pub->comps_len; i++ )
	{
		memcpy(b + a, buf5[i], ATTR_LEN_CELIA + 1);
		a += ATTR_LEN_CELIA + 1;

		memcpy(b + a, buf6[i], 1 /* TODO: buf6[i] length */);
		a += 1; /* TODO: buf6[i] length */
	}

	return final_len;
}

/*!
 * Unserialize a public key data structure from a byte array.
 *
 * @param pub			The public key returned
 * @param b				The byte array
 * @return					None
 */
void
kpabe_pub_unserialize( kpabe_pub_t* pub, char* b )
{
	int offset;
	int i;

	offset = 0;

	strcpy(pub->pairing_desc, b + offset);
	offset += strlen(pub->pairing_desc) + 1;
	pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc));

	element_init_G1(pub->g, pub->p);
	element_init_GT(pub->Y, pub->p);

	unserialize_element(b, &offset, pub->g);
	unserialize_element(b, &offset, pub->Y);

	pub->comps_len = unserialize_uint32(b, &offset);

	for( i = 0; i < pub->comps_len; i++ )
	{
		kpabe_pub_comp_t c;

		strcpy(c.attr, b + offset);
		offset += strlen(c.attr) + 1;

		element_init_G1(c.T, pub->p);

		unserialize_element(b, &offset, c.T);

		memcpy(&pub->comps[i], &c, sizeof(kpabe_pub_comp_t));
	}
}

/*!
 * serialize a policy data structure to a byte arrat.
 *
 * @param b					Will contain resulting byte array
 * @param p					Policy data structure
 * @return						Size of byte array
 */
size_t
serialize_policy( char* b, kpabe_policy_t* p ) /* TODO: b */
{
	int i;
	size_t final_len = 0;

	char buf1[4];
	serialize_uint32(buf1, (uint32_t) p->k);
	final_len += 4;

	char buf2[4];
	serialize_uint32(buf2, (uint32_t) p->children_len);
	final_len += 4;

	size_t buf4_len = ATTR_LEN_CELIA + 1;
	char buf4[buf4_len];
	char* buf5 = NULL; /* TODO */
	char* buf6[p->children_len];
	size_t buf6_len[p->children_len];
	if( p->children_len == 0 )
	{
		strcpy(buf4, p->attr);
		serialize_element(buf5, p->D);
		final_len += buf4_len + 1;
	}
	else
		for( i = 0; i < p->children_len; i++ )
		{
			buf6_len[i] = serialize_policy(buf6[i], &p->children[i]);
			final_len += buf6_len[i];
		}

	size_t a = 0;

	memcpy(b, buf1, 4);
	a += 4;

	memcpy(b + a, buf2, 4);
	a += 4;

	if( p->children_len == 0 )
	{
		memcpy(b  + a, buf4, buf4_len);
		a += buf4_len;

		memcpy(b  + a, buf5, 1 /* TODO */);
		a += 1 /* TODO */;
	}
	else
		for( i = 0; i < p->children_len; i++ )
		{
			memcpy(b + a, buf6[i], buf6_len[i]);
			a += buf6_len[i];
		}

	return final_len;
}

/*!
 * Unserialize a policy data structure from a byte array using the paring parameter
 * from the public data structure
 *
 * @param p				The policy returned
 * @param pub			Public data structure
 * @param b				The byte array
 * @return					None
 */

void
unserialize_policy( kpabe_policy_t* p, kpabe_pub_t pub, char* b, int* offset )
{
	int i;
	static unsigned int stack_c = 0;

	p->k = unserialize_uint32(b, offset);
	p->children_len = unserialize_uint32(b, offset);

	if( p->children_len == 0 )
	{
		size_t attr_len = strlen(b + *offset) + 1;
		strcpy(p->attr, b + *offset);
		*offset += attr_len;
		element_init_G1(p->D,  pub.p);
		unserialize_element(b, offset, p->D);
	}
	else{
		for( i = 0; i < p->children_len; i++ )
			unserialize_policy(&p->children[i], pub, b, offset);
	}
}

/*!
 * Serialize a private key data structure to a byte array.
 *
 * @param b				Will contain resulting byte array
 * @param prv			Private key data structure
 * @return					Size of byte array
 */
void
kpabe_prv_serialize( char* b, kpabe_prv_t* prv ) /* TODO: b */
{
	serialize_policy( b, &prv->p );
}

/*!
 * Unserialize a ciphertext data structure from a byte array.
 *
 * @param prv			The returned private key
 * @param pub			Public parameter structure
 * @param b				The byte array
 * @return					None
 */

void
kpabe_prv_unserialize( kpabe_prv_t* prv, kpabe_pub_t pub, char* b )
{
	int offset = 0;
	unserialize_policy(&prv->p, pub, b, &offset);
}

/*!
 * Serialize a ciphertext key data structure to a GByteArray.
 *
 * @param b                                   Will contain resulting byte array
 * @param cph				Ciphertext data structure
 * @return					Size of resulting byte arrray
 */

void
kpabe_cph_serialize( char* b, kpabe_cph_t* cph ) /* TODO: b */
{
	int i;
	size_t final_len = 0;

	char *buf1 = NULL; /* TODO */
    serialize_element(buf1, cph->Ep);
	final_len += 1 /* TODO */;

	char buf2[4];
    serialize_uint32(buf2, cph->comps_len);
	final_len += 4;

	char buf3[cph->comps_len][ATTR_LEN_CELIA + 1];
	size_t buf3_len[cph->comps_len];

	char* buf4[cph->comps_len]; /* TODO */

	for( i = 0; i < cph->comps_len; i++ )
	{
		buf3_len[i] = strlen(cph->comps[i].attr)+1;
		strcpy(buf3[i], cph->comps[i].attr);
		final_len += buf3_len[i];

		serialize_element(buf4[i] , cph->comps[i].E);
		final_len += 1 /* TODO */;
	}

	size_t a = 0;

	memcpy(b, buf1, 1 /* TODO */);
	a += 1 /* TODO */;

	memcpy(b + a, buf2, 4);
	a += 4;

	for( i = 0; i < cph->comps_len; i++ )
	{
		memcpy(b + a, buf3[i], buf3_len[i]);
		a += buf3_len[i];

		memcpy(b + a, buf4[i], 1 /* TODO */);
		a += 1 /* TODO */;
	}
}

/*!
 * Unserialize a ciphertext data structure from a GByteArray. if free is true,
 * free the byte array
 *
 * @param pub				Public key data structure
 * @param b					Byte array containing data structure serialized
 * @return					Ciphertext key data structure
 */

void
kpabe_cph_unserialize( kpabe_cph_t* cph, kpabe_pub_t* pub, char* b )
{
	int i;
	int offset = 0;

	offset = 0;

	element_init_GT(cph->Ep, pub->p);
	unserialize_element(b, &offset, cph->Ep);

	cph->comps_len = unserialize_uint32(b, &offset);

	for( i = 0; i < cph->comps_len; i++ )
	{
		kpabe_cph_comp_t c;

		strcpy(c.attr, b + offset);
		offset += strlen(c.attr)+1;

		element_init_G1(c.E,  pub->p);

		unserialize_element(b, &offset, c.E);

		memcpy(&cph->comps[i], &c, sizeof(kpabe_cph_comp_t));
	}
}

void print_celia_config(){
	printf("[celia] ABE Benchmark program.\n");
	printf("    Configuration:\n");
	printf("        Number of attribute: %d\n", NUM_ATTR_CELIA);
	printf("        Length of each attribute: %d\n", ATTR_LEN_CELIA);
	printf("        Length of encrypted message: %d\n", MSG_LEN_CELIA);
}
