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

#include "celia.h"

//#include <os/lib/heapmem.h>
#if defined(CONTIKI_TARGET_ZOUL)
#include <dev/cbc.h>
#else
#include <mbedtls/aes.h>
#endif

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
#if defined(CONTIKI_TARGET_ZOUL)
init_aes( element_t k, unsigned char* iv )
#else
init_aes( mbedtls_aes_context* ctx, element_t k, int enc, unsigned char* iv )
#endif
{
	int key_len;
	unsigned char* key_buf;

	key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
	key_buf = (unsigned char*) malloc(key_len);
	element_to_bytes(key_buf, k);

#if defined(CONTIKI_TARGET_ZOUL)
	crypto_init();

	uint8_t ret;
	if( (ret = aes_load_keys(key_buf + 1, AES_KEY_STORE_SIZE_KEY_SIZE_128, 1, 0)) != CRYPTO_SUCCESS){
		printf("ERROR: loading keys (error: %d)\n", ret);
		exit(1);
	}
#else
	if(enc)
		mbedtls_aes_setkey_enc(ctx, key_buf + 1, 128);
	else
		mbedtls_aes_setkey_dec(ctx, key_buf + 1, 128);
#endif
	free(key_buf);

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

size_t
aes_128_cbc_encrypt( char **ct, char* pt, size_t pt_len, element_t k )
{
	unsigned char iv[16];

#if defined(CONTIKI_TARGET_ZOUL)
	init_aes(k, iv);
#else
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	init_aes(&ctx, k, 1, iv);
#endif

	/* TODO make less crufty */

	/* stuff in real length (big endian) before padding */
	size_t pt_final_len = 4 + pt_len;
	pt_final_len += (16 - ((int) pt_final_len % 16));
	char *pt_final = malloc(pt_final_len);
	memset(pt_final, 0, pt_final_len);
	
	pt_final[0] = (pt_len & 0xff000000)>>24;
	pt_final[1] = (pt_len & 0xff0000)>>16;
	pt_final[2] = (pt_len & 0xff00)>>8;
	pt_final[3] = (pt_len & 0xff)>>0;

	memcpy(pt_final + 4, pt, pt_len);

	*ct = malloc(pt_final_len);

#if defined(CONTIKI_TARGET_ZOUL)
	uint8_t ret;
	if( (ret = cbc_crypt_start(1, 0, iv, pt_final, *ct, pt_final_len, NULL)) != CRYPTO_SUCCESS){
		printf("ERROR: starting cbc operation (error: %d)\n", ret);
		exit(1);
	}

	do {
		ret = cbc_crypt_check_status();
	} while(ret == -1 || ret == 255);
	/* otherwise continues with error 255 */

	if( ret != CRYPTO_SUCCESS ){
		printf("ERROR: performing cbc operation (error: %d)\n", ret);
		exit(1);
	}
#else
	mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, pt_final_len, iv,
			      (unsigned char*) pt_final,
			      (unsigned char*) *ct);
#endif
	
	free(pt_final);
#if defined(CONTIKI_TARGET_ZOUL)
	crypto_disable();
#else
	mbedtls_aes_free(&ctx);
#endif

	return pt_final_len;
}

/*!
 * AES 128bit CBC mode decryption
 *
 * @param pt			GByteArrary of ciphertext
 * @param k				Sercet message from KP-ABE
 * @return				GByteArray of plaintext
 */

size_t
aes_128_cbc_decrypt( char** pt, char* ct, size_t ct_len, element_t k )
{
	unsigned char iv[16];
	unsigned int len;

#if defined(CONTIKI_TARGET_ZOUL)
	init_aes(k, iv);
#else
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	init_aes(&ctx, k, 0, iv);
#endif

	char* pt_final = malloc(ct_len);

#if defined(CONTIKI_TARGET_ZOUL)
	uint8_t ret;
	if( (ret = cbc_crypt_start(0, 0, iv, ct, pt_final, ct_len, NULL)) != CRYPTO_SUCCESS){
		printf("ERROR: starting cbc operation (error: %d)\n", ret);
		exit(1);
	}

	do {
		ret = cbc_crypt_check_status();
	} while(ret == -1 || ret == 255);
	/* otherwise continues with error 255 */

	if( ret != CRYPTO_SUCCESS ){
		printf("ERROR: performing cbc operation (error: %d)\n", ret);
		exit(1);
	}
#else
	if(mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, ct_len, iv,
			     (unsigned char*) ct,
				 (unsigned char*) pt_final) == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH)
		return 0;
#endif

	/* TODO make less crufty */

	/* get real length */
	len = 0;
	len = len
	    | ((pt_final[0])<<24) | ((pt_final[1])<<16)
	    | ((pt_final[2])<<8)  | ((pt_final[3])<<0);
	
	/* truncate any garbage from the padding */
	*pt = malloc(len);
	memcpy(*pt, pt_final + 4, len);

	free(pt_final);
#if defined(CONTIKI_TARGET_ZOUL)
	crypto_disable();
#else
	mbedtls_aes_free(&ctx);
#endif
	return len;
}

/*!
 * Serialize a 32 bit unsign integer to a GByteArray.
 *
 * @param b                                   resulting byte array
 * @param k					Unsign integer
 * @return					
 */

void
serialize_uint32( char** b, uint32_t k )
{
	*b = malloc(4);
	
	int i;
	uint8_t byte;

	for( i = 3; i >= 0; i-- )
	{
		byte = (k & 0xff<<(i*8))>>(i*8);
		(*b)[3-i] = byte;
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

size_t
serialize_element( char** b, element_t e )
{
	uint32_t len;

	len = element_length_in_bytes(e);
	*b = malloc(4 + len);

	char *buf1 = NULL;
	serialize_uint32(&buf1, len);
	memcpy(*b, buf1, 4);
	free(buf1);

	unsigned char* buf2 = (unsigned char*) malloc(len);
	element_to_bytes(buf2, e);
	memcpy(*b + 4, buf2, len);
	free(buf2);
	
	return 4+len;
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
	unsigned char* buf;

	len = unserialize_uint32(b, offset);

	buf = (unsigned char*) malloc(len);
	memcpy(buf, b + *offset, len);
	*offset += len;

	element_from_bytes(e, buf);
	free(buf);
}

/*!
 * Serialize a public key data structure to a byte array.
 *
 * @param b					Will contain resulting byte array
 * @param pub				Public key data structure
 * @return						The size of the byte array
 */
size_t
kpabe_pub_serialize( char** b, kpabe_pub_t* pub )
{
	int i;
	size_t final_len = 0;

	char* buf1 = malloc(strlen(pub->pairing_desc) + 1);
	strcpy(buf1, pub->pairing_desc);
	size_t buf1_len = strlen(buf1) + 1;
	final_len += buf1_len;
	char* buf2 = NULL;
	size_t buf2_len = serialize_element(&buf2, pub->g);
	final_len += buf2_len;
	char* buf3 = NULL;
	size_t buf3_len = serialize_element(&buf3, pub->Y);
	final_len += buf3_len;
	char* buf4 = NULL;
	serialize_uint32(&buf4, pub->comps_len);
	final_len += 4;

	char* buf5[pub->comps_len];
	size_t buf5_len[pub->comps_len];
	char* buf6[pub->comps_len];
	size_t buf6_len[pub->comps_len];
	for( i = 0; i < pub->comps_len; i++ )
	{
		buf5[i] = malloc(strlen(pub->comps[i].attr) + 1);
		strcpy(buf5[i], pub->comps[i].attr);
		buf5_len[i] = strlen(buf5[i]) + 1;
		buf6_len[i] = serialize_element(&buf6[i], pub->comps[i].T);
		final_len += buf6_len[i] + buf5_len[i];
	}

	*b = malloc(final_len);
	size_t a = 0;

	memcpy(*b, buf1, buf1_len);
	a += buf1_len;
	free(buf1);

	memcpy(*b + a, buf2, buf2_len);
	a += buf2_len;
	free(buf2);

	memcpy(*b + a, buf3, buf3_len);
	a += buf3_len;
	free(buf3);

	memcpy(*b + a, buf4, 4);
	a += 4;
	free(buf4);

	for( i = 0; i < pub->comps_len; i++ )
	{
		memcpy(*b + a, buf5[i], buf5_len[i]);
		a += buf5_len[i];
		free(buf5[i]);

		memcpy(*b + a, buf6[i], buf6_len[i]);
		a += buf6_len[i];
		free(buf6[i]);
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
kpabe_pub_unserialize( kpabe_pub_t** pub, char* b )
{
	int offset;
	int i;

	*pub = (kpabe_pub_t*) malloc(sizeof(kpabe_pub_t));
	offset = 0;

	(*pub)->pairing_desc = malloc(strlen(b + offset) + 1);
	strcpy((*pub)->pairing_desc, b + offset);
	offset += strlen((*pub)->pairing_desc) + 1;
	pairing_init_set_buf((*pub)->p, (*pub)->pairing_desc, strlen((*pub)->pairing_desc));

	element_init_G1((*pub)->g, (*pub)->p);
	element_init_GT((*pub)->Y, (*pub)->p);

	unserialize_element(b, &offset, (*pub)->g);
	unserialize_element(b, &offset, (*pub)->Y);

	(*pub)->comps_len = unserialize_uint32(b, &offset);
	(*pub)->comps = malloc((*pub)->comps_len*sizeof(kpabe_pub_comp_t));

	for( i = 0; i < (*pub)->comps_len; i++ )
	{
		kpabe_pub_comp_t c;

		c.attr = malloc(strlen(b + offset) + 1);
		strcpy(c.attr, b + offset);
		offset += strlen(c.attr) + 1;

		element_init_G1(c.T, (*pub)->p);

		unserialize_element(b, &offset, c.T);

		memcpy(&(*pub)->comps[i], &c, sizeof(kpabe_pub_comp_t));
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
serialize_policy( char** b, kpabe_policy_t* p )
{
	int i;
	size_t final_len = 0;

	char* buf1 = NULL;
	serialize_uint32(&buf1, (uint32_t) p->k);
	final_len += 4;

	char* buf2 = NULL;
	serialize_uint32(&buf2, (uint32_t) p->children_len);
	final_len += 4;

	char* buf4 = NULL;
	size_t buf4_len = 0;
	char* buf5 = NULL;
	size_t buf5_len = 0;
	char* buf6[p->children_len];
	size_t buf6_len[p->children_len];
	if( p->children_len == 0 )
	{
		buf4 = malloc(strlen(p->attr) + 1);
		strcpy(buf4, p->attr);
		buf4_len = strlen(buf4) + 1;
		buf5_len = serialize_element(&buf5, p->D);
		final_len += buf4_len + buf5_len;
	}
	else
		for( i = 0; i < p->children_len; i++ )
		{
			buf6_len[i] = serialize_policy(&buf6[i], &p->children[i]);
			final_len += buf6_len[i];
		}

	*b = malloc(final_len);
	size_t a = 0;

	memcpy(*b, buf1, 4);
	a += 4;
	free(buf1);

	memcpy(*b + a, buf2, 4);
	a += 4;
	free(buf2);

	if( p->children_len == 0 )
	{
		memcpy(*b  + a, buf4, buf4_len);
		a += buf4_len;
		free(buf4);

		memcpy(*b  + a, buf5, buf5_len);
		a += buf5_len;
		free(buf5);
	}
	else
		for( i = 0; i < p->children_len; i++ )
		{
			memcpy(*b + a, buf6[i], buf6_len[i]);
			a += buf6_len[i];
			free(buf6[i]);
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
 * @param offset	    Offset of policy data structure within GByteArray
 * @return					None
 */

void
unserialize_policy( kpabe_policy_t** p, kpabe_pub_t* pub, char* b, int* offset )
{
	int i;

	if(*p == NULL)
		*p = (kpabe_policy_t*) malloc(sizeof(kpabe_policy_t));

	(*p)->k = unserialize_uint32(b, offset);
	(*p)->attr = 0;
	(*p)->children_len = unserialize_uint32(b, offset);
	(*p)->children = (kpabe_policy_t*) malloc((*p)->children_len*sizeof(kpabe_policy_t));

	if( (*p)->children_len == 0 )
	{
		(*p)->attr = malloc(strlen(b + *offset) + 1);
		strcpy((*p)->attr, b + *offset);
		*offset += strlen((*p)->attr) + 1;
		element_init_G1((*p)->D,  pub->p);
		unserialize_element(b, offset, (*p)->D);
	}
	else
		for( i = 0; i < (*p)->children_len; i++ )
		{
			kpabe_policy_t* tmp = &(*p)->children[i];
			unserialize_policy(&tmp, pub, b, offset);
		}
}

/*!
 * Serialize a private key data structure to a byte array.
 *
 * @param b				Will contain resulting byte array
 * @param prv			Private key data structure
 * @return					Size of byte array
 */
size_t
kpabe_prv_serialize( char** b, kpabe_prv_t* prv )
{
	return serialize_policy( b, prv->p );
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
kpabe_prv_unserialize( kpabe_prv_t** prv, kpabe_pub_t* pub, char* b )
{
	int offset;

	*prv = (kpabe_prv_t*) malloc(sizeof(kpabe_prv_t));
	offset = 0;

	(*prv)->p = NULL;
	unserialize_policy(&(*prv)->p, pub, b, &offset);
}

/*!
 * Serialize a ciphertext key data structure to a GByteArray.
 *
 * @param b                                   Will contain resulting byte array
 * @param cph				Ciphertext data structure
 * @return					Size of resulting byte arrray
 */

size_t
kpabe_cph_serialize( char** b, kpabe_cph_t* cph )
{
	int i;
	size_t final_len = 0;

	char *buf1 = NULL;
	size_t buf1_len;
    buf1_len = serialize_element(&buf1, cph->Ep);
	final_len += buf1_len;

	char* buf2  = NULL;
        serialize_uint32(&buf2, cph->comps_len);
	final_len += 4;

	char* buf3[cph->comps_len];
	size_t buf3_len[cph->comps_len];

	char* buf4[cph->comps_len];
	size_t buf4_len[cph->comps_len];

	for( i = 0; i < cph->comps_len; i++ )
	{
		buf3_len[i] = strlen(cph->comps[i].attr)+1;
		buf3[i] = malloc(buf3_len[i]);
		strcpy(buf3[i], cph->comps[i].attr);
		final_len += buf3_len[i];

		buf4_len[i] = serialize_element(&buf4[i] , cph->comps[i].E);
		final_len += buf4_len[i];
	}

	*b = malloc(final_len);
	size_t a = 0;

	memcpy(*b, buf1, buf1_len);
	a += buf1_len;
	free(buf1);

	memcpy(*b + a, buf2, 4);
	a += 4;
	free(buf2);

	for( i = 0; i < cph->comps_len; i++ )
	{
		memcpy(*b + a, buf3[i], buf3_len[i]);
		a += buf3_len[i];
		free(buf3[i]);

		memcpy(*b + a, buf4[i], buf4_len[i]);
		a += buf4_len[i];
		free(buf4[i]);		
	}	

	return final_len;
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
kpabe_cph_unserialize( kpabe_cph_t** cph, kpabe_pub_t* pub, char* b )
{
	int i;
	int offset = 0;

	(*cph) = (kpabe_cph_t*) malloc(sizeof(kpabe_cph_t));
	offset = 0;

	element_init_GT((*cph)->Ep, pub->p);
	unserialize_element(b, &offset, (*cph)->Ep);

	(*cph)->comps_len = unserialize_uint32(b, &offset);
	(*cph)->comps = malloc((*cph)->comps_len*sizeof(kpabe_cph_comp_t));

	for( i = 0; i < (*cph)->comps_len; i++ )
	{
		kpabe_cph_comp_t c;

		c.attr = malloc(strlen(b + offset) + 1);
		strcpy(c.attr, b + offset);
		offset += strlen(c.attr)+1;

		element_init_G1(c.E,  pub->p);

		unserialize_element(b, &offset, c.E);

		memcpy(&(*cph)->comps[i], &c, sizeof(kpabe_cph_comp_t));
	}
}

/*!
 * Free a policy date structure
 *
 * @param					Policy data structure
 * @return					None
 */

void
kpabe_policy_free( kpabe_policy_t* p )
{
	int i;

	if( p->attr )
	{
		free(p->attr);
		element_clear(p->D);
	}

	for( i = 0; i < p->children_len; i++ )
	{
		kpabe_policy_free(p->children + i);
	}

	if(p->children_len > 0)
		free(p->children);
}

/*!
 * Free a public key date structure
 *
 * @param					Public key data structure
 * @return					None
 */

void
kpabe_pub_free( kpabe_pub_t* pub )
{
	int i;

	for( i = 0; i < pub->comps_len; i++ )
	{
		kpabe_pub_comp_t* c = &pub->comps[i];
		memcpy(c, pub->comps + i, sizeof(kpabe_pub_comp_t));
		free(c->attr);
		c->attr = NULL;
		element_clear(c->T);
	}

	free(pub->comps);
	
	element_clear(pub->g);
	element_clear(pub->Y);
	pairing_clear(pub->p);
	free(pub->pairing_desc);

	free(pub);
}

/*!
 * Free a master key date structure
 *
 * @param					Master key data structure
 * @return					None
 */

void
kpabe_msk_free( kpabe_msk_t* msk )
{
	int i;

	for( i = 0; i < msk->comps_len; i++ )
	{
		kpabe_msk_comp_t *c = &msk->comps[i];
		free(c->attr);
		c->attr = NULL;
		element_clear(c->t);
	}
	free(msk->comps);

	element_clear(msk->y);
	
	free(msk);
}

/*!
 * Free a private key date structure
 *
 * @param					Private key data structure
 * @return					None
 */

void
kpabe_prv_free( kpabe_prv_t* prv )
{
	kpabe_policy_free(prv->p);
	free(prv->p);
}

/*!
 * Free a ciphrtext date structure
 *
 * @param					Ciphertext data structure
 * @return					None
 */

void
kpabe_cph_free( kpabe_cph_t* cph )
{
	int i;

	element_clear(cph->Ep);


	for( i = 0; i < cph->comps_len; i++ )
	{
		kpabe_cph_comp_t c;

		c = cph->comps[i];
		c.attr = NULL;
		element_clear(c.E);
	}
	free(cph->comps);

	free(cph);
}
