/*!	\file celia.h
 *
 *	\brief Routines for the Goyal-Pandey-Sahai-Waters ABE scheme.
 *	Include glib.h and pbc.h before including this file.
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

#include <pbc.h>

#include "config.h"

#define TYPE_A_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"

#if defined (__cplusplus)
extern "C" {
#endif

/*
  one attribute structure in public key
*/
typedef struct
{
	char attr[ATTR_LEN_CELIA+1];
	element_t T;		/* G_1 */
}
kpabe_pub_comp_t;

/*
  A public key.
*/
typedef struct
{
	char pairing_desc[360];
	pairing_t p;
	element_t g;           /* G_1 */
	element_t Y; 		   /* G_T */
	kpabe_pub_comp_t comps[NUM_ATTR_CELIA];
	size_t comps_len;
}
kpabe_pub_t;

/*
  one attribute structure in master key
*/
typedef struct
{
	char attr[ATTR_LEN_CELIA+1];
	element_t t;		/* Z_p */
}
kpabe_msk_comp_t;

/*
  A master secret key.
*/
typedef struct
{
	element_t y;    	/* Z_p */
	kpabe_msk_comp_t comps[NUM_ATTR_CELIA];
	size_t comps_len;
}
kpabe_msk_t;

typedef struct
{
	int deg;
	/* coefficients from [0] x^0 to [deg] x^deg */
	element_t coef[5]; /* Z_p (of length deg + 1) */
}
kpabe_polynomial_t;

typedef struct kpabe_policy_t kpabe_policy_t;
  
struct kpabe_policy_t
{
	/* serialized */
	unsigned int k;            /* one if leaf, otherwise threshold */
	char attr[ATTR_LEN_CELIA+1];       /* attribute string if leaf, otherwise null */
	element_t D;      /* G_1, only for leaves */
	/* pointers to kpabe_policy_t's, NULL for leaves */
	kpabe_policy_t* children;

	size_t children_len;

	/* only used during encryption */
	kpabe_polynomial_t q;

	/* only used during decryption */
	int satisfiable;
	int min_leaves;
	int attri;
	int satl[NUM_ATTR_CELIA];
	size_t satl_len;
};

/*
  A private key.
*/
typedef struct
{
	kpabe_policy_t p;	/* kpabe_policy_t */
}
kpabe_prv_t;

/*
  one attribute structure in ciphertext key
*/
typedef struct
{
	char attr[ATTR_LEN_CELIA+1];
	element_t E;  		/* G_1 */
}
kpabe_cph_comp_t;

/*
  A ciphertext.
*/
typedef struct
{
	element_t Ep; 		/* G_T */
	kpabe_cph_comp_t comps[NUM_ATTR_CELIA];
	size_t comps_len;
}
kpabe_cph_t;

/*
  core function
*/
int kpabe_setup( kpabe_pub_t* pub, kpabe_msk_t* msk, char attributes[NUM_ATTR_CELIA][ATTR_LEN_CELIA+1] );
int kpabe_keygen( kpabe_prv_t* prv, kpabe_pub_t* pub, kpabe_msk_t* msk, char* policy );
void kpabe_enc_byte_array( kpabe_cph_t* cph, char aes_buf[AES_LEN_CELIA], kpabe_pub_t* pub, char  m[MSG_LEN_CELIA+1] );
void kpabe_enc( kpabe_cph_t* cph, kpabe_pub_t* pub, element_t m_e );
void kpabe_dec_byte_array( char m[MSG_LEN_CELIA+1], kpabe_pub_t* pub, kpabe_prv_t* prv, kpabe_cph_t* cph, char aes_buf[AES_LEN_CELIA] );
int kpabe_dec( kpabe_pub_t* pub, kpabe_prv_t* prv, kpabe_cph_t* cph, element_t m_e );

/*
  Exactly what it seems.
*/
void kpabe_cph_serialize( char* b, kpabe_cph_t* cph );
size_t kpabe_pub_serialize( char* b, kpabe_pub_t* pub );
void kpabe_prv_serialize( char* b, kpabe_prv_t* prv );

/*
  Also exactly what it seems.
*/
void kpabe_cph_unserialize( kpabe_cph_t* cph, kpabe_pub_t* pub, char* b );
void kpabe_pub_unserialize( kpabe_pub_t* pub, char* b );
void kpabe_prv_unserialize( kpabe_prv_t* prv, kpabe_pub_t pub, char* b );

/*
  Return a description of the last error that occured. Call this after
  kpabe_enc or kpabe_dec returns 0. The returned string does not
  need to be free'd.
*/
char* kpabe_error();

/*
 * AES CBC Encryption/Decryption functions
*/
void aes_128_cbc_encrypt( char ct[AES_LEN_CELIA], char pt[MSG_LEN_CELIA+1], element_t k );
void aes_128_cbc_decrypt( char pt[MSG_LEN_CELIA+1], char ct[AES_LEN_CELIA], element_t k );

#if defined (__cplusplus)
} // extern "C"
#endif
