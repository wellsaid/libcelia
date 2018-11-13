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

#if defined (__cplusplus)
extern "C" {
#endif

/*
  one attribute structure in public key
*/
typedef struct
{
	char* attr;
	element_t T;		/* G_1 */
}
kpabe_pub_comp_t;

/*
  A public key.
*/
typedef struct
{
	char* pairing_desc;
	pairing_t p;
	element_t g;           /* G_1 */
	element_t Y; 		   /* G_T */
	kpabe_pub_comp_t* comps;
	size_t comps_len;
}
kpabe_pub_t;

/*
  one attribute structure in master key
*/
typedef struct
{
	char* attr;
	element_t t;		/* Z_p */
}
kpabe_msk_comp_t;

/*
  A master secret key.
*/
typedef struct
{
	element_t y;    	/* Z_p */
	kpabe_msk_comp_t* comps;
	size_t comps_len;
}
kpabe_msk_t;

typedef struct
{
	int deg;
	/* coefficients from [0] x^0 to [deg] x^deg */
	element_t* coef; /* Z_p (of length deg + 1) */
}
kpabe_polynomial_t;

typedef struct kpabe_policy_t kpabe_policy_t;
  
struct kpabe_policy_t
{
	/* serialized */
	int k;            /* one if leaf, otherwise threshold */
	char* attr;       /* attribute string if leaf, otherwise null */
	element_t D;      /* G_1, only for leaves */
	kpabe_policy_t** children; /* pointers to kpabe_policy_t's, NULL for leaves */
	size_t children_len;

	/* only used during encryption */
	kpabe_polynomial_t* q;

	/* only used during decryption */
	int satisfiable;
	int min_leaves;
	int attri;
	int* satl;
	size_t satl_len;
};

/*
  A private key.
*/
typedef struct
{
	kpabe_policy_t* p;	/* kpabe_policy_t */
}
kpabe_prv_t;

/*
  one attribute structure in ciphertext key
*/
typedef struct
{
	char* attr;
	element_t E;  		/* G_1 */
}
kpabe_cph_comp_t;

/*
  A ciphertext.
*/
typedef struct
{
	element_t Ep; 		/* G_T */
	kpabe_cph_comp_t* comps;
	size_t comps_len;
}
kpabe_cph_t;

/*
  core function
*/
void kpabe_setup( kpabe_pub_t** pub, kpabe_msk_t** msk, char** attributes, size_t num_attributes );
kpabe_prv_t* kpabe_keygen( kpabe_pub_t* pub, kpabe_msk_t* msk, char* policy );
size_t kpabe_enc( char** c, kpabe_pub_t* pub, char* m, size_t m_len, char** attributes, size_t num_attributes );
size_t kpabe_dec( char** m, kpabe_pub_t* pub, kpabe_prv_t* prv, char * c, size_t c_len);


/*
  Exactly what it seems.
*/
size_t kpabe_cph_serialize( char** b, kpabe_cph_t* cph );

/*
  Also exactly what it seems.
*/
kpabe_cph_t* kpabe_cph_unserialize( kpabe_pub_t* pub, char* b);
    
/*
  Again, exactly what it seems.
*/
void kpabe_pub_free( kpabe_pub_t* pub );
void kpabe_msk_free( kpabe_msk_t* msk );
void kpabe_prv_free( kpabe_prv_t* prv );
void kpabe_cph_free( kpabe_cph_t* cph );

/*
  Return a description of the last error that occured. Call this after
  kpabe_enc or kpabe_dec returns 0. The returned string does not
  need to be free'd.
*/
char* kpabe_error();

/*
 * AES CBC Encryption/Decryption functions
*/
size_t aes_128_cbc_encrypt( char** ct, char* pt, size_t pt_len, element_t k );
size_t aes_128_cbc_decrypt( char** pt, char* ct, size_t ct_len, element_t k );

#if defined (__cplusplus)
} // extern "C"
#endif
