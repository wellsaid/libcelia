/*!	\file core.c
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pbc.h>
#include <time.h>

#include "celia.h"
#include "config.h"

/********************************************************************************
 * Goyal-Pandey-Sahai-Waters Implementation
 ********************************************************************************/

#ifndef KPABE_DEBUG
#define NDEBUG
#endif

/*!
 * Last error call back for display
 *
 * @return				last_error.
 */

char last_error[256];
char*
kpabe_error()
{
	return last_error;
}

/*!
 * Handle error while using library routine
 *
 * @param fmt			Error string
 * @return				none.
 */

void
raise_error(char* fmt, ...)
{
	va_list args;

#ifdef KPABE_DEBUG
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(1);
#else
	va_start(args, fmt);
	vsnprintf(last_error, 256, fmt, args);
	va_end(args);
#endif
}

/*!
 * Generate public and master key with the provided attributes list.
 *
 * @param pub			Pointer to the public key data structure
 * @param msk			Pointer to the master key data structure
 * @param attributes	Attributes list
 * @param num_attributes  The number of attributes in the list
 * @return				0 on error 1 on success
 */

int
kpabe_setup( kpabe_pub_t* pub, kpabe_msk_t* msk, char attributes[NUM_ATTR_CELIA][ATTR_LEN_CELIA+1] )
{
	element_t tmp;	/* G_1 */
	int i;

	strcpy(pub->pairing_desc, TYPE_A_PARAMS);
	if( pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc)) ){
		return 0;
	}

	element_init_G1(pub->g, pub->p);
	element_init_G1(tmp, pub->p);
	element_init_GT(pub->Y, pub->p);
	element_init_Zr(msk->y, pub->p);

	pub->comps_len = 0;
	msk->comps_len = 0;
	
	/* compute */
 	element_random(msk->y);
	element_random(pub->g);

	element_pow_zn(tmp, pub->g, msk->y);
	pairing_apply(pub->Y, pub->g, tmp, pub->p);

	for( i = 0; i < NUM_ATTR_CELIA; i++)
	{
		kpabe_pub_comp_t TA;
		kpabe_msk_comp_t ta;

		strcpy(TA.attr, attributes[i]);
		strcpy(ta.attr, TA.attr);

		element_init_Zr(ta.t, pub->p);
		element_init_G1(TA.T, pub->p);

 		element_random(ta.t);
		element_pow_zn(TA.T, pub->g, ta.t);

		memcpy(&pub->comps[i], &TA, sizeof(kpabe_pub_comp_t));
		pub->comps_len++;
		memcpy(&msk->comps[i], &ta, sizeof(kpabe_msk_comp_t));
		msk->comps_len++;
	}
	
	return 1;
}

/*!
 * Encrypt a secret message with the provided attributes list, return a ciphertext.
 *
 * @param c                           Byte array containing ciphertext
 * @param pub			Public key structure
 * @param m				Byte array containing plaintext
 * @param m_len                   Length of the plaintext
 * @param attributes	Attributes list
 * @return				Length of ciphertext
 */

void
kpabe_enc_byte_array( kpabe_cph_t* cph, char aes_buf[AES_LEN_CELIA], kpabe_pub_t* pub, char  m[MSG_LEN_CELIA+1] )
{
	int i;
	uint8_t byte;
	element_t m_e;
	kpabe_enc( cph, pub, m_e );

	aes_128_cbc_encrypt(aes_buf, m, m_e);
	element_clear(m_e);

	size_t a = 0;
}

/*!
 * Encrypt a secret message with the provided attributes list, return a ciphertext
.
 *
 * @param pub		Public key structure
 * @param m_e		Secret Message
 * @return				Ciphertext structure
 */

void
kpabe_enc( kpabe_cph_t* cph, kpabe_pub_t* pub, element_t m_e )
{
 	element_t s;
	int i, j;

	/* initialize */
	element_init_Zr(s, pub->p);
	element_init_GT(m_e, pub->p);
	element_init_GT(cph->Ep, pub->p);

	/* compute */
 	element_random(m_e);
 	element_random(s);
	element_pow_zn(cph->Ep, pub->Y, s);
	element_mul(cph->Ep, cph->Ep, m_e);

	cph->comps_len = 0;

	for( i = 0; i < pub->comps_len; i++)
	{
		kpabe_cph_comp_t c;

		strcpy(c.attr, pub->comps[i].attr);

		element_init_G1(c.E, pub->p);

		for( j = 0; j < pub->comps_len; j++ )
		{
			if( !strcmp(pub->comps[j].attr, c.attr) )
			{
				element_pow_zn(c.E, pub->comps[j].T, s);
				break;
			}
			else
			{
				if(j == (pub->comps_len - 1))
				{
					raise_error("Check your attribute universe,\nCertain attribute not include!\n");
					return;
				}
			}
		}

		memcpy(&cph->comps[i], &c, sizeof(kpabe_cph_comp_t));
		cph->comps_len++;
	}
}

/*!
 * Subroutine to fill out a single KP-ABE Policy node structure
 *
 * @param p                           Pointer which will contain the structure
 * @param k				Threshold of this node
 * @param s				Attribute of this node (if it is the leaf node)
 * @return				Policy node data structure
 */

void
base_node( kpabe_policy_t* p, int k, char s[ATTR_LEN_CELIA+1] )
{
	p->k = k;
	strcpy(p->attr, s);
	p->children_len = 0;
}

/* Helper method:
 *     Counts the number of tokens in the string
 */
size_t
strtok_count( char* s,  const char* delim )
{
	int count = 0;
	char *ptr = s;
	while((ptr = strpbrk(ptr, delim)) != NULL)
	{
		count++;
		ptr++;
	}

	return count;
}

/*!
 * Generate a Policy tree from the input policy string.
 *
 * @param root                      Pointer to the root of the policy
 * @param s				Policy string
 * @return				Policy root node data structure
 */
int
parse_policy_postfix( kpabe_policy_t* root, char* s )
{
	int i;
	
	char*  tok;
	size_t stack_len = 0;
	kpabe_policy_t* top;

	kpabe_policy_t stack[(strtok_count(s, " ")+1)*sizeof(kpabe_policy_t)];
	top = &stack[0];

	char s_tmp[strlen(s)+1];
	strcpy(s_tmp,s);
	
	tok = strtok(s_tmp, " ");
	while( tok )
	{
		int k, n;
		kpabe_policy_t node;
		
		if( sscanf(tok, "%dof%d", &k, &n) != 2 )
		{
			/* push leaf token */
			base_node(&node, 1, tok);
			memcpy(top++, &node, sizeof(kpabe_policy_t));
			stack_len++;
		}
		else
		{
			/* parse "kofn" operator */
			if( k < 1 )
			{
				raise_error("error parsing \"%s\": trivially satisfied operator \"%s\"\n", s_tmp, tok);
				return 0;
			}
			else if( k > n )
			{
				raise_error("error parsing \"%s\": unsatisfiable operator \"%s\"\n", s_tmp, tok);
				return 0;
			}
			else if( n == 1 )
			{
				raise_error("error parsing \"%s\": identity operator \"%s\"\n", s_tmp, tok);
				return 0;
			}
			else if( n > stack_len )
			{
				raise_error("error parsing \"%s\": stack underflow at \"%s\"\n", s_tmp, tok);
				return 0;
			}
			
			/* pop n things and fill in children */
			base_node(&node, k, 0);
			for( i = n - 1; i >= 0; i-- )
			{
				memcpy(&node.children[i], --top, sizeof(kpabe_policy_t));
				stack_len--;
				node.children_len++;
			}

			/* push result */
			memcpy(top++, &node, sizeof(kpabe_policy_t));
			stack_len++;
		}

		tok = strtok(NULL, " ");
	}

	if( stack_len > 1 )
	{
		raise_error("error parsing \"%s\": extra tokens left on stack\n", s_tmp);
		return 0;
	}
	else if( stack_len < 1 )
	{
		raise_error("error parsing \"%s\": empty policy\n", s_tmp);
		return 0;
	}

	memcpy(root, --top, sizeof(kpabe_policy_t));
	
	return 1;
}

/*!
 * Randomly generate the Lagrange basis polynomial base on provided constant value
 *
 * @param q                           Pointer to structure containing the lagrange basis polynomial
 * @param deg			Degree of the lagrange basis polynomial
 * @param zero_val		Constant value of the lagrange basis polynomial
 * @return				Lagrange basis polynomial data structure
 */
void
rand_poly( kpabe_polynomial_t* q, int deg, element_t zero_val )
{
	int i;

	q->deg = deg;

	for( i = 0; i < q->deg + 1; i++ )
		element_init_same_as(q->coef[i], zero_val);

	element_set(q->coef[0], zero_val);

	for( i = 1; i < q->deg + 1; i++ )
 		element_random(q->coef[i]);
	
}

/*!
 * Compute the constant value of the child node's Lagrange basis polynomial,
 *
 * @param r				Constant value of this child node's Lagrange basis polynomial
 * @param q				Pointer to the lagrange basis polynomial of parent node
 * @param x				index of this child node in its parent node
 * @return				None
 */

void
eval_poly( element_t r, kpabe_polynomial_t* q, element_t x )
{
	int i;
	element_t s, t;

	element_init_same_as(s, r);
	element_init_same_as(t, r);

	element_set0(r);
	element_set1(t);

	for( i = 0; i < q->deg + 1; i++ )
	{
		/* r += q->coef[i] * t */
		element_mul(s, q->coef[i], t);
		element_add(r, r, s);

		/* t *= x */
		element_mul(t, t, x);
	}

	element_clear(s);
	element_clear(t);
}

/*!
 * Routine to fill out the Policy tree
 *
 * @param P				Pointer to Root node policy data structure
 * @param pub			Public key
 * @param msk			Master key
 * @param e				Root secret
 * @return				None
 */

int
fill_policy( kpabe_policy_t* p, kpabe_pub_t* pub, kpabe_msk_t* msk, element_t e )
{
	int i;
	element_t r;
	element_t t;
	element_t a;

	element_init_Zr(r, pub->p);
	element_init_Zr(t, pub->p);
	element_init_Zr(a, pub->p);

	rand_poly(&p->q, p->k - 1, e);

	if( p->children == NULL )
	{
		element_init_G1(p->D,  pub->p);

		for( i = 0; i < msk->comps_len; i++ )
		{
			if( !strcmp(msk->comps[i].attr, p->attr) )
			{
				element_div(a, p->q.coef[0], msk->comps[i].t);
				element_pow_zn(p->D, pub->g, a);
				break;
			}
			else
			{
				if(i == (msk->comps_len - 1))
				{
					raise_error("Check your attribute universe,\nCertain attribute not included!\n");
					return 0;
				}

			}
		}
	}
	else
	{		
		for( i = 0; i < p->children_len; i++ )
		{
			element_set_si(r, i + 1);
			eval_poly(t, &p->q, r);
			if(!fill_policy(&p->children[i], pub, msk, t))
				return 0;
		}
	}

	element_clear(r);
	element_clear(t);
	element_clear(a);
	return 1;
}

/*!
 * Generate private key with the provided policy.
 *
 * @param prv                       Pointer to structure which contain the private key
 * @param pub			Public key data structure
 * @param msk			Master key data structure
 * @param policy		Policy tree string
 * @return				Private key data structure.
 */
int
kpabe_keygen( kpabe_prv_t* prv, kpabe_pub_t* pub, kpabe_msk_t* msk, char* policy )
{
	/* initialize */

	parse_policy_postfix(&prv->p, policy);

	/* compute */
	if(!fill_policy(&prv->p, pub, msk, msk->y))
		return 0;

	return 1;
}

/*!
 * Check whether the attributes in the ciphertext data structure can
 * access the root secret in the policy data structure, and mark all
 * possible path
 *
 * @param p				Policy node data structure (root)
 * @param cph			Ciphertext data structure
 * @param oub			Public key data structure
 * @return				None
 */

int
check_sat( kpabe_policy_t* p, kpabe_cph_t* cph, kpabe_pub_t* pub )
{
	int i, l;

	p->satisfiable = 0;
	if( p->children_len == 0 )
	{
		for( i = 0; i < cph->comps_len; i++ )
		{
			if( !strcmp(cph->comps[i].attr, p->attr) )
			{
				p->satisfiable = 1;
				p->attri = i;
				break;
			}
		}
		for( i = 0; i < pub->comps_len; i++ )
			if( !strcmp(pub->comps[i].attr, p->attr) )
			{
				break;
			}
			else
			{
				if(i == (pub->comps_len - 1))
				{
					raise_error("Check your attribute universe,\nCertain attribute not included!\n");
					return 0;
				}
			}
	}
	else
	{
		for( i = 0; i < p->children_len; i++ )
			if(!check_sat(&p->children[i], cph, pub))
			{
				return 0;
			}

		l = 0;
		for( i = 0; i < p->children_len; i++ )
			if( p->children[i].satisfiable )
			{
			    l++;
			}
		
		if( l >= p->k )
			p->satisfiable = 1;
	}

	return 1;
}

/*!
 * Function that compare the minimal leaves of two child policy node of the same parent node
 *
 * @param a				index of first child node in its parent node
 * @param b				index of second child node in its parent node
 * @return	k			compare result
 */

kpabe_policy_t* cur_comp_pol;
int
cmp_int( const void* a, const void* b )
{
	int k, l;

	k = cur_comp_pol->children[*((int*)a)].min_leaves;
	l = cur_comp_pol->children[*((int*)b)].min_leaves;

	return
		k <  l ? -1 :
		k == l ?  0 : 1;
}

/*!
 * Choose the path with minimal leaves node from all possible path which are marked as satisfiable
 * Mark the respective "min_leaves" element in the policy node data structure
 *
 * @param p				Policy node data structure (root)
 * @return				None
 */

void
pick_sat_min_leaves( kpabe_policy_t* p )
{
	int i, k, l = 0;

	assert(p->satisfiable == 1);

	if( p->children_len == 0 )
		p->min_leaves = 1;
	else
	{
		for( i = 0; i < p->children_len; i++ )
			if( p->children[i].satisfiable )
				pick_sat_min_leaves(&p->children[i]);

		int c[p->children_len];
		for( i = 0; i < p->children_len; i++ )
			c[i] = i;

		cur_comp_pol = p;
		qsort(c, p->children_len, sizeof(int), cmp_int);

		/* count how many satl we need */
		p->satl_len = 0;
		for( i = 0; i < p->children_len && l < p->k; i++ )
			if( p->children[c[i]].satisfiable )
			{
				l++;
				p->satl_len++;
			}
		
		p->satl_len = 0;
		p->min_leaves = 0;
		l = 0;
		for( i = 0; i < p->children_len && l < p->k; i++ )
			if( p->children[c[i]].satisfiable )
			{
				l++;
				p->min_leaves += p->children[c[i]].min_leaves;
				k = c[i] + 1;
				p->satl[p->satl_len++] = k;
			}
		assert(l == p->k);
	}
}

/*!
 * Compute Lagrange coefficient
 *
 * @param r				Lagrange coefficient
 * @param s				satisfiable node set
 * @param s_len                    length of node set
 * @param i				index of this node in the satisfiable node set
 * @return				None
 */

void
lagrange_coef( element_t r, int* s, size_t s_len, int i )
{
	int j, k;
	element_t t;

	element_init_same_as(t, r);

	element_set1(r);
	for( k = 0; k < s_len; k++ )
	{
		j = s[k];
		if( j == i )
			continue;
		element_set_si(t, - j);
		element_mul(r, r, t); /* num_muls++; */
		element_set_si(t, i - j);
		element_invert(t, t);
		element_mul(r, r, t); /* num_muls++; */
	}

	element_clear(t);
}

/*!
 * DecryptNode(E;D;x) algorithm for leaf node
 *
 * @param r				Pairing result
 * @param exp			Recursive exponent from DecryptNode(E;D;z) algorithm from non-leaf node above
 * @param p				Policy node dtat structure(leaf node x)
 * @param cph			Ciphertext data structure
 * @param pub			Public key data structure
 * @return				None
 */

void
dec_leaf_flatten( element_t r, element_t exp,
									kpabe_policy_t* p, kpabe_cph_t* cph, kpabe_pub_t* pub )
{
	kpabe_cph_comp_t* c;
	element_t s;

	c = &(cph->comps[p->attri]);

	element_init_GT(s, pub->p);

	pairing_apply(s, p->D,  c->E,  pub->p); /* num_pairings++; */
	element_pow_zn(s, s, exp); /* num_exps++; */
	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
}

void dec_node_flatten( element_t r, element_t exp,
											 kpabe_policy_t* p, kpabe_cph_t* cph, kpabe_pub_t* pub );

/*!
 * DecryptNode(E;D;z) algorithm for non-leaf node
 *
 * @param r				Pairing result
 * @param exp			Recursive exponent from DecryptNode(E;D;z) algorithm from non-leaf node above
 * @param p				Policy node dtat structure(non-leaf node z)
 * @param cph			Ciphertext data structure
 * @param pub			Public key data structure
 * @return				None
 */

void
dec_internal_flatten( element_t r, element_t exp,
											kpabe_policy_t* p, kpabe_cph_t* cph, kpabe_pub_t* pub )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl_len; i++ )
	{
		lagrange_coef(t, p->satl, p->satl_len, p->satl[i]);
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_flatten(r, expnew, &p->children[p->satl[i] - 1], cph, pub);
	}

	element_clear(t);
	element_clear(expnew);
}

/*!
 * Choose DecryptNode algorithm for non-leaf node and leaf node
 *
 * @param r				Pairing result
 * @param exp			Recursive exponent from DecryptNode(E;D;z) algorithm from non-leaf node above
 * @param p				Policy node data structure
 * @param cph			Ciphertext data structure
 * @param pub			Public key data structure
 * @return				None
 */

void
dec_node_flatten( element_t r, element_t exp,
									kpabe_policy_t* p, kpabe_cph_t* cph, kpabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children_len == 0 )
		dec_leaf_flatten(r, exp, p, cph, pub);
	else
		dec_internal_flatten(r, exp, p, cph, pub);
}

/*!
 * DecryptNode algorithm for root secret
 *
 * @param r				Root secret
 * @param p				Policy node dtat structure(root)
 * @param cph			Ciphertext data structure
 * @param pub			Public key data structure
 * @return				None
 */

void
dec_flatten( element_t r, kpabe_policy_t* p, kpabe_cph_t* cph, kpabe_pub_t* pub )
{
	element_t one;

	element_init_Zr(one, pub->p);

	element_set1(one);
	element_set1(r);

	dec_node_flatten(r, one, p, cph, pub);

	element_clear(one);
}

/*!
 * Decrypt the secret message m
 *
 * @param m                                 Byte string which will contain the plaintext
 * @param pub				Public key data structure
 * @param prv				Private key data structure
 * @param c                                   Byte string containing ciphertext
 * @param c_len                            Length of 'c'
 * @return int				Successfully decrypt (size of 'm') or not (0)
 */

void
kpabe_dec_byte_array( char m[MSG_LEN_CELIA+1], kpabe_pub_t* pub, kpabe_prv_t* prv, kpabe_cph_t* cph, char aes_buf[AES_LEN_CELIA] )
{
	int i;
	size_t a = 0;
	uint8_t tmp;
	element_t m_e;

	kpabe_dec(pub, prv, cph, m_e);

	aes_128_cbc_decrypt(m, aes_buf, m_e);
}

/*!
 * Decrypt the secret message m
 *
 * @param pub				Public key data structure
 * @param prv				Private key data structure
 * @param cph				Ciphertext data structure
 * @param m_e					Secret message
 * @return int				Successfully decrypt or not
 */

int
kpabe_dec( kpabe_pub_t* pub, kpabe_prv_t* prv, kpabe_cph_t* cph, element_t m_e )
{
	element_t Ys;
	element_init_GT(m_e, pub->p);
	element_init_GT(Ys, pub->p);
	
	if(!check_sat(&prv->p,  cph, pub))
		return 0;
 	if( !prv->p.satisfiable )
	{
		raise_error("cannot decrypt, attributes in ciphertext do not satisfy policy\n");
		return 0;
	}

	pick_sat_min_leaves(&prv->p);
	dec_flatten(Ys, &prv->p, cph, pub);
	element_div(m_e, cph->Ep, Ys);

	return 1;
}
