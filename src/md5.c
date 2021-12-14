/*
 * 	md5.c (RFC1321)
 *
 * 	Copyright (C) 2004-2005 Bart�omiej Korupczynski <bartek@klolik.org>
 *
 * 	This program is free software; you can redistribute it and/or
 * 	modify it under the terms of the GNU General Public License
 * 	as published by the Free Software Foundation; either
 * 	version 2 of the License, or (at your option) any later
 * 	version.
 *
 * 	This program is distributed in the hope that it will be useful,
 * 	but WITHOUT ANY WARRANTY; without even the implied warranty of
 * 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * 	GNU General Public License for more details.
 *
 * 	You should have received a copy of the GNU General Public License
 * 	along with this program; if not, write to the Free Software
 * 	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

//#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>


#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_BYTESWAP_H
#include <byteswap.h>
#endif
#ifdef HAVE_MACHINE_BSWAP_H
#include <machine/bswap.h>
#endif

#ifdef SWAP32
#undef SWAP32
#endif
#if !defined(SWAP32) && defined(HAVE_DECL_BSWAP_32) && HAVE_DECL_BSWAP_32
/* Linux */
#define SWAP32(x)	bswap_32(x)
#endif
#if !defined(SWAP32) && defined(HAVE_DECL_BSWAP32) && HAVE_DECL_BSWAP32
/* FreeBSD */
#define SWAP32(x)	bswap32(x)
#endif
#if !defined(SWAP32) && defined(HAVE_DECL_SWAP32) && HAVE_DECL_SWAP32
/* OpenBSD */
#define SWAP32(x)	swap32(x)
#endif
#if !defined(SWAP32) && defined(HAVE_DECL___SWAP32) && HAVE_DECL___SWAP32
#define SWAP32(x)	__swap32(x)
#endif

#if !defined(SWAP32)
#warning No native byteswap, possible performance loss
#define SWAP32(x)	\
	( (((x) & 0xff000000) >> 24) | \
	  (((x) & 0x00ff0000) >>  8) | \
	  (((x) & 0x0000ff00) <<  8) | \
	  (((x) & 0x000000ff) << 24) )
#endif


#if !defined(IS_LITTLE_ENDIAN) && !defined(IS_BIG_ENDIAN)
#error unknown machine endianess
#endif
#ifdef IS_LITTLE_ENDIAN
#define LSB_FIRST(x)	SWAP32(x)
#else
#define LSB_FIRST(x)	(x)
#endif


#include "md5.h"


/*
 * 	MD5 T[]
*/

#define T_1	0xd76aa478
#define T_2	0xe8c7b756
#define T_3	0x242070db
#define T_4	0xc1bdceee
#define T_5	0xf57c0faf
#define T_6	0x4787c62a
#define T_7	0xa8304613
#define T_8	0xfd469501
#define T_9	0x698098d8
#define T_10	0x8b44f7af
#define T_11	0xffff5bb1
#define T_12	0x895cd7be
#define T_13	0x6b901122
#define T_14	0xfd987193
#define T_15	0xa679438e
#define T_16	0x49b40821
#define T_17	0xf61e2562
#define T_18	0xc040b340
#define T_19	0x265e5a51
#define T_20	0xe9b6c7aa
#define T_21	0xd62f105d
#define T_22	0x02441453
#define T_23	0xd8a1e681
#define T_24	0xe7d3fbc8
#define T_25	0x21e1cde6
#define T_26	0xc33707d6
#define T_27	0xf4d50d87
#define T_28	0x455a14ed
#define T_29	0xa9e3e905
#define T_30	0xfcefa3f8
#define T_31	0x676f02d9
#define T_32	0x8d2a4c8a
#define T_33	0xfffa3942
#define T_34	0x8771f681
#define T_35	0x6d9d6122
#define T_36	0xfde5380c
#define T_37	0xa4beea44
#define T_38	0x4bdecfa9
#define T_39	0xf6bb4b60
#define T_40	0xbebfbc70
#define T_41	0x289b7ec6
#define T_42	0xeaa127fa
#define T_43	0xd4ef3085
#define T_44	0x04881d05
#define T_45	0xd9d4d039
#define T_46	0xe6db99e5
#define T_47	0x1fa27cf8
#define T_48	0xc4ac5665
#define T_49	0xf4292244
#define T_50	0x432aff97
#define T_51	0xab9423a7
#define T_52	0xfc93a039
#define T_53	0x655b59c3
#define T_54	0x8f0ccc92
#define T_55	0xffeff47d
#define T_56	0x85845dd1
#define T_57	0x6fa87e4f
#define T_58	0xfe2ce6e0
#define T_59	0xa3014314
#define T_60	0x4e0811a1
#define T_61	0xf7537e82
#define T_62	0xbd3af235
#define T_63	0x2ad7d2bb
#define T_64	0xeb86d391


// aux functions
#define F(_x, _y, _z)		((_x & _y) | ((~_x) & _z))
#define G(_x, _y, _z)		((_x & _z) | (_y & (~_z)))
#define H(_x, _y, _z)		(_x ^ _y ^ _z)
#define I(_x, _y, _z)		(_y ^ (_x | (~_z)))

#define S(_j, s1, s2, s3, s4)	( (_j%4) == 1 ? s1 : ( (_j%4) == 2 ? s2 : ( (_j%4) == 3 ? s3 : s4 ) ) )
#define S1(_j)			S(_j, 7, 12, 17, 22)
#define S2(_j)			S(_j, 5, 9, 14, 20)
#define S3(_j)			S(_j, 4, 11, 16, 23)
#define S4(_j)			S(_j, 6, 10, 15, 21)

#define K(_j, _f, _fi, _cm, _rm)	(( _f + _cm *((_j-_fi)%4) + _rm * ((_j-_fi)/4) )%16)
#define K1(_j)			K(_j, 0,  1, 1,  4)
#define K2(_j)			K(_j, 1, 17, 5,  4)
#define K3(_j)			K(_j, 5, 33, 3, 12)
#define K4(_j)			K(_j, 0, 49, 7, 12)

// cyclic shift left
#define L(_y, _n)		(((_y) << (_n)) | ((_y) >> (32-(_n))))

// rounds
#define R1(_a, _b, _c, _d, _x, _i) \
	_a += F(_b, _c, _d) + (_x[K1(_i)]) + ((uint32_t) (T_##_i)); \
	_a = L(_a, S1(_i)); \
	_a += (_b);
#define R2(_a, _b, _c, _d, _x, _i) \
	_a += G(_b, _c, _d) + (_x[K2(_i)]) + ((uint32_t) (T_##_i)); \
	_a = L(_a, S2(_i)); \
	_a += (_b);
#define R3(_a, _b, _c, _d, _x, _i) \
	_a += H(_b, _c, _d) + (_x[K3(_i)]) + ((uint32_t) (T_##_i)); \
	_a = L(_a, S3(_i)); \
	_a += (_b);
#define R4(_a, _b, _c, _d, _x, _i) \
	_a += I(_b, _c, _d) + (_x[K4(_i)]) + ((uint32_t) (T_##_i)); \
	_a = L(_a, S4(_i)); \
	_a += (_b);


/*
 * 	constants
*/

static unsigned char padding[64] = { 0x80, 0 /* 0, ... */ };

static char base64[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
}; /* [A-Z][a-z][0-9][+/] */

/*
 *	copy swapped 32bit words (make little endian)
 *	len in 32-bit words
*/

#ifndef IS_LITTLE_ENDIAN
static inline void block_to_le(uint32_t *dst, uint32_t *src, int len)
{
	for(; len>0; len--) {
		*dst = SWAP32(*src);
		dst++;
		src++;
	}
}
static inline void block_to_le_inplace(uint32_t *ptr, int len)
{
	for(; len>0; len--) {
		*ptr = SWAP32(*ptr);
		ptr++;
	}
}
#endif

/*
 * 	md5 one block, assumes correct byte endianess
*/

static void md5_block(uint32_t state[4], uint32_t x[16])
{
	uint32_t a, b, c, d;

#if 0
	for (a=0; a<16; a++) {
		printf("%08x", SWAP32(x[a]));
		if (a%2==1) printf(" ");
	}

	printf("\n");
#endif

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	/* round 1 */
	R1(a, b, c, d, x,  1); R1(d, a, b, c, x,  2); R1(c, d, a, b, x,  3); R1(b, c, d, a, x,  4);
	R1(a, b, c, d, x,  5); R1(d, a, b, c, x,  6); R1(c, d, a, b, x,  7); R1(b, c, d, a, x,  8);
	R1(a, b, c, d, x,  9); R1(d, a, b, c, x, 10); R1(c, d, a, b, x, 11); R1(b, c, d, a, x, 12);
	R1(a, b, c, d, x, 13); R1(d, a, b, c, x, 14); R1(c, d, a, b, x, 15); R1(b, c, d, a, x, 16);
	/* round 2 */
	R2(a, b, c, d, x, 17); R2(d, a, b, c, x, 18); R2(c, d, a, b, x, 19); R2(b, c, d, a, x, 20);
	R2(a, b, c, d, x, 21); R2(d, a, b, c, x, 22); R2(c, d, a, b, x, 23); R2(b, c, d, a, x, 24);
	R2(a, b, c, d, x, 25); R2(d, a, b, c, x, 26); R2(c, d, a, b, x, 27); R2(b, c, d, a, x, 28);
	R2(a, b, c, d, x, 29); R2(d, a, b, c, x, 30); R2(c, d, a, b, x, 31); R2(b, c, d, a, x, 32);
	/* round 3 */
	R3(a, b, c, d, x, 33); R3(d, a, b, c, x, 34); R3(c, d, a, b, x, 35); R3(b, c, d, a, x, 36);
	R3(a, b, c, d, x, 37); R3(d, a, b, c, x, 38); R3(c, d, a, b, x, 39); R3(b, c, d, a, x, 40);
	R3(a, b, c, d, x, 41); R3(d, a, b, c, x, 42); R3(c, d, a, b, x, 43); R3(b, c, d, a, x, 44);
	R3(a, b, c, d, x, 45); R3(d, a, b, c, x, 46); R3(c, d, a, b, x, 47); R3(b, c, d, a, x, 48);
	/* round 4 */
	R4(a, b, c, d, x, 49); R4(d, a, b, c, x, 50); R4(c, d, a, b, x, 51); R4(b, c, d, a, x, 52);
	R4(a, b, c, d, x, 53); R4(d, a, b, c, x, 54); R4(c, d, a, b, x, 55); R4(b, c, d, a, x, 56);
	R4(a, b, c, d, x, 57); R4(d, a, b, c, x, 58); R4(c, d, a, b, x, 59); R4(b, c, d, a, x, 60);
	R4(a, b, c, d, x, 61); R4(d, a, b, c, x, 62); R4(c, d, a, b, x, 63); R4(b, c, d, a, x, 64);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

/*
 * 	init state
*/

static inline void md5_init(uint32_t state[4])
{
	state[0] = 0x67452301;
	state[1] = 0xefcdab89;
	state[2] = 0x98badcfe;
	state[3] = 0x10325476;
}

/*
 * 	md5 encode string
 * 	(max length: 2^32-1 characters)
*/

void md5(uint32_t hash[4], void *data, size_t len)
{
	uint32_t state[4];
	uint32_t bitlen, i, left;
	char buf[64];


	/* init */
	md5_init(state);
	bitlen = len << 3;

	/* process */
	for (i = len/64; i>0; i--) {
#ifdef IS_LITTLE_ENDIAN
		md5_block(state, (uint32_t *) data);
#else
		block_to_le((uint32_t *) buf, (uint32_t *) data, 16);
		md5_block(state, (uint32_t *) buf);
#endif
		data += 64;
	}

	/* finalize */
	left = len % 64;
	if (left) memcpy(buf, data, left);

	if (left < 56) {
		memcpy(buf+left, padding, 56-left);
	} else {
		memcpy(buf+left, padding, 64-left);
#ifndef IS_LITTLE_ENDIAN
		block_to_le_inplace((uint32_t *) buf, 16);
#endif
		md5_block(state, (uint32_t *) buf);
		memset(buf, 0, 56); /* == memcpy(buf, padding+1, 56); */
	}

	memcpy(&buf[56], &bitlen, 4);
	memset(&buf[60], '\0', 4);
#ifndef IS_LITTLE_ENDIAN
	// don't touch last two words (bitlength)
	block_to_le_inplace((uint32_t *) buf, 14);
#endif
	md5_block(state, (uint32_t *) buf);

	/* result */
	memcpy(hash, state, 16); /* 4*uint32 = 16 bytes */
#ifndef IS_LITTLE_ENDIAN
	block_to_le_inplace(hash, 4);
#endif
}


/*
 * 	md5 string -> hex (static)
 * 	128 bits => 32 chars + '\0'
*/

char* md5_hex(void* data, size_t len)
{
	uint32_t buf[4];
	static char hash[33];

	if (!data) return NULL;

	md5(buf, data, len);
	snprintf(hash, sizeof(hash), "%08x%08x%08x%08x", LSB_FIRST(buf[0]), LSB_FIRST(buf[1]), LSB_FIRST(buf[2]), LSB_FIRST(buf[3]));
	hash[sizeof(hash)-1] = '\0';

	return hash;
}

char* md5_string_hex(char* str)
{
	return md5_hex(str, strlen(str));
}

/*
 * 	md5 string -> base64 (static)
 * 	128bits => 22 chars + '\0'
 * 	(base64 padding is missing)
*/

char* md5_base64(void* data, size_t len)
{
	uint32_t buf32[4];
	static char hash[23];
	unsigned char *buf8 = (unsigned char *) buf32;
	char *pos = hash;
	int i;


	if (!data) return NULL;

	memset(hash, '\0', sizeof(hash));
	md5(buf32, data, len);

	for (i=5;; i--) {
		*pos = base64[*buf8 >> 2];
		pos++;

		if (i == 0) {
			*pos = base64[(*buf8 << 4) & 0x3f];
			break;
		}

		*pos = base64[( (*buf8 << 4) | (buf8[1] >> 4) ) & 0x3f];
		pos++;
		buf8++;

		*pos = base64[( (*buf8 & 0x0f) << 2) |  ((buf8[1] >> 6))];
		pos++;
		buf8++;

		*pos = base64[*buf8 & 0x3f];
		pos++;
		buf8++;
	}

	hash[sizeof(hash)-1] = '\0';
	return hash;
}

char* md5_string_base64(char* str)
{
	return md5_base64(str, strlen(str));
}


/*
 * 	main - command line testing
*/

#ifdef MD5_TEST

char *test_strings[] = {
	"d41d8cd98f00b204e9800998ecf8427e", "",
	"0cc175b9c0f1b6a831c399e269772661", "a",
	"900150983cd24fb0d6963f7d28e17f72", "abc",
	"f96b697d7cb7938d525a2f31aaf161d0", "message digest",
	"c3fcd3d76192e4007dfb496cca67e13b", "abcdefghijklmnopqrstuvwxyz",
	"d174ab98d277d9f5a5611c2c9f419d9f", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"57edf4a22be3c955ac49da2e2107b67a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	"f40a0ec3fbf6cf062c9faf3752bd6e6c", "123456789012345678901234567890123456789012345678901234",
	"c9ccf168914a1bcfc3229f1948e67da0", "1234567890123456789012345678901234567890123456789012345",
	"49f193adce178490e34d1b3a4ec0064c", "12345678901234567890123456789012345678901234567890123456",
	"23339de0ceca03763ff42d807768964d", "123456789012345678901234567890123456789012345678901234567",
	NULL
};

int test_suite()
{
	char *result;
	char **pos;
	int fails;

	printf("RFC1321 test suite:\n\n");

	fails = 0;
	for (pos = test_strings; *pos != NULL; pos += 2) {
		result = md5_string_hex(pos[1]);

		if (strcmp(result, pos[0]) == 0) {
			printf("%-4s %-32s \"%s\"\n", "OK", result, pos[1]);
		} else {
			printf("%-4s %-32s \"%s\"\n", "FAIL", result, pos[1]);
			printf("%-4s %-32s\n", "EXP", pos[0]);
			fails++;
		}
	}

	exit(fails != 0);
}


int main(int argc, char* argv[])
{
	char *endianess;

#ifdef IS_LITTLE_ENDIAN
	endianess = "little-endian";
#else
	endianess = "big-endian";
#endif

	if (argc < 2) {
		printf("Usage: %s [ -t | STRING ]\n\n", argv[0]);
		printf("Machine endianess: %s\n", endianess);
		exit(1);
	}

	if (strcmp(argv[1], "-t") == 0) {
		test_suite();
		exit(3);
	}

	printf("%s\n", md5_string_hex(argv[1]));
	printf("%s\n", md5_string_base64(argv[1]));
	exit(0);
}

#endif
