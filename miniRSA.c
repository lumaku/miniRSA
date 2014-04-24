/*
 * miniRSA.c
 *
 *  Created on: 12.02.2014
 *
 *  https://github.com/lumaku/miniRSA
 *
 * Copyright (c) 2014 Ludwig Kürzinger
 * under the MIT license
 *
 */

#include "miniRSA.h"


// Alle brauchbaren Primzahlen von 5 .. 251
const uint16_t RSA_Primes [] = {
		0x0005, 0x0007, 0x000b, 0x000d, 0x0011, 0x0013, 0x0017, 0x001d, 0x001f, 0x0025,
		0x0029, 0x002b, 0x002f, 0x0035, 0x003b, 0x003d, 0x0043, 0x0047, 0x0049, 0x004f,
		0x0053, 0x0059, 0x0061, 0x0065, 0x0067, 0x006b, 0x006d, 0x0071, 0x007f, 0x0083,
		0x0089, 0x008b, 0x0095, 0x0097, 0x009d, 0x00a3, 0x00a7, 0x00ad, 0x00b3, 0x00b5,
		0x00bf, 0x00c1, 0x00c5, 0x00c7, 0x00d3, 0x00df, 0x00e3, 0x00e5, 0x00e9, 0x00ef,
		0x00f1, 0x00fb
 };
const uint16_t RSA_NumerOfPrimes = 52;

// possible numbers for e
// (a 16 bit number can't possibly contain all of them as factors)
const uint16_t RSA_SmallPrimes[] ={ 2, 3, 5, 7, 11, 13, 17, 19 };
const uint16_t RSA_NumberOfSmallPrimes = 8;


uint32_t random_state  =  0xabcd1234;

uint16_t RSA_n; // basis
uint16_t RSA_e = 2; // public key
uint16_t RSA_d; // private key

uint16_t RSA_Phi; // phi.

uint16_t RSA_s; // signature
uint16_t RSA_h; // challenge the user has to sign


void RSA_generate_new_keypair(uint32_t seed)
{
	uint16_t temp_index;
	uint16_t temp_index_p;
	uint16_t temp_index_q;
	uint16_t p = 2;
	uint16_t q = 3;
	uint16_t Phi;

	// new p, q
	temp_index = Das_kannste_schon_so_machen_aber_dann_isses_halt_kacke(seed);
	temp_index_p = temp_index % RSA_NumerOfPrimes;
	do {
		temp_index = Das_kannste_schon_so_machen_aber_dann_isses_halt_kacke(temp_index++);
		temp_index_q = temp_index % RSA_NumerOfPrimes;
	} while (temp_index_p == temp_index_q);

	p = RSA_Primes[temp_index_p];
	q = RSA_Primes[temp_index_q];

	// new n
	RSA_n = p * q;

	// new h
	temp_index = Das_kannste_schon_so_machen_aber_dann_isses_halt_kacke(temp_index);
	RSA_h = temp_index % RSA_n;

	//  Euler Phi funktion
	Phi = ( p - 1 ) * ( q - 1 );
	RSA_Phi = Phi;

	// Calc public key e
	RSA_e = RSA_find_relative_prime(Phi);

	// d*e = 1 mod (Phi)
	RSA_d = RSA_ExtEuklid(RSA_e, Phi);

	// sign
	RSA_s =  RSA_modulo_exponentiation(RSA_h, RSA_d);
}

uint16_t RSA_get_n()
{
	return RSA_n;
}

uint16_t RSA_get_public_key()
{
	return RSA_e;
}

uint16_t RSA_get_private_key() // should. not. use.
{
	return RSA_d;
}

uint16_t RSA_get_correct_signature()
{
	return RSA_s;
}

uint16_t RSA_get_challenge()
{
	return RSA_h;
}

uint16_t RSA_ExtEuklid(uint16_t u, uint16_t v)
{
	// source: Knuths Art of Computer Programming, vol 2, Algorithm X
	// compute gcd
	// d * e + k * phi = 1
	// u * u1 + v * u2 = u3
	// returns d (the private key)

	// programming this in the worst possible way :)
	int32_t u1 = 0;
	int32_t u2 = 0;
	int32_t u3 = 0;
	int32_t v1 = 0;
	int32_t v2 = 0;
	int32_t v3 = 0;
	int32_t t1;
	int32_t t2;
	int32_t t3;
//	int32_t rest;
	int32_t q;

	// init
	u1 = 1;
	u2 = 0;
	u3 = (int32_t) u;
	v1 = 0;
	v2 = 1;
	v3 = (int32_t) v;

	while (v3 != 0) // step 2
	{ // step 3
		// pre - step
		q = u3 / v3;
		//rest = u3 % v3;

		// first step
		t1 = u1 - q * v1;
		t2 = u2 - q * v2;
		t3 = u3 - q * v3;

		// second step
		// u <- v
		u1 = v1;
		u2 = v2;
		u3 = v3;

		// v <- t
		v1 = t1;
		v2 = t2;
		v3 = t3;
	}

	if (u1 < 0) {
		u1 = v + u1;
		return ((uint16_t)u1);
	} else {
		return ((uint16_t)u1);
	}
}


uint16_t RSA_find_relative_prime(uint16_t phi)
{
	uint16_t i;
	uint16_t Rest;
	for (i = 0; i < RSA_NumberOfSmallPrimes; i++) {
		// gcd(i,phi) = 1
		Rest = phi % RSA_SmallPrimes[i];
		if (Rest) {
			return RSA_SmallPrimes[i];
		}
	}
	return 23; // man kanns ja mal versuchen.
}


uint16_t RSA_modulo_exponentiation(uint16_t x, uint16_t y)
{
	// x hoch y
	uint16_t temp_n = RSA_n;
	uint16_t temp_x = x;
	uint16_t temp_y = y % RSA_Phi;
	uint16_t temp_y_bit;
	uint16_t mask = 0x8000;
	uint16_t temp_z = 1;

	if (x == 0) {
		return 0;
	}

	if (y == 0) {
		return 1;
	}

	// algorithmus: square-and-multiply
	do {
		temp_z = RSA_modulo_multiplication( temp_z , temp_z , temp_n);
		temp_y_bit = temp_y & mask;
		mask = mask >> 1;
		if (temp_y_bit) {
			temp_z = RSA_modulo_multiplication( temp_z , temp_x , temp_n);
		}
	} while (mask);

	return temp_z;
}

uint16_t RSA_modulo_multiplication(uint16_t x, uint16_t y, uint16_t n)
{
	if ((x == 0) || (y == 0)) {
		return 0;
	}

	uint32_t temp_n = ((uint32_t) (n));
	uint32_t temp_x = ((uint32_t) (x) % temp_n);
	uint32_t temp_y = ((uint32_t) (y) % temp_n);
	uint32_t temp_z = 0;


	temp_z = temp_x * temp_y;
	temp_z = temp_z % temp_n;

	return ((uint16_t) (temp_z & 0xffff));
}

uint16_t RSA_modulo_addition(uint16_t x, uint16_t y, uint16_t n)
{
	uint32_t temp_n = ((uint32_t) (n));
	uint32_t temp_x = ((uint32_t) (x)) % temp_n;
	uint32_t temp_y = ((uint32_t) (y)) % temp_n;
	uint32_t temp_z = 0;

	if (x == 0) {
		return y;
	}

	if (y == 0) {
		return x;
	}

	temp_z = (temp_x + temp_y) % temp_n;

	return ((uint16_t) temp_z);
}


uint16_t Das_kannste_schon_so_machen_aber_dann_isses_halt_kacke(uint32_t seed)
{
	// sporadious random number generator
	uint32_t temp = seed;

	temp ^= (temp << 16) % Modulo_Prime;
	random_state ^= temp;

	return ((uint16_t)(random_state & 0xffff));
}


