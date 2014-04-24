/*
 * miniRSA.h
 *
 *  Created on: 12.02.2014
 *
 *  https://github.com/lumaku/miniRSA
 *
 * Copyright (c) 2014 Ludwig Kürzinger
 * Under the terms of the MIT license.
 */

#ifndef MINIRSA_H_
#define MINIRSA_H_

#include "config.h"
#include <stdio.h>
#include <inttypes.h>


#define Modulo_Prime      99529

void RSA_generate_new_keypair(uint32_t seed);

// public key
uint16_t RSA_get_n();
uint16_t RSA_get_public_key();

// public challenge
uint16_t RSA_get_challenge();


// SECRET!!!
uint16_t RSA_get_private_key();
uint16_t RSA_get_correct_signature();

//  internal functions
uint16_t RSA_ExtEuklid(uint16_t e, uint16_t phi);
uint16_t RSA_find_relative_prime(uint16_t phi);
uint16_t RSA_modulo_exponentiation(uint16_t x, uint16_t y);
uint16_t RSA_modulo_multiplication(uint16_t x, uint16_t y, uint16_t n);
uint16_t RSA_modulo_addition(uint16_t x, uint16_t y, uint16_t n);
uint16_t Das_kannste_schon_so_machen_aber_dann_isses_halt_kacke(uint32_t seed);



#endif /* MINIRSA_H_ */
