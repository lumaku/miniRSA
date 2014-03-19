/*
 * miniRSA.h
 *
 *  Created on: 12.02.2014
 *
 *  https://github.com/lumaku/miniRSA
 *
The MIT License (MIT)

Copyright (c) 2014 Ludwig Kürzinger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
.
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
