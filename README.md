miniRSA
=======

Features:
 o RSA implementation in C
 o keylength up to 16 bit
 o just for having fun while learning crypto

Explanation of RSA:
-------------------

Variables: 
 o n is the product of two prime numbers p * q = n
 o d is the (secret) private key
 o e is the public key
 o c is the challenge (also known as h)
 o s = c^d is the signed challenge

