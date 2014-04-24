miniRSA
=======

Features:
- RSA implementation in C
- key length up to 16 bit
- just for having fun while learning crypto

Explanation of RSA:
-------------------

See [the wikipedia page on RSA](https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29).

Variables: 
- n is the product of two prime numbers p * q = n
- d is the (secret) private key
- e is the public key
- c is the challenge (also known as h)
- s = c^d is the signed challenge

