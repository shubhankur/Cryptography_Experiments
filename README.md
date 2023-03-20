# Cryptography_Experiments


Call different cryptographic functions and measure the speed of different cryptographic
operations. For that purpose, it would need to create or read a small file of size 1KB and a large file of size 10MB.
These can be randomly generated data or existing files of any type (of the specified size). The program is to
implement and measure the runtime of the following functionalities:

(a)Create a 128-bit AES key, encrypt and decrypt each of the two files using AES
in the CBC mode. AES implementations need to be based on hardware implementation of AES, so ensure that
your libraries are chosen or configured properly.

(b) Repeat part (a) using AES in the CTR mode.

(c) Repeat part (b) with a 256-bit key.

(d) Create a 2048-bit RSA key, encrypt and decrypt the files above with PKCS #1v2 padding (at least v2.0, but use v2.2 if available; it may also be called OAEP). This experiment can use a 1MB
file for the second file size to reduce the runtime.

(e) Repeat part (d) with a 3072-bit key. This experiment can use a 1MB file for
the second file size to reduce the runtime.

(f) Compute a hash of each of the files using hash functions SHA-256, SHA-512,
and SHA3-256.

(g) Create a 2048-bit DSA key, sign the two files and verify the corresponding
signatures. If creating a key takes two parameters, use 224 bits for the exponent size. If the hash function algorithm
needs to specified separately, use SHA-256.

(h) Repeat part (g) with a 3072-bit DSA key (if the second parameter is required, use 256).

Include simple checking of correctness of your code, namely, that computed ciphertexts decrypt to the original data and that signed messages properly verify. (There is no need to test whether the library functions themselves
work correctly.)

Your program will need to measure the following execution times:

1. For each encryption experiment (a)–(e), measure (i) the time it take to generate a new key, (ii) the total time it takes to encrypt each of the two files, (iii) the total time it takes to
   decrypt each file, and also compute (iv) encryption speed per byte for both files and (v) decryption speed per byte
   for both files.
2. For each hash function experiment listed in part (f), measure the total time to compute the hash of both files and compute per-byte timings.

    3.For each signature experiment, measure (i) the key generation time, and (ii) the
time to produce a signature for both files, (iii) the time to verify a signature on both of the files, and compute per-byte time for (iv) signing and (v) signature verification for both files.
