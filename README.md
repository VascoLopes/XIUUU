# XIUUU: Safe Sharing of Cryptographic Secrets


The main objective of this project is to implement a system that allows to exchange encrypted secrets between two entities in a reliable and secure way.

This project integrate and make available a series of distribution schemes and key exchange protocols, and also ways to generate new keys  from passwords.

In a more detailed way, XIUUU provides:
- Generating a cryptographic secret from user-entered passwords, namely through the algorithm Password Based Key Derivation Function 2 (PBKDF2)
- Exchange of a cryptographic secret using the Diffie-Hellman key agreement protocol;
- Exchange of a cryptographic secret using Merkle's Puzzles;
- Exchange of a cryptographic secret using the Rivest Shamir Adleman (RSA);
- Distribution of new cipher keys from pre-distributed keys;
- Distribution of new cipher keys using a trusted agent which is the chosen server;
- Exchanges that use RSA also use X.509 digital certificates;
- Digital signature for integrity check in key exchanges that use Diffie-Hellman protocol;
- The choice of different cipher algorithms for Merkle Puzzles;
- The choice of different hash functions for PBKDF2.


