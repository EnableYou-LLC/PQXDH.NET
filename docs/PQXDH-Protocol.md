# PQXDH Protocol Specification

## Introduction

Post-Quantum Extended Diffie-Hellman (PQXDH) is a key agreement protocol designed by Signal to enhance the security of the X3DH (Extended Triple Diffie-Hellman) protocol against quantum computing threats. This document provides a detailed explanation of the PQXDH protocol as implemented in the PQXDH library.

## Protocol Overview

PQXDH combines classical elliptic curve cryptography with post-quantum cryptography to create a hybrid approach that maintains security even if one of the cryptographic schemes is compromised. The protocol uses:

- **X25519**: A widely used elliptic curve Diffie-Hellman key exchange mechanism
- **ML-KEM**: The NIST-standardized version of CRYSTALS-Kyber, a lattice-based Key Encapsulation Mechanism (KEM)

## Key Components

### Key Types

PQXDH uses the following key types:

1. **Identity Keys**:
   - Classical Identity Key: Long-term X25519 key pair
   - Post-Quantum Identity Key: Long-term ML-KEM key pair

2. **Ephemeral Keys**:
   - Classical Ephemeral Key: One-time X25519 key pair
   - Post-Quantum One-Time Prekey: One-time ML-KEM key pair

### Cryptographic Primitives

The protocol uses the following cryptographic primitives:

- **X25519**: For elliptic curve Diffie-Hellman key exchange
- **ML-KEM**: For post-quantum key encapsulation
- **SHA-256**: For combining shared secrets
- **PBKDF2**: For key derivation from the combined shared secret
- **AES-GCM**: For authenticated encryption of messages

## Protocol Operation

### Key Generation

Both communicating parties generate and maintain:
- A long-term X25519 key pair
- A long-term ML-KEM key pair

### One-Way Communication (A → B)

For Alice to send a message to Bob:

1. **Key Retrieval**:
   - Alice retrieves Bob's public keys (X25519 and ML-KEM)

2. **Ephemeral Key Generation**:
   - Alice generates an ephemeral X25519 key pair

3. **Classical Key Agreement**:
   - Alice computes a shared secret using her ephemeral X25519 private key and Bob's X25519 public key

4. **Post-Quantum Key Encapsulation**:
   - Alice encapsulates a shared secret for Bob using his ML-KEM public key
   - This produces a ciphertext and a shared secret

5. **Key Combination**:
   - Alice combines the X25519 shared secret and the ML-KEM shared secret by concatenating them and applying SHA-256

6. **Key Derivation**:
   - Alice derives an encryption key from the combined shared secret using PBKDF2-HMAC-SHA256

7. **Message Encryption**:
   - Alice encrypts her message using AES-GCM with the derived key

8. **Package Creation**:
   - Alice creates a package containing:
     - Her ephemeral X25519 public key
     - The ML-KEM ciphertext
     - The encrypted message with IV and authentication tag

9. **Sending**:
   - Alice sends the package to Bob

### Decryption (B receives from A)

When Bob receives a package from Alice:

1. **Classical Key Agreement**:
   - Bob computes a shared secret using his X25519 private key and Alice's ephemeral X25519 public key

2. **Post-Quantum Key Decapsulation**:
   - Bob decapsulates the ML-KEM ciphertext using his ML-KEM private key to obtain the shared secret

3. **Key Combination**:
   - Bob combines the X25519 shared secret and the ML-KEM shared secret using the same method as Alice

4. **Key Derivation**:
   - Bob derives the decryption key from the combined shared secret using PBKDF2-HMAC-SHA256

5. **Message Decryption**:
   - Bob decrypts the message using AES-GCM with the derived key and the provided IV and authentication tag

## Security Properties

### Hybrid Security

PQXDH provides security if either the classical or the post-quantum component remains secure:

- If quantum computers break X25519, the ML-KEM component provides security
- If ML-KEM has vulnerabilities, the X25519 component provides security

### Forward Secrecy

PQXDH provides forward secrecy through the use of ephemeral keys:

- Even if long-term private keys are compromised in the future
- Past communications remain secure
- Each message uses a unique ephemeral key, ensuring independence between messages

### Authentication

The protocol provides implicit authentication:

- Only the intended recipient with the correct private keys can decrypt the message
- The authentication tag in AES-GCM ensures message integrity and authenticity

## Protocol Limitations

PQXDH has the following limitations:

1. Not designed to protect against active quantum attackers with contemporaneous access
2. Relies on the security of the AEAD (Authenticated Encryption with Associated Data) algorithm
3. Does not provide non-repudiation (this is by design)
4. Requires secure distribution of public keys

## Implementation Notes

In the PQXDH library implementation:

1. ML-KEM-1024 is used as the post-quantum algorithm, providing the highest security level
2. Key generation, encapsulation, and decapsulation use the Bouncy Castle cryptographic library
3. AES-GCM with 128-bit authentication tags is used for encryption
4. PBKDF2 with 10,000 iterations is used for key derivation

## Differences from X3DH

PQXDH differs from X3DH in the following ways:

1. Adds a post-quantum component (ML-KEM) alongside the classical component
2. Uses KEM for the post-quantum component instead of another Diffie-Hellman exchange
3. Combines shared secrets to derive a single encryption key

## References

1. Signal's PQXDH Protocol: https://signal.org/docs/specifications/pqxdh/
2. NIST FIPS 203 (ML-KEM): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf
3. X3DH Protocol: https://signal.org/docs/specifications/x3dh/
4. CRYSTALS-Kyber: https://pq-crystals.org/kyber/