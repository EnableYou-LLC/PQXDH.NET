# PQXDH Documentation

Welcome to the PQXDH documentation. This library provides a .NET implementation of the Post-Quantum Extended Diffie-Hellman (PQXDH) protocol, offering hybrid cryptographic security that combines classical elliptic curve cryptography with post-quantum algorithms.

## Contents

- [Getting Started](#getting-started)
- [Basic Concepts](#basic-concepts)
- [Detailed Documentation](#detailed-documentation)
- [Security Considerations](#security-considerations)
- [FAQ](#faq)

## Getting Started

To integrate PQXDH into your .NET project, first install the package:

```bash
dotnet add package PQXDH
```

Then add the using directive to your code:

```csharp
using PQXDH;
```

## Basic Concepts

PQXDH is a hybrid cryptographic protocol that combines:

1. **Classical Cryptography**: X25519 elliptic curve Diffie-Hellman key exchange
2. **Post-Quantum Cryptography**: ML-KEM (Module Lattice-based Key Encapsulation Mechanism, formerly known as CRYSTALS-Kyber)

The core components of PQXDH are:

- **Key Pairs**: Contain both classical (X25519) and post-quantum (ML-KEM) key components
- **Hybrid Key Agreement**: Performs both classical and post-quantum key exchanges
- **Combined Security**: Requires breaking both classical and post-quantum components to compromise the encryption

## Detailed Documentation

For more detailed information, refer to these documentation pages:

- [API Documentation](API.md): Complete API reference for the PQXDH library
- [PQXDH Protocol](PQXDH-Protocol.md): Detailed explanation of the PQXDH protocol
- [Crypto Primitives](https://en.wikipedia.org/wiki/Cryptographic_primitive): Information about the underlying cryptographic primitives

## Basic Usage Example

```csharp
// Generate key pairs for both parties
var aliceKeyPair = await PQXDHCrypto.GenerateKeyPairAsync();
var bobKeyPair = await PQXDHCrypto.GenerateKeyPairAsync();

// Alice encrypts a message for Bob
string message = "Hello Bob! This is a secret message.";
byte[] plaintext = Encoding.UTF8.GetBytes(message);
var encryptedPackage = await PQXDHCrypto.EncryptAsync(plaintext, bobKeyPair.GetPublicKey());

// Bob decrypts the message
byte[] decryptedData = await PQXDHCrypto.DecryptAsync(encryptedPackage, bobKeyPair);
string decryptedMessage = Encoding.UTF8.GetString(decryptedData);

Console.WriteLine(decryptedMessage); // Outputs: Hello Bob! This is a secret message.
```

## Security Considerations

When using PQXDH, keep the following security considerations in mind:

1. **Key Management**: Securely store private keys, particularly identity keys
2. **Key Rotation**: Regularly rotate keys for long-term security
3. **Random Number Generation**: Ensure your environment has high-quality random number generation
4. **Side-Channel Attacks**: Be aware of potential side-channel vulnerabilities in your application
5. **Dependency Updates**: Keep the Bouncy Castle library updated to the latest version

## FAQ

### Why use hybrid cryptography?

Hybrid cryptography combines classical and post-quantum algorithms to provide security against both classical and quantum attacks. It ensures that even if one system is compromised, the other continues to provide protection.

### What security level does PQXDH provide?

PQXDH uses ML-KEM-1024, which provides a security level roughly equivalent to AES-256, making it suitable for protecting highly sensitive information against future quantum attacks.

### Is PQXDH standardized?

PQXDH itself is not a standard, but it uses standardized components. The post-quantum component, ML-KEM, is standardized by NIST in FIPS 203, and the classical component, X25519, is widely standardized and used.

### How does PQXDH compare to other post-quantum protocols?

PQXDH is specifically designed as an enhancement to Signal's X3DH protocol, focusing on asynchronous messaging scenarios. Other post-quantum protocols may have different design goals and security properties.

### Can I use PQXDH for TLS or other protocols?

While the core cryptographic operations of PQXDH could be adapted for other protocols, this library is specifically designed for asynchronous message encryption following the PQXDH protocol. For TLS, consider dedicated post-quantum TLS libraries.