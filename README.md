# PQXDH.NET

A cross-platform .NET implementation of the Post-Quantum Extended Diffie-Hellman (PQXDH) protocol, providing hybrid encryption that combines classical elliptic curve cryptography with post-quantum algorithms to protect against future quantum computing threats.

## Features

- **Hybrid Encryption**: Combines X25519 elliptic curve with ML-KEM (NIST-standardized version of CRYSTALS-Kyber) for dual protection
- **Future-Proof Security**: Protects against both classical and quantum computing attacks
- **Forward Secrecy**: Uses ephemeral keys to ensure past communications remain secure
- **Authenticated Encryption**: Uses AES-GCM to provide confidentiality, integrity, and authenticity
- **Multi-Target Support**: Compatible with .NET Standard 2.0 and above
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Wide Framework Support**: Compatible with .NET Framework 4.6.1+, .NET Core 2.0+, .NET 5.0+, Xamarin, Unity, UWP and more
- **NIST-Standardized Algorithms**: Uses ML-KEM (Module Lattice-based Key Encapsulation Mechanism), the NIST-standardized version of CRYSTALS-Kyber

## Installation

```bash
dotnet add package PQXDH
```

## Quick Start

```csharp
using System;
using System.Text;
using System.Threading.Tasks;
using PQXDH;

// Generate a key pair for the recipient
var bobKeyPair = await PQXDHCrypto.GenerateKeyPairAsync();

// The message to encrypt
string message = "Hello, post-quantum world!";
byte[] messageBytes = Encoding.UTF8.GetBytes(message);

// Encrypt the message for Bob
var encryptedPackage = await PQXDHCrypto.EncryptAsync(messageBytes, bobKeyPair.GetPublicKey());

// Bob decrypts the message
byte[] decryptedBytes = await PQXDHCrypto.DecryptAsync(encryptedPackage, bobKeyPair);
string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

Console.WriteLine(decryptedMessage); // Outputs: Hello, post-quantum world!
```

## About PQXDH

PQXDH (Post-Quantum Extended Diffie-Hellman) is a [cryptographic protocol developed by Signal](https://signal.org/docs/specifications/pqxdh/) to enhance the security of the X3DH key exchange protocol against quantum computing threats. It combines the classical X25519 elliptic curve with post-quantum algorithms in a hybrid approach.

### Why Hybrid Cryptography?

The hybrid approach ensures that:

1. If classical cryptography (X25519) is broken by quantum computers, the ML-KEM layer still protects your data
2. If the post-quantum algorithm (ML-KEM) has vulnerabilities, the classical layer still provides security
3. An attacker would need to break both systems to compromise the encrypted data

This library implements the PQXDH protocol specification as defined by Signal, adapted for use in .NET applications.

## About ML-KEM

ML-KEM (Module Lattice-based Key Encapsulation Mechanism) is the NIST-standardized version of CRYSTALS-Kyber, one of the winners of the NIST Post-Quantum Cryptography standardization process. In April 2023, NIST published FIPS 203 which standardizes Kyber as ML-KEM.

This library uses ML-KEM-1024, which provides the highest security level of the ML-KEM family:

- **ML-KEM-512**: Security roughly equivalent to AES-128
- **ML-KEM-768**: Security roughly equivalent to AES-192
- **ML-KEM-1024**: Security roughly equivalent to AES-256 (used in this library)

## Platform Compatibility

PQXDH.NET is designed to be widely compatible with .NET platforms through multi-targeting:

- **.NET Standard 2.0+**: Base compatibility layer
- **.NET Framework 4.6.1+**: For traditional Windows applications
- **.NET Core 2.0+**: For cross-platform applications
- **.NET 5.0/6.0/7.0/8.0/9.0**: For modern applications
- **Xamarin/MAUI**: For mobile applications
- **Unity**: For game development
- **UWP**: For Windows Store applications

## Implementation Details

PQXDH.NET uses:

- **X25519**: For classical elliptic curve key exchange
- **ML-KEM-1024**: For post-quantum key encapsulation (the most secure ML-KEM parameter set)
- **SHA-256**: For combining shared secrets
- **PBKDF2**: For key derivation from shared secrets
- **AES-GCM**: For authenticated encryption of the actual data
- **Bouncy Castle**: For all cryptographic operations, ensuring high-quality implementations

## Advanced Usage

### Key Management

```csharp
// Generate a key pair
var keyPair = await PQXDHCrypto.GenerateKeyPairAsync();

// Extract just the public components for sharing
var publicKey = keyPair.GetPublicKey();

// The public key can be serialized and shared with others
byte[] serializedPublicKey = SerializePublicKey(publicKey); // Implement your serialization

// Later, deserialize and use for encryption
var deserializedPublicKey = DeserializePublicKey(serializedPublicKey); // Implement your deserialization
var encryptedData = await PQXDHCrypto.EncryptAsync(data, deserializedPublicKey);
```

### File Encryption

```csharp
// Encrypt a file
byte[] fileContents = File.ReadAllBytes("secret.pdf");
var encryptedPackage = await PQXDHCrypto.EncryptAsync(fileContents, recipientPublicKey);

// Save the encrypted package
SaveEncryptedPackage(encryptedPackage, "secret.pdf.encrypted"); // Implement your serialization

// Later, load and decrypt
var loadedPackage = LoadEncryptedPackage("secret.pdf.encrypted"); // Implement your deserialization
byte[] decryptedFile = await PQXDHCrypto.DecryptAsync(loadedPackage, recipientKeyPair);
File.WriteAllBytes("decrypted.pdf", decryptedFile);
```

## Security Considerations

- **Key Storage**: Securely store private keys; consider using platform secure storage mechanisms
- **Key Rotation**: Regularly generate new key pairs for long-term security
- **Random Number Generation**: The library uses cryptographically secure random number generation
- **Side-Channel Attacks**: Be aware of potential side-channel vulnerabilities in your application
- **Dependency Security**: Keep Bouncy Castle and other dependencies updated to the latest versions

## Dependencies

- **BouncyCastle.Cryptography**: For cryptographic operations including ML-KEM (version 2.5.0+)
- **System.Memory**: For efficient memory operations in .NET Standard 2.0

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Signal for the PQXDH protocol specification
- The CRYSTALS-Kyber/ML-KEM team for their post-quantum algorithm
- NIST for standardizing ML-KEM in FIPS 203
- The Bouncy Castle team for their comprehensive cryptography library
- The .NET cryptography community

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ✨ Generative AI Notice

This project, including the entire codebase, documentation, and project structure were created through collaborative prompting with Anthropic's Claude 3.7 Sonnet. This represents an experiment in AI-assisted software development, demonstrating how generative AI can support the creation of specialized cryptographic libraries.

While the implementation follows established cryptographic protocols and best practices, users should conduct their own security reviews before using this library in production environments.