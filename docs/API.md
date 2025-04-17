# PQXDH API Documentation

This document provides detailed information about the PQXDH library's API.

## Table of Contents

- [Main Classes](#main-classes)
- [PQXDHCrypto](#pqxdhcrypto)
- [HybridKeyPair](#hybridkeypair)
- [HybridPublicKey](#hybridpublickey)
- [EncryptedPackage](#encryptedpackage)
- [EncryptedData](#encrypteddata)
- [Usage Examples](#usage-examples)

## Main Classes

The PQXDH library consists of the following main classes:

| Class | Description |
|-------|-------------|
| `PQXDHCrypto` | Main class containing encryption and decryption methods |
| `HybridKeyPair` | Represents a key pair containing both classical and post-quantum keys |
| `HybridPublicKey` | Represents a public key containing both classical and post-quantum components |
| `EncryptedPackage` | Container for encrypted data and associated cryptographic materials |
| `EncryptedData` | Holds the encrypted data with initialization vector and authentication tag |

## PQXDHCrypto

The main class that provides encryption and decryption functionality.

### Methods

#### GenerateKeyPairAsync

```csharp
public static Task<HybridKeyPair> GenerateKeyPairAsync()
```

Generates a new hybrid key pair containing both X25519 and ML-KEM keys.

**Returns**: A `Task<HybridKeyPair>` containing the generated key pair.

**Example**:
```csharp
HybridKeyPair keyPair = await PQXDHCrypto.GenerateKeyPairAsync();
```

#### EncryptAsync

```csharp
public static Task<EncryptedPackage> EncryptAsync(byte[] data, HybridPublicKey recipientPublicKey)
```

Encrypts data for a recipient using their hybrid public key.

**Parameters**:
- `data`: The data to encrypt.
- `recipientPublicKey`: The recipient's hybrid public key.

**Returns**: A `Task<EncryptedPackage>` containing the encrypted data and associated cryptographic material.

**Exceptions**:
- `ArgumentNullException`: Thrown if `data` or `recipientPublicKey` is null.

**Example**:
```csharp
byte[] data = Encoding.UTF8.GetBytes("Secret message");
EncryptedPackage package = await PQXDHCrypto.EncryptAsync(data, recipientPublicKey);
```

#### DecryptAsync

```csharp
public static Task<byte[]> DecryptAsync(EncryptedPackage encryptedPackage, HybridKeyPair recipientKeyPair)
```

Decrypts data using the recipient's hybrid key pair.

**Parameters**:
- `encryptedPackage`: The encrypted package to decrypt.
- `recipientKeyPair`: The recipient's hybrid key pair.

**Returns**: A `Task<byte[]>` containing the decrypted data.

**Exceptions**:
- `ArgumentNullException`: Thrown if `encryptedPackage` or `recipientKeyPair` is null.
- `InvalidOperationException`: Thrown if decryption fails, likely due to an incorrect key pair or tampered data.

**Example**:
```csharp
byte[] decryptedData = await PQXDHCrypto.DecryptAsync(encryptedPackage, recipientKeyPair);
string message = Encoding.UTF8.GetString(decryptedData);
```

## HybridKeyPair

Represents a key pair containing both classical (X25519) and post-quantum (ML-KEM) keys.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `ClassicalPublicKey` | `byte[]` | The X25519 public key |
| `ClassicalPrivateKey` | `byte[]` | The X25519 private key |
| `PostQuantumPublicKey` | `byte[]` | The ML-KEM public key |
| `PostQuantumPrivateKey` | `byte[]` | The ML-KEM private key |

### Methods

#### GetPublicKey

```csharp
public HybridPublicKey GetPublicKey()
```

Returns a public key containing only the public components of this key pair.

**Returns**: A `HybridPublicKey` containing the public components.

**Example**:
```csharp
HybridPublicKey publicKey = keyPair.GetPublicKey();
```

## HybridPublicKey

Represents a public key containing both classical (X25519) and post-quantum (ML-KEM) components.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `ClassicalKey` | `byte[]` | The X25519 public key |
| `PostQuantumKey` | `byte[]` | The ML-KEM public key |

## EncryptedPackage

Container for encrypted data and associated cryptographic materials.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `EphemeralClassicalPublicKey` | `byte[]` | The ephemeral X25519 public key used for encryption |
| `KyberCiphertext` | `byte[]` | The ML-KEM ciphertext containing the encapsulated key |
| `EncryptedData` | `EncryptedData` | The encrypted data with authentication information |

## EncryptedData

Holds the encrypted data along with the initialization vector and authentication tag.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `IV` | `byte[]` | The initialization vector used for AES-GCM encryption |
| `CipherText` | `byte[]` | The encrypted data |
| `AuthTag` | `byte[]` | The authentication tag for validating data integrity |

## Usage Examples

### Basic Encryption and Decryption

```csharp
using System;
using System.Text;
using System.Threading.Tasks;
using PQXDH;

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

### Serialization Example

```csharp
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using PQXDH;

// Serialize a hybrid public key to JSON
static string SerializePublicKey(HybridPublicKey publicKey)
{
    var dto = new
    {
        ClassicalKey = Convert.ToBase64String(publicKey.ClassicalKey),
        PostQuantumKey = Convert.ToBase64String(publicKey.PostQuantumKey)
    };
    return JsonSerializer.Serialize(dto);
}

// Deserialize a hybrid public key from JSON
static HybridPublicKey DeserializePublicKey(string json)
{
    var dto = JsonSerializer.Deserialize<PublicKeyDto>(json);
    return new HybridPublicKey
    {
        ClassicalKey = Convert.FromBase64String(dto.ClassicalKey),
        PostQuantumKey = Convert.FromBase64String(dto.PostQuantumKey)
    };
}

// Helper DTO class
private class PublicKeyDto
{
    public string ClassicalKey { get; set; }
    public string PostQuantumKey { get; set; }
}
```

### File Encryption Example

```csharp
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using PQXDH;

// Encrypt a file
static async Task EncryptFileAsync(string sourceFilePath, string destFilePath, HybridPublicKey recipientKey)
{
    byte[] fileData = File.ReadAllBytes(sourceFilePath);
    var encryptedPackage = await PQXDHCrypto.EncryptAsync(fileData, recipientKey);
    
    // Serialize the encrypted package
    using FileStream fs = File.Create(destFilePath);
    await JsonSerializer.SerializeAsync(fs, new
    {
        EphemeralClassicalPublicKey = Convert.ToBase64String(encryptedPackage.EphemeralClassicalPublicKey),
        KyberCiphertext = Convert.ToBase64String(encryptedPackage.KyberCiphertext),
        IV = Convert.ToBase64String(encryptedPackage.EncryptedData.IV),
        CipherText = Convert.ToBase64String(encryptedPackage.EncryptedData.CipherText),
        AuthTag = Convert.ToBase64String(encryptedPackage.EncryptedData.AuthTag)
    });
}

// Decrypt a file
static async Task<byte[]> DecryptFileAsync(string encryptedFilePath, HybridKeyPair recipientKeyPair)
{
    using FileStream fs = File.OpenRead(encryptedFilePath);
    var dto = await JsonSerializer.DeserializeAsync<EncryptedPackageDto>(fs);
    
    var encryptedPackage = new EncryptedPackage
    {
        EphemeralClassicalPublicKey = Convert.FromBase64String(dto.EphemeralClassicalPublicKey),
        KyberCiphertext = Convert.FromBase64String(dto.KyberCiphertext),
        EncryptedData = new EncryptedData
        {
            IV = Convert.FromBase64String(dto.IV),
            CipherText = Convert.FromBase64String(dto.CipherText),
            AuthTag = Convert.FromBase64String(dto.AuthTag)
        }
    };
    
    return await PQXDHCrypto.DecryptAsync(encryptedPackage, recipientKeyPair);
}

// Helper DTO class
private class EncryptedPackageDto
{
    public string EphemeralClassicalPublicKey { get; set; }
    public string KyberCiphertext { get; set; }
    public string IV { get; set; }
    public string CipherText { get; set; }
    public string AuthTag { get; set; }
}
```