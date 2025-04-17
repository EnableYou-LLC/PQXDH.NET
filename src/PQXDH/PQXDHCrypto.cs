// PQXDH.NET - A cross-platform .NET implementation of the Post-Quantum Extended Diffie-Hellman Protocol
// This library provides encryption and decryption functionality based on the Signal PQXDH protocol
// which combines classic elliptic curve (X25519) with post-quantum Kyber algorithm

using System;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Security;
using PQXDH.Models;

namespace PQXDH
{
    /// <summary>
    /// Main PQXDH implementation providing Post-Quantum encryption and decryption
    /// </summary>
    public class PQXDHCrypto
    {
        // ML-KEM-1024 is used for maximum security (formerly Kyber-1024)
        
        /// <summary>
        /// Generates a key pair containing both X25519 and ML-KEM keys
        /// </summary>
        /// <returns>A hybrid key pair containing both classical and post-quantum keys</returns>
        public static Task<HybridKeyPair> GenerateKeyPairAsync()
        {
            // Generate X25519 key pair (classical)
            var x25519KeyPairGenerator = new X25519KeyPairGenerator();
            x25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            var x25519KeyPair = x25519KeyPairGenerator.GenerateKeyPair();
            
            var x25519PublicKey = (X25519PublicKeyParameters)x25519KeyPair.Public;
            var x25519PrivateKey = (X25519PrivateKeyParameters)x25519KeyPair.Private;
            
            var classicalPublicKey = x25519PublicKey.GetEncoded();
            var classicalPrivateKey = x25519PrivateKey.GetEncoded();

            // Generate ML-KEM key pair (post-quantum)
            var mlkemKeyPairGenerator = new MLKemKeyPairGenerator();
            mlkemKeyPairGenerator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), MLKemParameters.ml_kem_1024));
            var mlkemKeyPair = mlkemKeyPairGenerator.GenerateKeyPair();
            
            var mlkemPublicKey = (MLKemPublicKeyParameters)mlkemKeyPair.Public;
            var mlkemPrivateKey = (MLKemPrivateKeyParameters)mlkemKeyPair.Private;
            
            var pqPublicKey = mlkemPublicKey.GetEncoded();
            var pqPrivateKey = mlkemPrivateKey.GetEncoded();

            var result = new HybridKeyPair
            {
                ClassicalPublicKey = classicalPublicKey,
                ClassicalPrivateKey = classicalPrivateKey,
                PostQuantumPublicKey = pqPublicKey,
                PostQuantumPrivateKey = pqPrivateKey
            };
            
            return Task.FromResult(result);
        }

        /// <summary>
        /// Encrypts data using PQXDH protocol combining X25519 and ML-KEM
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="recipientPublicKey">The recipient's hybrid public key</param>
        /// <returns>Encrypted data with encapsulated key</returns>
        public static Task<EncryptedPackage> EncryptAsync(byte[] data, HybridPublicKey recipientPublicKey)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (recipientPublicKey == null)
                throw new ArgumentNullException(nameof(recipientPublicKey));

            // Step 1: Generate ephemeral keypair
            var ephemeralX25519KeyPairGenerator = new X25519KeyPairGenerator();
            ephemeralX25519KeyPairGenerator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            var ephemeralX25519KeyPair = ephemeralX25519KeyPairGenerator.GenerateKeyPair();
            var ephemeralX25519PublicKey = (X25519PublicKeyParameters)ephemeralX25519KeyPair.Public;
            var ephemeralX25519PrivateKey = (X25519PrivateKeyParameters)ephemeralX25519KeyPair.Private;

            // Step 2: Perform X25519 key agreement
            var x25519Agreement = new X25519Agreement();
            x25519Agreement.Init(ephemeralX25519PrivateKey);
            
            var recipientX25519PublicKey = new X25519PublicKeyParameters(recipientPublicKey.ClassicalKey, 0);
            
            byte[] classicalSharedSecret = new byte[32]; // X25519 produces 32-byte shared secrets
            x25519Agreement.CalculateAgreement(recipientX25519PublicKey, classicalSharedSecret, 0);

            // Step 3: Perform ML-KEM encapsulation
            var mlkemPublicKey = MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024, recipientPublicKey.PostQuantumKey);
            var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_1024);
            encapsulator.Init(new ParametersWithRandom(mlkemPublicKey, new SecureRandom()));
            
            // var encapsulationResult = mlkemKem.GenerateEncapsulated(recipientMlkemPublicKey);

            byte[] mlkemCiphertext = new byte[encapsulator.EncapsulationLength];
            byte[] mlkemSharedSecret = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(mlkemCiphertext, 0, mlkemCiphertext.Length, mlkemSharedSecret, 0, mlkemSharedSecret.Length);

            // Step 4: Combine the shared secrets
            byte[] combinedSharedSecret = CombineSharedSecrets(classicalSharedSecret, mlkemSharedSecret);

            // Step 5: Derive encryption key from combined shared secret
            byte[] encryptionKey = DeriveEncryptionKey(combinedSharedSecret);

            // Step 6: Encrypt the data with AES-GCM
            var encryptedData = EncryptWithAes(data, encryptionKey);

            // Step 7: Create the encrypted package
            var result = new EncryptedPackage
            {
                EphemeralClassicalPublicKey = ephemeralX25519PublicKey.GetEncoded(),
                KyberCiphertext = mlkemCiphertext,
                EncryptedData = encryptedData
            };
            
            return Task.FromResult(result);
        }

        /// <summary>
        /// Decrypts data using PQXDH protocol
        /// </summary>
        /// <param name="encryptedPackage">Package containing encrypted data and encapsulated key</param>
        /// <param name="recipientKeyPair">The recipient's hybrid key pair</param>
        /// <returns>Decrypted data</returns>
        public static Task<byte[]> DecryptAsync(EncryptedPackage encryptedPackage, HybridKeyPair recipientKeyPair)
        {
            if (encryptedPackage == null)
                throw new ArgumentNullException(nameof(encryptedPackage));
            if (recipientKeyPair == null)
                throw new ArgumentNullException(nameof(recipientKeyPair));

            // Step 1: Perform X25519 key agreement
            var recipientX25519PrivateKey = new X25519PrivateKeyParameters(recipientKeyPair.ClassicalPrivateKey, 0);
            var ephemeralX25519PublicKey = new X25519PublicKeyParameters(encryptedPackage.EphemeralClassicalPublicKey, 0);
            
            var x25519Agreement = new X25519Agreement();
            x25519Agreement.Init(recipientX25519PrivateKey);
            
            byte[] classicalSharedSecret = new byte[32]; // X25519 produces 32-byte shared secrets
            x25519Agreement.CalculateAgreement(ephemeralX25519PublicKey, classicalSharedSecret, 0);

            // Step 2: Perform ML-KEM decapsulation
           var mlKemPrivateKey = MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_1024, recipientKeyPair.PostQuantumPrivateKey);
            var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_1024);
            decapsulator.Init(mlKemPrivateKey);

            byte[] mlkemSharedSecret = new byte[decapsulator.SecretLength];
            decapsulator.Decapsulate(encryptedPackage.KyberCiphertext, 0, encryptedPackage.KyberCiphertext.Length, mlkemSharedSecret, 0, mlkemSharedSecret.Length);

            // Step 3: Combine the shared secrets
            byte[] combinedSharedSecret = CombineSharedSecrets(classicalSharedSecret, mlkemSharedSecret);

            // Step 4: Derive decryption key from combined shared secret
            byte[] decryptionKey = DeriveEncryptionKey(combinedSharedSecret);

            // Step 5: Decrypt the data with AES-GCM
            byte[] decryptedData = DecryptWithAes(encryptedPackage.EncryptedData, decryptionKey);
            
            return Task.FromResult(decryptedData);
        }

        #region Helper Methods

        private static byte[] CombineSharedSecrets(byte[] classicalSecret, byte[] quantumSecret)
        {
            // Combine secrets by concatenating and hashing with SHA-256
            var sha256 = new Sha256Digest();
            var combined = new byte[classicalSecret.Length + quantumSecret.Length];
            Buffer.BlockCopy(classicalSecret, 0, combined, 0, classicalSecret.Length);
            Buffer.BlockCopy(quantumSecret, 0, combined, classicalSecret.Length, quantumSecret.Length);
            
            byte[] result = new byte[32];
            sha256.BlockUpdate(combined, 0, combined.Length);
            sha256.DoFinal(result, 0);
            
            return result;
        }

        private static byte[] DeriveEncryptionKey(byte[] sharedSecret)
        {
            // Use PBKDF2 via Bouncy Castle
            byte[] salt = new byte[] { 0x43, 0x87, 0x23, 0x72, 0x45, 0x56, 0x68, 0x14, 0x62, 0x84 };
            int iterations = 10000;
            
            var pbeParametersGenerator = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pbeParametersGenerator.Init(
                sharedSecret,
                salt,
                iterations);
            
            var derivedKey = (KeyParameter)pbeParametersGenerator.GenerateDerivedMacParameters(256);
            return derivedKey.GetKey();
        }
        
        private static EncryptedData EncryptWithAes(byte[] data, byte[] key)
        {
            byte[] iv = new byte[16];
            var random = new SecureRandom();
            random.NextBytes(iv);
            
            // Use GCM mode from Bouncy Castle
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);
            cipher.Init(true, parameters);
            
            byte[] encryptedBytes = new byte[cipher.GetOutputSize(data.Length)];
            int len = cipher.ProcessBytes(data, 0, data.Length, encryptedBytes, 0);
            cipher.DoFinal(encryptedBytes, len);
            
            // Extract the tag (last 16 bytes)
            byte[] tag = new byte[16];
            Buffer.BlockCopy(encryptedBytes, encryptedBytes.Length - 16, tag, 0, 16);
            
            // Remove the tag from the ciphertext
            var actualCiphertext = new byte[encryptedBytes.Length - 16];
            Buffer.BlockCopy(encryptedBytes, 0, actualCiphertext, 0, actualCiphertext.Length);
            
            return new EncryptedData
            {
                IV = iv,
                CipherText = actualCiphertext,
                AuthTag = tag
            };
        }
        
        private static byte[] DecryptWithAes(EncryptedData encryptedData, byte[] key)
        {
            // Combine ciphertext and tag for Bouncy Castle GCM
            byte[] ciphertextWithTag = new byte[encryptedData.CipherText.Length + encryptedData.AuthTag.Length];
            Buffer.BlockCopy(encryptedData.CipherText, 0, ciphertextWithTag, 0, encryptedData.CipherText.Length);
            Buffer.BlockCopy(encryptedData.AuthTag, 0, ciphertextWithTag, encryptedData.CipherText.Length, encryptedData.AuthTag.Length);
            
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, encryptedData.IV, null);
            cipher.Init(false, parameters);
            
            byte[] decryptedBytes = new byte[cipher.GetOutputSize(ciphertextWithTag.Length)];
            int len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, decryptedBytes, 0);
            cipher.DoFinal(decryptedBytes, len);
            
            return decryptedBytes;
        }

        #endregion
    }
}