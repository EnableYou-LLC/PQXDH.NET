using System;
using System.Text;
using System.Threading.Tasks;
using PQXDH;

namespace PQXDH.Demo
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("PQXDH.NET Demo - Post-Quantum Encryption and Decryption");
            Console.WriteLine("--------------------------------------------------------");
            Console.WriteLine();

            await DemoBasicEncryptionDecryption();
            
            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static async Task DemoBasicEncryptionDecryption()
        {
            Console.WriteLine("Demo: Basic Encryption/Decryption");
            Console.WriteLine("--------------------------------");

            // Alice and Bob generate their key pairs
            Console.WriteLine("Generating key pairs for Alice and Bob...");
            var aliceKeyPair = await PQXDHCrypto.GenerateKeyPairAsync();
            var bobKeyPair = await PQXDHCrypto.GenerateKeyPairAsync();

            // The message that Alice wants to send to Bob
            string originalMessage = "Hello Bob! This is a secret message encrypted with post-quantum cryptography!";
            byte[] originalData = Encoding.UTF8.GetBytes(originalMessage);
            Console.WriteLine($"Original message: {originalMessage}");

            // Alice encrypts the message for Bob
            Console.WriteLine("Alice encrypts the message for Bob...");
            var encryptedPackage = await PQXDHCrypto.EncryptAsync(originalData, bobKeyPair.GetPublicKey());

            Console.WriteLine($"Message encrypted. Package contains:");
            Console.WriteLine($" - Ephemeral Classical Public Key: {encryptedPackage.EphemeralClassicalPublicKey.Length} bytes");
            Console.WriteLine($" - ML-KEM Ciphertext: {encryptedPackage.KyberCiphertext.Length} bytes");
            Console.WriteLine($" - Encrypted Data: {encryptedPackage.EncryptedData.CipherText.Length} bytes");
            Console.WriteLine($" - IV: {BytesToHex(encryptedPackage.EncryptedData.IV)}");
            Console.WriteLine($" - Auth Tag: {BytesToHex(encryptedPackage.EncryptedData.AuthTag)}");

            // Bob decrypts the message
            Console.WriteLine("Bob decrypts the message...");
            byte[] decryptedData = await PQXDHCrypto.DecryptAsync(encryptedPackage, bobKeyPair);
            string decryptedMessage = Encoding.UTF8.GetString(decryptedData);

            Console.WriteLine($"Decrypted message: {decryptedMessage}");
            Console.WriteLine($"Decryption successful: {originalMessage == decryptedMessage}");
            
            // Demonstrate compromise scenarios
            Console.WriteLine();
            Console.WriteLine("Security Analysis:");
            Console.WriteLine("-----------------");
            
            Console.WriteLine("1. Classical (X25519) security only:");
            Console.WriteLine("   - If quantum computers break elliptic curve cryptography");
            Console.WriteLine("   - But ML-KEM remains secure");
            Console.WriteLine("   - The message remains secure due to the hybrid approach");
            
            Console.WriteLine();
            Console.WriteLine("2. Post-quantum (ML-KEM) security only:");
            Console.WriteLine("   - If ML-KEM has vulnerabilities");
            Console.WriteLine("   - But X25519 remains secure");
            Console.WriteLine("   - The message remains secure due to the hybrid approach");
            
            Console.WriteLine();
            Console.WriteLine("3. Forward secrecy:");
            Console.WriteLine("   - Even if long-term keys are compromised in the future");
            Console.WriteLine("   - Past messages cannot be decrypted");
            Console.WriteLine("   - Due to the use of ephemeral keys for each message");

            // Implementation details
            Console.WriteLine();
            Console.WriteLine("Implementation Details:");
            Console.WriteLine("----------------------");
            Console.WriteLine("This library uses:");
            Console.WriteLine("- X25519 for classical key exchange");
            Console.WriteLine("- ML-KEM-1024 for post-quantum key encapsulation (NIST standardized version of Kyber)");
            Console.WriteLine("- SHA-256 for combining shared secrets");
            Console.WriteLine("- PBKDF2 for key derivation");
            Console.WriteLine("- AES-GCM for authenticated encryption");
            Console.WriteLine("- Bouncy Castle 2.5.0+ for all cryptographic operations");
            
            // Key sizes
            Console.WriteLine();
            Console.WriteLine("Key and Ciphertext Sizes:");
            Console.WriteLine("------------------------");
            Console.WriteLine($"X25519 Public Key: {aliceKeyPair.ClassicalPublicKey.Length} bytes");
            Console.WriteLine($"X25519 Private Key: {aliceKeyPair.ClassicalPrivateKey.Length} bytes");
            Console.WriteLine($"ML-KEM-1024 Public Key: {aliceKeyPair.PostQuantumPublicKey.Length} bytes");
            Console.WriteLine($"ML-KEM-1024 Private Key: {aliceKeyPair.PostQuantumPrivateKey.Length} bytes");
            Console.WriteLine($"ML-KEM-1024 Ciphertext: {encryptedPackage.KyberCiphertext.Length} bytes");
            Console.WriteLine($"Combined Shared Secret Size: 32 bytes (after hashing)");
        }

        private static string BytesToHex(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
                return string.Empty;
                
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);
                
            if (hex.Length > 16)
                return hex.ToString(0, 16) + "...";
            else
                return hex.ToString();
        }
    }
}