using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace PQXDH.Tests
{
    public class PQXDHCryptoTests
    {
        [Fact]
        public async Task KeyGeneration_ShouldCreateValidKeyPair()
        {
            // Act
            var keyPair = await PQXDHCrypto.GenerateKeyPairAsync();

            // Assert
            Assert.NotNull(keyPair);
            Assert.NotNull(keyPair.ClassicalPublicKey);
            Assert.NotNull(keyPair.ClassicalPrivateKey);
            Assert.NotNull(keyPair.PostQuantumPublicKey);
            Assert.NotNull(keyPair.PostQuantumPrivateKey);

            Assert.True(keyPair.ClassicalPublicKey.Length > 0);
            Assert.True(keyPair.ClassicalPrivateKey.Length > 0);
            Assert.True(keyPair.PostQuantumPublicKey.Length > 0);
            Assert.True(keyPair.PostQuantumPrivateKey.Length > 0);
        }

        [Fact]
        public async Task EncryptDecrypt_ShouldReturnOriginalData()
        {
            // Arrange
            var keyPair = await PQXDHCrypto.GenerateKeyPairAsync();
            var originalData = Encoding.UTF8.GetBytes("This is a test message for PQXDH encryption.");

            // Act
            var encryptedPackage = await PQXDHCrypto.EncryptAsync(originalData, keyPair.GetPublicKey());
            var decryptedData = await PQXDHCrypto.DecryptAsync(encryptedPackage, keyPair);

            // Assert
            Assert.Equal(originalData, decryptedData);
        }

        [Fact]
        public async Task Encrypt_WithDifferentData_ShouldCreateDifferentCiphertext()
        {
            // Arrange
            var keyPair = await PQXDHCrypto.GenerateKeyPairAsync();
            var data1 = Encoding.UTF8.GetBytes("Message 1");
            var data2 = Encoding.UTF8.GetBytes("Message 2");

            // Act
            var package1 = await PQXDHCrypto.EncryptAsync(data1, keyPair.GetPublicKey());
            var package2 = await PQXDHCrypto.EncryptAsync(data2, keyPair.GetPublicKey());

            // Assert
            Assert.NotEqual(
                Convert.ToBase64String(package1.EncryptedData.CipherText),
                Convert.ToBase64String(package2.EncryptedData.CipherText));
        }

        [Fact]
        public async Task Encrypt_WithSameData_ShouldCreateDifferentCiphertext()
        {
            // Arrange
            var keyPair = await PQXDHCrypto.GenerateKeyPairAsync();
            var data = Encoding.UTF8.GetBytes("Same message");

            // Act
            var package1 = await PQXDHCrypto.EncryptAsync(data, keyPair.GetPublicKey());
            var package2 = await PQXDHCrypto.EncryptAsync(data, keyPair.GetPublicKey());

            // Assert - Ephemeral keys should make the same message encrypt differently each time
            Assert.NotEqual(
                Convert.ToBase64String(package1.EncryptedData.CipherText),
                Convert.ToBase64String(package2.EncryptedData.CipherText));

            Assert.NotEqual(
                Convert.ToBase64String(package1.EphemeralClassicalPublicKey),
                Convert.ToBase64String(package2.EphemeralClassicalPublicKey));
        }

        [Fact]
        public async Task Decrypt_WithWrongKeyPair_ShouldNotDecryptCorrectly()
        {
            // Arrange
            var senderKeyPair = await PQXDHCrypto.GenerateKeyPairAsync();
            var recipientKeyPair = await PQXDHCrypto.GenerateKeyPairAsync();
            var wrongKeyPair = await PQXDHCrypto.GenerateKeyPairAsync();

            var originalData = Encoding.UTF8.GetBytes("Secret message");

            // Act
            var encryptedPackage = await PQXDHCrypto.EncryptAsync(originalData, recipientKeyPair.GetPublicKey());

            // Assert
            // This should throw an authentication exception when using AES-GCM 
            // due to authentication tag verification failure
            await Assert.ThrowsAnyAsync<Exception>(() =>
                PQXDHCrypto.DecryptAsync(encryptedPackage, wrongKeyPair));
        }

        [Fact]
        public async Task LargeData_ShouldEncryptAndDecryptCorrectly()
        {
            // Arrange
            var keyPair = await PQXDHCrypto.GenerateKeyPairAsync();

            // Create a large data set (100 KB)
            var originalData = new byte[100 * 1024];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(originalData);
            }

            // Act
            var encryptedPackage = await PQXDHCrypto.EncryptAsync(originalData, keyPair.GetPublicKey());
            var decryptedData = await PQXDHCrypto.DecryptAsync(encryptedPackage, keyPair);

            // Assert
            Assert.Equal(originalData, decryptedData);
        }
    }
}