using System;

namespace PQXDH.Models
{
    /// <summary>
    /// Represents an encrypted message package with all components needed for decryption
    /// </summary>
    public class EncryptedPackage
    {
        /// <summary>
        /// The ephemeral classical X25519 public key used for this encryption
        /// </summary>
        public byte[] EphemeralClassicalPublicKey { get; set; } = Array.Empty<byte>();
    
        /// <summary>
        /// The Kyber ciphertext containing the encapsulated key
        /// </summary>
        public byte[] KyberCiphertext { get; set; } = Array.Empty<byte>();
    
        /// <summary>
        /// The encrypted data with its authentication tag and initialization vector
        /// </summary>
        public EncryptedData EncryptedData { get; set; } = new EncryptedData();
    }
}