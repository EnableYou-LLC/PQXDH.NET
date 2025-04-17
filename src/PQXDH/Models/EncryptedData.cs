using System;

namespace PQXDH.Models
{
    /// <summary>
    /// Container for AES-GCM encrypted data with authentication
    /// </summary>
    public class EncryptedData
    {
        /// <summary>
        /// The initialization vector for AES-GCM
        /// </summary>
        public byte[] IV { get; set; } = Array.Empty<byte>();
    
        /// <summary>
        /// The encrypted data
        /// </summary>
        public byte[] CipherText { get; set; } = Array.Empty<byte>();
    
        /// <summary>
        /// The authentication tag for verifying integrity
        /// </summary>
        public byte[] AuthTag { get; set; } = Array.Empty<byte>();
    }
}