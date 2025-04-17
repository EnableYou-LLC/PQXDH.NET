using System;

namespace PQXDH.Models
{
    /// <summary>
    /// Contains both classical (X25519) and post-quantum (Kyber) public keys
    /// </summary>
    public class HybridPublicKey
    {
        /// <summary>
        /// The classical X25519 public key
        /// </summary>
        public byte[] ClassicalKey { get; set; } = Array.Empty<byte>();
    
        /// <summary>
        /// The post-quantum Kyber public key
        /// </summary>
        public byte[] PostQuantumKey { get; set; } = Array.Empty<byte>();
    }
}