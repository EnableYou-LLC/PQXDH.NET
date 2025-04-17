using System;

namespace PQXDH.Models
{
    /// <summary>
    /// Contains both classical (X25519) and post-quantum (Kyber) keys
    /// </summary>
    public class HybridKeyPair
    {
        /// <summary>
        /// The classical X25519 public key
        /// </summary>
        public byte[] ClassicalPublicKey { get; set; } = Array.Empty<byte>();
    
        /// <summary>
        /// The classical X25519 private key
        /// </summary>
        public byte[] ClassicalPrivateKey { get; set; } = Array.Empty<byte>();
    
        /// <summary>
        /// The post-quantum Kyber public key
        /// </summary>
        public byte[] PostQuantumPublicKey { get; set; } = Array.Empty<byte>();
    
        /// <summary>
        /// The post-quantum Kyber private key
        /// </summary>
        public byte[] PostQuantumPrivateKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Returns a public key pair derived from this key pair
        /// </summary>
        /// <returns>A hybrid public key containing only the public components</returns>
        public HybridPublicKey GetPublicKey()
        {
            return new HybridPublicKey
            {
                ClassicalKey = ClassicalPublicKey,
                PostQuantumKey = PostQuantumPublicKey
            };
        }
    }
}
