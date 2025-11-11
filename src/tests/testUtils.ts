// // Utility functions for testing
// export async function generateTestKeyPair(): Promise<CryptoKeyPair> {
//   const { webcrypto } = await import('crypto');
//   return webcrypto.subtle.generateKey(
//     { name: 'X25519' },
//     true,
//     ['deriveKey', 'deriveBits']
//   ) as Promise<CryptoKeyPair>;
// }

// export function createMockEncryptionResult(): { ciphertext: Uint8Array; nonce: Uint8Array } {
//   return {
//     ciphertext: new Uint8Array(64),
//     nonce: new Uint8Array(12),
//   };
// }