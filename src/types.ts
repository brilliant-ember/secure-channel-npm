// Cross-platform crypto types
export interface CryptoKey {
  readonly type: 'secret' | 'private' | 'public';
  readonly extractable: boolean;
  readonly algorithm: string;
}

export interface CryptoKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface SubtleCrypto {
  // Key operations
  generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): Promise<any>;
  deriveBits(algorithm: any, baseKey: any, length: number): Promise<ArrayBuffer>;
  importKey(format: string, keyData: any, algorithm: any, extractable: boolean, keyUsages: string[]): Promise<any>;
  exportKey(format: string, key: any): Promise<ArrayBuffer>;
  
  // Encryption/decryption
  encrypt(algorithm: any, key: any, data: any): Promise<ArrayBuffer>;
  decrypt(algorithm: any, key: any, data: any): Promise<ArrayBuffer>;
  
  // Sign/verify
  sign(algorithm: any, key: any, data: any): Promise<ArrayBuffer>;
  verify(algorithm: any, key: any, signature: any, data: any): Promise<boolean>;
  
  // Key derivation
  deriveKey(algorithm: any, baseKey: any, derivedKeyAlgorithm: any, extractable: boolean, keyUsages: string[]): Promise<any>;
}