import { byteArrayToBase64, base64StringToByteArr } from './helpers';
import { CryptoKey, CryptoKeyPair, SubtleCrypto } from './types';

/**
 * Cross-platform signature verification client
 * Uses Ed25519 for signing and verification
 */
export class Signature {
  private static instance: Signature | null = null;
  private static initialized = false;

  private subtle: SubtleCrypto | null = null;
  private keypair: CryptoKeyPair | null = null;
  private serverPublicKey: CryptoKey | null = null;

  private constructor() {}

  /**
   * Get singleton instance of Signature
   * @returns Promise<Signature>
   */
  public static async getInstance(): Promise<Signature> {
    if (!this.initialized) {
      this.instance = new Signature();
      await this.instance.init();
      this.initialized = true;
    }
    return this.instance!;
  }

  /**
   * Initialize with server's public key for verification
   * @param serverPublicKeyB64 Server's Ed25519 public key in base64 format
   */
  public async initializeServerKey(serverPublicKeyB64: string): Promise<void> {
    if (!this.subtle) throw new Error('Crypto not initialized');

    const serverPublicKeyBytes = base64StringToByteArr(serverPublicKeyB64);
    
    this.serverPublicKey = await this.subtle.importKey(
      'raw',
      serverPublicKeyBytes as any,
      { name: 'Ed25519' },
      false, // not extractable
      ['verify']
    );
  }

  /**
   * Update server's public key (for key rotation)
   * @param serverPublicKeyB64 Server's new Ed25519 public key in base64 format
   */
  public async updateServerKey(serverPublicKeyB64: string): Promise<void> {
    await this.initializeServerKey(serverPublicKeyB64);
  }

  /**
   * Get our public key to share with others
   * @returns Base64 encoded public key
   */
  public async getPublicKey(): Promise<string> {
    if (!this.subtle || !this.keypair) throw new Error('Signature not initialized');
    
    const publicKeyBytes = await this.subtle.exportKey('raw', this.keypair.publicKey);
    return byteArrayToBase64(publicKeyBytes);
  }

  /**
   * Sign data with our private key
   * @param data String or Uint8Array to sign
   * @returns the signature
   */
  public async sign(data: string | Uint8Array): Promise<Uint8Array> {
    if (!this.subtle || !this.keypair) throw new Error('Signature not initialized');

    const dataToSign = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    
    const signature = await this.subtle.sign(
      'Ed25519',
      this.keypair.privateKey,
      dataToSign as any
    );

    return new Uint8Array(signature);
  }

  /**
   * Verify signature from server using the stored server public key
   * @param signature byte array signature to verify
   * @param data Original data that was signed
   * @returns boolean indicating if signature is valid
   */
  public async verify(signatureBytes: Uint8Array, data: string | Uint8Array): Promise<boolean> {
    if (!this.subtle || !this.serverPublicKey) {
      throw new Error('Server public key not initialized. Call initializeServerKey() first.');
    }

    const dataToVerify = typeof data === 'string' ? new TextEncoder().encode(data) : data;

    return await this.subtle.verify(
      'Ed25519',
      this.serverPublicKey,
      signatureBytes as any,
      dataToVerify as any
    );
  }

  /**
   * Verify signature with a specific public key (one-time use)
   * @param publicKey public key to use for verification
   * @param signature signature to verify
   * @param data Original data that was signed
   * @returns boolean indicating if signature is valid
   */
  public async verifyWithKey(publicKeyBytes: Uint8Array, signatureBytes: Uint8Array, data: string | Uint8Array): Promise<boolean> {
    if (!this.subtle) throw new Error('Crypto not initialized');

    const dataToVerify = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const publicKey = await this.subtle.importKey(
      'raw',
      publicKeyBytes as any,
      { name: 'Ed25519' },
      false, // not extractable
      ['verify']
    );

    return await this.subtle.verify(
      'Ed25519',
      publicKey,
      signatureBytes as any,
      dataToVerify as any
    );
  }

  /**
   * Initialize the crypto subsystem and generate key pair
   */
  private async init(): Promise<void> {
    const globalObj = globalThis as any;
    // 1. Try Browser environment first
    if (globalObj.crypto?.subtle) {
      this.subtle = globalObj.crypto.subtle;
    }
//   Try Node.js webcrypto import (Node.js 15+)
    else {
      try {
        const { webcrypto } = await import('crypto' as any);
        this.subtle = webcrypto.subtle as any;
      } catch (error) {
        throw new Error('Web Crypto API not available in this environment');
      }
    }

    // Generate our key pair (non-exportable)
    this.keypair = await this.subtle?.generateKey(
      { name: 'Ed25519' },
      false, // not extractable - more secure
      ['sign', 'verify']
    ) as CryptoKeyPair;
  }
}