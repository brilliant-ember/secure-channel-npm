import { byteArrayToBase64, generateRandomBytes, EncryptionResult } from './helpers';
import { CryptoKey, CryptoKeyPair, SubtleCrypto } from './types';

/**
 * Cross-platform key exchange client for secure communication
 * Uses X25519 for key exchange, HKDF for key derivation, and AES-GCM for encryption
 */
export class KeyExchange {
  private static instance: KeyExchange | null = null;
  private static initialized = false;

  private subtle: SubtleCrypto | null = null;
  private keypair: CryptoKeyPair | null = null;
  private txKey: CryptoKey | null = null; // Transmit key (encrypt)
  private rxKey: CryptoKey | null = null; // Receive key (decrypt)

  private constructor() {}

  /**
   * Get singleton instance of KeyExchange
   * @returns Promise<KeyExchange>
   */
  public static async getInstance(): Promise<KeyExchange> {
    if (!this.initialized) {
      this.instance = new KeyExchange();
      await this.instance.init();
      this.initialized = true;
    }
    return this.instance!;
  }

  /**
   * Generate encryption keys using server's public key
   * @param serverPublicKey Server's X25519 public key
   * @returns Promise<string> Client's public key base64 to send to server
   */
  public async generateKey(serverPublicKey: CryptoKey): Promise<string> {
    if (!this.subtle) throw new Error('Crypto not initialized');
    
    // Step 0: Create our key pair
    this.keypair = await this.subtle.generateKey(
      { name: 'X25519' },
      false,
      ['deriveKey', 'deriveBits']
    ) as CryptoKeyPair;

    const publicKxKey = byteArrayToBase64(await this.subtle.exportKey('raw', this.keypair.publicKey))

    // Step 1: Derive shared secret
    const sharedSecret = await this.subtle.deriveBits(
      { name: 'X25519', public: serverPublicKey },
      this.keypair.privateKey,
      256
    );

    // Step 2: Derive TX and RX keys using HKDF with public key as additional context
    
    this.txKey = await this.importAes(
      await this.hkdf(sharedSecret, new TextEncoder().encode('client-to-server' + publicKxKey))
    );
    
    this.rxKey = await this.importAes(
      await this.hkdf(sharedSecret, new TextEncoder().encode('server-to-client' + publicKxKey))
    );
    
    // Return our public key for the server
    return publicKxKey;
  }

  /**
   * Encrypt plaintext using the current TX key
   * @param plaintext String or Uint8Array to encrypt
   * @returns Promise<EncryptionResult> Object containing ciphertext and nonce
   */
  public async encrypt(plaintext: string | Uint8Array): Promise<EncryptionResult> {
    if (!this.txKey) throw new Error('No encryption key available. Call generateKey() first.');
    if (!this.subtle) throw new Error('Crypto not initialized');

    const iv = await generateRandomBytes(12); // 96-bit nonce for AES-GCM

    const encrypted = await this.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as any},
      this.txKey,
      typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext as any
    );

    return {
      ciphertext: new Uint8Array(encrypted),
      nonce: iv
    };
  }

  /**
   * Decrypt ciphertext using the current RX key
   * @param ciphertext Encrypted data as Uint8Array
   * @param nonce Nonce used for encryption as Uint8Array
   * @returns Promise<Uint8Array> Decrypted plaintext
   */
  public async decrypt(ciphertext: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
    if (!this.rxKey) throw new Error('No decryption key available. Call generateKey() first.');
    if (!this.subtle) throw new Error('Crypto not initialized');

    const decrypted = await this.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce as any },
      this.rxKey,
      ciphertext as any
    );

    return new Uint8Array(decrypted);
  }

  /**
   * Initialize the crypto subsystem
   */
  private async init(): Promise<void> {
      const globalObj = globalThis as any;
      if (globalObj.crypto?.subtle){
        this.subtle = globalObj.crypto.subtle
        return
      }
    //  Try Node.js webcrypto import (Node.js 15+)
    try {
      const { webcrypto } = await import('crypto' as any);
      this.subtle = webcrypto.subtle as any;
      return;
    } catch (error) {
      // 4. Final fallback
      throw new Error('Web Crypto API not available in this environment');
    }
  }

  private async importAes(raw: Uint8Array): Promise<CryptoKey> {
    if (!this.subtle) {
      throw new Error('Crypto not initialized. Call getInstance() first.');
    }
    return this.subtle.importKey(
      "raw", raw as any, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  private async hkdf(sharedSecret: ArrayBuffer, info: Uint8Array, salt: Uint8Array = new Uint8Array(32)): Promise<Uint8Array> {
    if (!this.subtle) {
      throw new Error('Crypto not initialized. Call getInstance() first.');
    }

    const hkdfAlg = {
      name: 'HKDF',
      hash: "SHA-256",
      salt: salt,
      info: info
    };

    const baseKey = await this.subtle.importKey(
      'raw',
      sharedSecret,
      'HKDF',
      false,
      ['deriveBits', 'deriveKey']
    );

    const raw = await this.subtle.deriveBits(hkdfAlg, baseKey, 256);
    return new Uint8Array(raw);
  }
}