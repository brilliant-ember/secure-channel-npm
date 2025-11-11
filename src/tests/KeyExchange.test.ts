import { KeyExchange } from '../KeyExchange';

// Simple mock setup
const mockSubtle = {
  generateKey: jest.fn(),
  deriveBits: jest.fn(), 
  importKey: jest.fn(),
  encrypt: jest.fn(),
  decrypt: jest.fn(),
  exportKey: jest.fn(),
};

const mockServerPublicKey = { type: 'public', algorithm: { name: 'X25519' } };
const mockClientKeyPair = {
  publicKey: { type: 'public' },
  privateKey: { type: 'private' },
};

// Set up global crypto once
beforeAll(() => {
  (global as any).crypto = { subtle: mockSubtle };
});

describe('KeyExchange Basic Tests', () => {
  let keyExchange: KeyExchange;

  beforeEach(async () => {
    jest.clearAllMocks();
    
    // Reset singleton
    (KeyExchange as any).instance = null;
    (KeyExchange as any).initialized = false;

    // Setup mocks
    mockSubtle.generateKey.mockResolvedValue(mockClientKeyPair);
    mockSubtle.deriveBits.mockResolvedValue(new ArrayBuffer(32));
    mockSubtle.exportKey.mockResolvedValue(new Uint8Array(32).buffer);
    mockSubtle.importKey.mockResolvedValue({});
    mockSubtle.encrypt.mockResolvedValue(new ArrayBuffer(64));
    mockSubtle.decrypt.mockResolvedValue(new TextEncoder().encode('test decrypted').buffer);

    keyExchange = await KeyExchange.getInstance();
  });

  describe('getInstance', () => {
    it('should return singleton instance', async () => {
      const instance1 = await KeyExchange.getInstance();
      const instance2 = await KeyExchange.getInstance();
      expect(instance1).toBe(instance2);
    });
  });

  describe('generateKey', () => {
    it('should generate key pair and return public key as base64 string', async () => {
      const publicKey = await keyExchange.generateKey(mockServerPublicKey as any);
      
      expect(mockSubtle.generateKey).toHaveBeenCalledWith(
        { name: 'X25519' },
        false,
        ['deriveKey', 'deriveBits']
      );
      
      expect(typeof publicKey).toBe('string');
    });
  });

  describe('encrypt/decrypt', () => {
    beforeEach(async () => {
      await keyExchange.generateKey(mockServerPublicKey as any);
    });

    it('should encrypt string plaintext', async () => {
      const result = await keyExchange.encrypt('hello world');
      
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.nonce).toBeInstanceOf(Uint8Array);
      expect(result.nonce).toHaveLength(12);
    });

    it('should encrypt Uint8Array data', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const result = await keyExchange.encrypt(data);
      
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
    });

    it('should decrypt ciphertext', async () => {
      const { ciphertext, nonce } = await keyExchange.encrypt('test message');
      const decrypted = await keyExchange.decrypt(ciphertext, nonce);
      
      expect(decrypted).toBeInstanceOf(Uint8Array);
    });
  });

  describe('error handling', () => {
    it('should throw error when generating keys without initialization', async () => {
      // Create new instance without proper setup
      (KeyExchange as any).instance = null;
      (KeyExchange as any).initialized = false;
      const newInstance = await KeyExchange.getInstance();
      
      // Remove subtle to simulate uninitialized state
      (newInstance as any).subtle = null;
      
      await expect(newInstance.generateKey(mockServerPublicKey as any))
        .rejects.toThrow('Crypto not initialized');
    });

    it('should throw error when encrypting without keys', async () => {
      (KeyExchange as any).instance = null;
      (KeyExchange as any).initialized = false;
      const newInstance = await KeyExchange.getInstance();
      
      await expect(newInstance.encrypt('test'))
        .rejects.toThrow('No encryption key available');
    });

    it('should throw error when decrypting without keys', async () => {
      (KeyExchange as any).instance = null;
      (KeyExchange as any).initialized = false;
      const newInstance = await KeyExchange.getInstance();
      
      const ciphertext = new Uint8Array(32);
      const nonce = new Uint8Array(12);
      
      await expect(newInstance.decrypt(ciphertext, nonce))
        .rejects.toThrow('No decryption key available');
    });
  });
});

describe('KeyExchange Integration', () => {
  it('should complete full encrypt/decrypt workflow', async () => {
    const keyExchange = await KeyExchange.getInstance();
    
    // Setup mocks for complete workflow
    mockSubtle.generateKey.mockResolvedValue(mockClientKeyPair);
    mockSubtle.deriveBits.mockResolvedValue(new ArrayBuffer(32));
    mockSubtle.exportKey.mockResolvedValue(new Uint8Array(32).buffer);
    mockSubtle.importKey.mockResolvedValue({});
    mockSubtle.encrypt.mockResolvedValue(new ArrayBuffer(50));
    mockSubtle.decrypt.mockResolvedValue(new TextEncoder().encode('original message').buffer);

    // Generate keys
    const publicKey = await keyExchange.generateKey(mockServerPublicKey as any);
    expect(typeof publicKey).toBe('string');

    // Encrypt
    const originalMessage = 'secret message';
    const { ciphertext, nonce } = await keyExchange.encrypt(originalMessage);
    
    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(nonce).toHaveLength(12);

    // Decrypt
    const decrypted = await keyExchange.decrypt(ciphertext, nonce);
    const decryptedText = new TextDecoder().decode(decrypted);
    
    expect(decryptedText).toBe('original message');
  });
});