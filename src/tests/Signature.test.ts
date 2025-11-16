import { Signature } from '../Signature';
import { base64StringToByteArr, byteArrayToBase64 } from '../helpers';

// Mock crypto for consistent testing
const mockSubtle = {
  generateKey: jest.fn(),
  importKey: jest.fn(),
  exportKey: jest.fn(),
  sign: jest.fn(),
  verify: jest.fn(),
};

// Mock keys - use proper base64 data
const mockKeyPair = {
  publicKey: { type: 'public' },
  privateKey: { type: 'private' },
};

const mockServerPublicKey = { type: 'public' };
const mockPublicKeyBytes = new Uint8Array(32); // 32 bytes for Ed25519
const mockSignatureBytes = new Uint8Array(64); // 64 bytes for Ed25519 signature

// Convert to proper base64
const mockPublicKeyB64 = byteArrayToBase64(mockPublicKeyBytes);
// const mockSignatureBytes = byteArrayToBase64(mockSignatureBytes);
const mockServerKeyB64 = byteArrayToBase64(new Uint8Array(32).fill(1)); // Different key

// Set up global crypto
beforeAll(() => {
  (global as any).crypto = { subtle: mockSubtle };
});

describe('Signature Basic Tests', () => {
  let signature: Signature;

  beforeEach(async () => {
    jest.clearAllMocks();
    
    // Reset singleton
    (Signature as any).instance = null;
    (Signature as any).initialized = false;

    // Setup mocks
    mockSubtle.generateKey.mockResolvedValue(mockKeyPair);
    mockSubtle.importKey.mockResolvedValue(mockServerPublicKey);
    mockSubtle.exportKey.mockResolvedValue(mockPublicKeyBytes.buffer);
    mockSubtle.sign.mockResolvedValue(mockSignatureBytes.buffer);
    mockSubtle.verify.mockResolvedValue(true);

    signature = await Signature.getInstance();
  });

  describe('getInstance', () => {
    it('should return singleton instance', async () => {
      const instance1 = await Signature.getInstance();
      const instance2 = await Signature.getInstance();
      expect(instance1).toBe(instance2);
    });

    it('should generate key pair during initialization', async () => {
      expect(mockSubtle.generateKey).toHaveBeenCalledWith(
        { name: 'Ed25519' },
        false, // not extractable
        ['sign', 'verify']
      );
    });
  });

  describe('initializeServerKey', () => {
    it('should import server public key for verification', async () => {
      await signature.initializeServerKey(mockServerKeyB64);

      expect(mockSubtle.importKey).toHaveBeenCalledWith(
        'raw',
        expect.any(Uint8Array), // decoded base64 key
        { name: 'Ed25519' },
        false, // not extractable
        ['verify']
      );
    });

    it('should throw error if crypto not initialized', async () => {
      (Signature as any).instance = null;
      (Signature as any).initialized = false;
      const newInstance = await Signature.getInstance();
      (newInstance as any).subtle = null;

      await expect(newInstance.initializeServerKey(mockServerKeyB64))
        .rejects.toThrow('Crypto not initialized');
    });
  });

  describe('updateServerKey', () => {
    it('should update server public key', async () => {
      const newServerKeyB64 = byteArrayToBase64(new Uint8Array(32).fill(2)); // Different key
      
      await signature.updateServerKey(newServerKeyB64);

      expect(mockSubtle.importKey).toHaveBeenCalledWith(
        'raw',
        expect.any(Uint8Array),
        { name: 'Ed25519' },
        false,
        ['verify']
      );
    });
  });

  describe('getPublicKey', () => {
    it('should return our public key as base64 string', async () => {
      const publicKey = await signature.getPublicKey();

      expect(mockSubtle.exportKey).toHaveBeenCalledWith(
        'raw',
        mockKeyPair.publicKey
      );
      expect(typeof publicKey).toBe('string');
    });

    it('should throw error if not initialized', async () => {
      (Signature as any).instance = null;
      (Signature as any).initialized = false;
      const newInstance = await Signature.getInstance();
      (newInstance as any).keypair = null;

      await expect(newInstance.getPublicKey())
        .rejects.toThrow('Signature not initialized');
    });
  });

  describe('sign', () => {
    it('should sign string data', async () => {
      const data = 'test message';
      const result = await signature.sign(data);

      expect(mockSubtle.sign).toHaveBeenCalledWith(
        'Ed25519',
        mockKeyPair.privateKey,
        new TextEncoder().encode(data)
      );
      expect(result instanceof Uint8Array).toBe(true)
    });

    it('should sign Uint8Array data', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const result = await signature.sign(data);

      expect(mockSubtle.sign).toHaveBeenCalledWith(
        'Ed25519',
        mockKeyPair.privateKey,
        data
      );
      expect(result instanceof Uint8Array).toBe(true)

    });

    it('should throw error if not initialized', async () => {
      (Signature as any).instance = null;
      (Signature as any).initialized = false;
      const newInstance = await Signature.getInstance();
      (newInstance as any).keypair = null;

      await expect(newInstance.sign('test'))
        .rejects.toThrow('Signature not initialized');
    });
  });

  describe('verify', () => {
    beforeEach(async () => {
      await signature.initializeServerKey(mockServerKeyB64);
    });

    it('should verify signature with stored server key', async () => {
      const data = 'signed data';
      const isValid = await signature.verify(mockSignatureBytes, data);

      expect(mockSubtle.verify).toHaveBeenCalledWith(
        'Ed25519',
        mockServerPublicKey,
        expect.any(Uint8Array), // decoded signature
        new TextEncoder().encode(data)
      );
      expect(isValid).toBe(true);
    });

    it('should verify signature with Uint8Array data', async () => {
      const binaryData = new Uint8Array([1, 2, 3, 4, 5]);
      await signature.verify(mockSignatureBytes, binaryData);

      expect(mockSubtle.verify).toHaveBeenCalledWith(
        'Ed25519',
        mockServerPublicKey,
        expect.any(Uint8Array),
        binaryData
      );
    });

    it('should throw error if server key not initialized', async () => {
      (Signature as any).instance = null;
      (Signature as any).initialized = false;
      const newInstance = await Signature.getInstance();

      await expect(newInstance.verify(mockSignatureBytes, 'data'))
        .rejects.toThrow('Server public key not initialized');
    });
  });

  describe('verifyWithKey', () => {
    it('should verify signature with specific public key', async () => {
      const data = 'signed data';
      const isValid = await signature.verifyWithKey(mockPublicKeyBytes, mockSignatureBytes, data);

      expect(mockSubtle.importKey).toHaveBeenCalledWith(
        'raw',
        expect.any(Uint8Array), // decoded public key
        { name: 'Ed25519' },
        false,
        ['verify']
      );
      expect(mockSubtle.verify).toHaveBeenCalledWith(
        'Ed25519',
        mockServerPublicKey, // the imported key
        expect.any(Uint8Array), // decoded signature
        new TextEncoder().encode(data)
      );
      expect(isValid).toBe(true);
    });

    it('should throw error if crypto not initialized', async () => {
      (Signature as any).instance = null;
      (Signature as any).initialized = false;
      const newInstance = await Signature.getInstance();
      (newInstance as any).subtle = null;

      await expect(newInstance.verifyWithKey(mockPublicKeyBytes, mockSignatureBytes, 'data'))
        .rejects.toThrow('Crypto not initialized');
    });
  });
});

describe('Signature Integration Tests', () => {
  let signature: Signature;

  beforeEach(async () => {
    jest.clearAllMocks();
    (Signature as any).instance = null;
    (Signature as any).initialized = false;

    // Setup mocks for integration tests
    mockSubtle.generateKey.mockResolvedValue(mockKeyPair);
    mockSubtle.importKey.mockResolvedValue(mockServerPublicKey);
    mockSubtle.exportKey.mockResolvedValue(mockPublicKeyBytes.buffer);
    mockSubtle.sign.mockResolvedValue(mockSignatureBytes.buffer);
    mockSubtle.verify.mockResolvedValue(true);

    signature = await Signature.getInstance();
  });

  it('should complete full sign/verify workflow', async () => {
    // Setup server key
    await signature.initializeServerKey(mockServerKeyB64);

    // Get our public key
    const ourPublicKey = await signature.getPublicKey();
    expect(typeof ourPublicKey).toBe('string');
    const ourPublicKeyBytes = base64StringToByteArr(ourPublicKey)

    // Sign data
    const dataToSign = 'important message';
    const sig = await signature.sign(dataToSign);
    expect(sig instanceof Uint8Array).toBe(true);

    // Verify with our public key (simulating someone else verifying our signature)
    const isValid = await signature.verifyWithKey(ourPublicKeyBytes, sig, dataToSign);
    expect(isValid).toBe(true);
  });

  it('should handle server key rotation', async () => {
    const originalServerKey = byteArrayToBase64(new Uint8Array(32).fill(1));
    const newServerKey = byteArrayToBase64(new Uint8Array(32).fill(2));

    // Initialize with original key
    await signature.initializeServerKey(originalServerKey);
    
    // Update to new key
    await signature.updateServerKey(newServerKey);

    // Should have imported both keys
    expect(mockSubtle.importKey).toHaveBeenCalledTimes(2);
  });

  it('should handle verification failures', async () => {
    await signature.initializeServerKey(mockServerKeyB64);

    // Mock verification failure
    mockSubtle.verify.mockResolvedValueOnce(false);

    const isValid = await signature.verify(mockSignatureBytes, 'data');
    expect(isValid).toBe(false);
  });
});

describe('Signature Error Handling', () => {
  let signature: Signature;

  beforeEach(async () => {
    jest.clearAllMocks();
    (Signature as any).instance = null;
    (Signature as any).initialized = false;

    mockSubtle.generateKey.mockResolvedValue(mockKeyPair);
    mockSubtle.importKey.mockResolvedValue(mockServerPublicKey);
    mockSubtle.exportKey.mockResolvedValue(mockPublicKeyBytes.buffer);

    signature = await Signature.getInstance();
  });

  it('should handle crypto operation failures', async () => {
    mockSubtle.generateKey.mockRejectedValueOnce(new Error('Key generation failed'));

    // Reset and try to get new instance (should fail)
    (Signature as any).instance = null;
    (Signature as any).initialized = false;

    await expect(Signature.getInstance()).rejects.toThrow('Key generation failed');
  });

  it('should handle import key failures', async () => {
    mockSubtle.importKey.mockRejectedValueOnce(new Error('Import failed'));

    await expect(signature.initializeServerKey(mockServerKeyB64))
      .rejects.toThrow('Import failed');
  });
});

describe('Signature Cross-Platform Behavior', () => {
  let signature: Signature;

  beforeEach(async () => {
    jest.clearAllMocks();
    (Signature as any).instance = null;
    (Signature as any).initialized = false;

    mockSubtle.generateKey.mockResolvedValue(mockKeyPair);
    mockSubtle.importKey.mockResolvedValue(mockServerPublicKey);

    signature = await Signature.getInstance();
  });

  it('should use non-extractable keys for security', async () => {
    // Verify keys are generated as non-extractable
    expect(mockSubtle.generateKey).toHaveBeenCalledWith(
      { name: 'Ed25519' },
      false, // extractable: false
      ['sign', 'verify']
    );
  });

  it('should use non-extractable keys for imported server keys', async () => {
    await signature.initializeServerKey(mockServerKeyB64);

    // Verify imported server keys are also non-extractable
    expect(mockSubtle.importKey).toHaveBeenCalledWith(
      'raw',
      expect.any(Uint8Array),
      { name: 'Ed25519' },
      false, // extractable: false
      ['verify']
    );
  });

  it('should maintain singleton pattern across calls', async () => {
    const instance1 = await Signature.getInstance();
    const instance2 = await Signature.getInstance();
    const instance3 = await Signature.getInstance();

    expect(instance1).toBe(instance2);
    expect(instance2).toBe(instance3);
  });
});