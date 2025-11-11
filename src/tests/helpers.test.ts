import { 
  bigIntToBase64, 
  base64ToBigInt, 
  numberToBase64, 
  base64ToNumber,
  byteArrayToBase64,
  base64StringToByteArr,
  EncryptionResult,
  generateRandomBytes
} from '../helpers';

describe('Helper Functions', () => {
  describe('byteArrayToBase64', () => {
    it('should convert Uint8Array to base64 string', () => {
      const testData = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const result = byteArrayToBase64(testData);
      expect(result).toBe('SGVsbG8=');
    });

    it('should convert ArrayBuffer to base64 string', () => {
      const testData = new Uint8Array([72, 101, 108, 108, 111]).buffer;
      const result = byteArrayToBase64(testData);
      expect(result).toBe('SGVsbG8=');
    });

    it('should handle empty arrays', () => {
      const testData = new Uint8Array([]);
      const result = byteArrayToBase64(testData);
      expect(result).toBe('');
    });

    it('should handle binary data with all byte values', () => {
      // Test all possible byte values (0-255)
      const allBytes = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        allBytes[i] = i;
      }
      
      const result = byteArrayToBase64(allBytes);
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
      
      // Should be able to round-trip
      const roundTripped = base64StringToByteArr(result);
      expect(roundTripped).toEqual(allBytes);
    });

    it('should handle special byte sequences', () => {
      // Test edge cases: null bytes, max values, etc.
      const specialBytes = new Uint8Array([0, 255, 128, 64, 1, 127, 254, 2]);
      const result = byteArrayToBase64(specialBytes);
      const roundTripped = base64StringToByteArr(result);
      expect(roundTripped).toEqual(specialBytes);
    });
  });

  describe('base64StringToByteArr', () => {
    it('should convert base64 string to Uint8Array', () => {
      const base64String = 'SGVsbG8='; // "Hello"
      const result = base64StringToByteArr(base64String);
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should handle empty string', () => {
      const result = base64StringToByteArr('');
      expect(result).toEqual(new Uint8Array([]));
    });

    it('should handle base64 without padding', () => {
      const base64String = 'SGVsbG8'; // "Hello" without padding
      const result = base64StringToByteArr(base64String);
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should round-trip convert correctly', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128, 64, 127]);
      const base64 = byteArrayToBase64(original);
      const roundTripped = base64StringToByteArr(base64);
      expect(roundTripped).toEqual(original);
    });

    it('should handle various base64 encoded data', () => {
      const testCases = [
        { base64: 'YQ==', expected: new Uint8Array([97]) }, // "a"
        { base64: 'YWJj', expected: new Uint8Array([97, 98, 99]) }, // "abc"
        { base64: 'AQIDBAU=', expected: new Uint8Array([1, 2, 3, 4, 5]) },
      ];

      testCases.forEach(({ base64, expected }) => {
        const result = base64StringToByteArr(base64);
        expect(result).toEqual(expected);
      });
    });
  });

  describe('generateRandomBytes', () => {
    it('should generate random bytes of specified length', async () => {
      const length = 32;
      const result = await generateRandomBytes(length);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(length);
    });

    it('should generate different values each time', async () => {
      const result1 = await generateRandomBytes(16);
      const result2 = await generateRandomBytes(16);
      
      // Very unlikely to be equal for random data
      expect(result1).not.toEqual(result2);
    });

    it('should handle zero length', async () => {
      const result = await generateRandomBytes(0);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(0);
    });

    it('should generate valid random bytes (distribution test)', async () => {
      const length = 1000;
      const result = await generateRandomBytes(length);
      
      // Check that bytes are within valid range
      for (let i = 0; i < result.length; i++) {
        expect(result[i]).toBeGreaterThanOrEqual(0);
        expect(result[i]).toBeLessThanOrEqual(255);
      }
      
      // Simple entropy check - at least some bytes should be different
      let hasDifferentBytes = false;
      for (let i = 1; i < result.length; i++) {
        if (result[i] !== result[0]) {
          hasDifferentBytes = true;
          break;
        }
      }
      expect(hasDifferentBytes).toBe(true);
    });

    it('should throw error for negative length', async () => {
      await expect(generateRandomBytes(-1)).rejects.toThrow('Length must be non-negative');
    });

    it('should work with large sizes', async () => {
      const largeSize = 10000;
      const result = await generateRandomBytes(largeSize);
      expect(result.length).toBe(largeSize);
      expect(result).toBeInstanceOf(Uint8Array);
    });
  });

  describe('EncryptionResult interface', () => {
    it('should have correct structure', () => {
      const result: EncryptionResult = {
        ciphertext: new Uint8Array([1, 2, 3]),
        nonce: new Uint8Array([4, 5, 6])
      };

      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.nonce).toBeInstanceOf(Uint8Array);
    });
  });

  describe('Cross-platform compatibility', () => {
    it('should maintain consistency between byteArrayToBase64 and base64StringToByteArr', () => {
      const testVectors = [
        new Uint8Array([]),
        new Uint8Array([0]),
        new Uint8Array([255]),
        new Uint8Array([0, 255, 128, 64]),
        new Uint8Array(100).fill(42), // All same value
        new Uint8Array(256).map((_, i) => i), // All values 0-255
      ];

      testVectors.forEach(original => {
        const base64 = byteArrayToBase64(original);
        expect(typeof base64).toBe('string');
        
        const restored = base64StringToByteArr(base64);
        expect(restored).toEqual(original);
      });
    });

    it('should handle binary data that is not UTF-8', () => {
      // Create data that would be invalid UTF-8
      const binaryData = new Uint8Array([0xC0, 0xC1, 0xF5, 0xF6, 0xF7, 0xF8]);
      
      const base64 = byteArrayToBase64(binaryData);
      const restored = base64StringToByteArr(base64);
      
      expect(restored).toEqual(binaryData);
    });
  });
});
describe('Helpers Edge Cases', () => {
  it('should handle very large Uint8Arrays', () => {
    const largeArray = new Uint8Array(10000);
    for (let i = 0; i < largeArray.length; i++) {
      largeArray[i] = i % 256;
    }
    
    const base64 = byteArrayToBase64(largeArray);
    const restored = base64StringToByteArr(base64);
    
    expect(restored.length).toBe(largeArray.length);
    expect(restored).toEqual(largeArray);
  });

  it('should handle single byte conversions', () => {
    const singleByte = new Uint8Array([65]); // 'A'
    const base64 = byteArrayToBase64(singleByte);
    expect(base64).toBe('QQ==');
    
    const restored = base64StringToByteArr('QQ==');
    expect(restored).toEqual(singleByte);
  });

  it('should be consistent across multiple calls', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    
    const base641 = byteArrayToBase64(data);
    const base642 = byteArrayToBase64(data);
    
    expect(base641).toBe(base642);
    
    const restored1 = base64StringToByteArr(base641);
    const restored2 = base64StringToByteArr(base642);
    
    expect(restored1).toEqual(restored2);
    expect(restored1).toEqual(data);
  });
});

describe('BigInt/Number Base64 Helpers', () => {
  describe('bigIntToBase64 and base64ToBigInt', () => {
    it('should convert zero correctly', () => {
      const zero = 0n;
      const b64 = bigIntToBase64(zero);
      const result = base64ToBigInt(b64);
      
      expect(result).toBe(zero);
      expect(b64).toBe('AAAAAAAAAAA='); // 8 zero bytes in base64
    });

    it('should convert maximum uint64 value correctly', () => {
      const maxUint64 = 0xFFFFFFFFFFFFFFFFn;
      const b64 = bigIntToBase64(maxUint64);
      const result = base64ToBigInt(b64);
      
      expect(result).toBe(maxUint64);
      expect(b64).toBe('//////////8=');
    });

    it('should convert random uint64 values correctly', () => {
      const testValues = [
        1n,
        255n,
        65535n,
        4294967295n,
        1234567890123456789n,
        0x1234567890ABCDEFn
      ];

      testValues.forEach(value => {
        const b64 = bigIntToBase64(value);
        const result = base64ToBigInt(b64);
        expect(result).toBe(value);
        
        // Verify round-trip consistency
        const roundTrip = base64ToBigInt(bigIntToBase64(value));
        expect(roundTrip).toBe(value);
      });
    });

    it('should handle values with specific byte patterns in BIG-ENDIAN', () => {
      // Test values that produce specific base64 patterns in BIG-ENDIAN
      const testCases = [
        { 
          value: 1n, 
          expectedB64: 'AAAAAAAAAAE=' // 0x00...01 in big-endian
        },
        { 
          value: 256n, 
          expectedB64: 'AAAAAAAAAQA=' // 0x00...0100 in big-endian = 256
        },
        { 
          value: 0x0102030405060708n, 
          expectedB64: 'AQIDBAUGBwg=' // 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 in big-endian
        },
        { 
          value: 0x0000000000000100n, 
          expectedB64: 'AAAAAAAAAQA=' // 0x00...0100 in big-endian
        }
      ];

      testCases.forEach(({ value, expectedB64 }) => {
        const b64 = bigIntToBase64(value);
        expect(b64).toBe(expectedB64);
        expect(base64ToBigInt(b64)).toBe(value);
      });
    });

    it('should throw error for values outside uint64 range', () => {
      expect(() => bigIntToBase64(-1n)).toThrow('value out of uint64 range');
      expect(() => bigIntToBase64(0x10000000000000000n)).toThrow('value out of uint64 range');
    });

    it('should throw error for invalid base64 input', () => {
      expect(() => base64ToBigInt('')).toThrow('Empty base64 string');
      expect(() => base64ToBigInt('invalid!@#')).toThrow();
    });

    it('should throw error for base64 with wrong byte length', () => {
      // 4 bytes instead of 8
      const shortB64 = byteArrayToBase64(new Uint8Array(4));
      expect(() => base64ToBigInt(shortB64)).toThrow('Expected 8 bytes for uint64, got 4');
      
      // 16 bytes instead of 8
      const longB64 = byteArrayToBase64(new Uint8Array(16));
      expect(() => base64ToBigInt(longB64)).toThrow('Expected 8 bytes for uint64, got 16');
    });
  });

  describe('numberToBase64 and base64ToNumber', () => {
    it('should convert zero correctly', () => {
      const zero = 0;
      const b64 = numberToBase64(zero);
      const result = base64ToNumber(b64);
      
      expect(result).toBe(zero);
      expect(b64).toBe('AAAAAAAAAAA=');
    });

    it('should convert maximum safe integer correctly', () => {
      const maxSafe = Number.MAX_SAFE_INTEGER;
      const b64 = numberToBase64(maxSafe);
      const result = base64ToNumber(b64);
      
      expect(result).toBe(maxSafe);
    });

    it('should convert various numbers correctly', () => {
      const testValues = [
        0,
        1,
        255,
        65535,
        4294967295,
        1234567890,
        9007199254740991 // Number.MAX_SAFE_INTEGER
      ];

      testValues.forEach(value => {
        const b64 = numberToBase64(value);
        const result = base64ToNumber(b64);
        expect(result).toBe(value);
        
        // Verify round-trip consistency
        const roundTrip = base64ToNumber(numberToBase64(value));
        expect(roundTrip).toBe(value);
      });
    });

    it('should throw error for values outside safe integer range', () => {
      expect(() => numberToBase64(-1)).toThrow('value out of safe integer range');
      expect(() => numberToBase64(1.5)).toThrow('value out of safe integer range');
      expect(() => numberToBase64(Number.MAX_SAFE_INTEGER + 1)).toThrow('value out of safe integer range');
    });

    it('should throw error when base64 exceeds safe integer range', () => {
      const largeValue = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
      const b64 = bigIntToBase64(largeValue);
      
      expect(() => base64ToNumber(b64)).toThrow('value exceeds safe integer range');
    });
  });

  describe('cross-platform compatibility', () => {
    it('should produce consistent results across environments', () => {
      const testValues = [
        0n,
        1n,
        255n,
        65535n,
        0x1234567890ABCDEFn,
        0xFFFFFFFFFFFFFFFFn
      ];

      testValues.forEach(value => {
        const b64 = bigIntToBase64(value);
        
        // Verify the base64 string has correct length for 8 bytes
        // 8 bytes in base64 = 12 characters including padding
        expect(b64.length).toBe(12);
        expect(b64.endsWith('=')).toBe(true);
        
        // Verify round-trip
        expect(base64ToBigInt(b64)).toBe(value);
      });
    });

    it('should work with the existing byte array functions', () => {
      const value = 0x0102030405060708n;
      const b64FromBigInt = bigIntToBase64(value);
      
      // Convert manually using byte array functions for comparison
      const buf = new ArrayBuffer(8);
      const view = new DataView(buf);
      view.setBigUint64(0, value, false); // BIG-ENDIAN
      const bytes = new Uint8Array(buf);
      const b64FromBytes = byteArrayToBase64(bytes);
      
      expect(b64FromBigInt).toBe(b64FromBytes);
      expect(base64ToBigInt(b64FromBigInt)).toBe(value);
    });
  });

  describe('BIG-ENDIAN verification', () => {
    it('should use big-endian (network byte order)', () => {
      // In BIG-ENDIAN, the most significant byte comes first
      
      // 0x0100000000000000 in big-endian = first byte is 0x01, rest are 0x00
      const value1 = 0x0100000000000000n;
      const b641 = bigIntToBase64(value1);
      expect(b641).toBe('AQAAAAAAAAA='); // First byte 0x01 = 'AQ'
      expect(base64ToBigInt(b641)).toBe(value1);
      
      // 0x0000000000000001 in big-endian = last byte is 0x01
      const value2 = 1n;
      const b642 = bigIntToBase64(value2);
      expect(b642).toBe('AAAAAAAAAAE='); // Last byte 0x01 = 'AE'
      expect(base64ToBigInt(b642)).toBe(value2);
      
      // Verify they are different
      expect(b641).not.toBe(b642);
    });

    it('should handle multi-byte values in big-endian', () => {
      // 0x0001000000000000 in big-endian = second byte is 0x01
      const value1 = 0x0001000000000000n;
      const b64 = bigIntToBase64(value1);
      expect(b64).toBe('AAEAAAAAAAA=');
      expect(base64ToBigInt(b64)).toBe(value1);
      
      // 0x1234567890ABCDEF in big-endian = bytes in order: 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
      const value2 = 0x1234567890ABCDEFn;
      const b642 = bigIntToBase64(value2);
      expect(b642).toBe('EjRWeJCrze8=');
      expect(base64ToBigInt(b642)).toBe(value2);
    });

    it('should demonstrate big-endian vs little-endian difference', () => {
      // This shows the difference between big-endian and what little-endian would be
      const value = 0x0102030405060708n;
      
      // BIG-ENDIAN: bytes in memory: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
      const bigEndianB64 = bigIntToBase64(value);
      expect(bigEndianB64).toBe('AQIDBAUGBwg=');
      
      // If it were LITTLE-ENDIAN, bytes would be reversed: [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
      // But our functions always use BIG-ENDIAN
      expect(base64ToBigInt(bigEndianB64)).toBe(value);
    });
  });

  describe('edge cases and boundaries', () => {
    it('should handle all byte boundaries', () => {
      // Test each byte boundary
      const boundaries = [
        0xFFn,                    // 1 byte max
        0xFFFFn,                  // 2 bytes max  
        0xFFFFFFn,                // 3 bytes max
        0xFFFFFFFFn,              // 4 bytes max
        0xFFFFFFFFFFn,            // 5 bytes max
        0xFFFFFFFFFFFFn,          // 6 bytes max
        0xFFFFFFFFFFFFFFn,        // 7 bytes max
        0xFFFFFFFFFFFFFFFFn       // 8 bytes max
      ];

      boundaries.forEach(value => {
        const b64 = bigIntToBase64(value);
        const result = base64ToBigInt(b64);
        expect(result).toBe(value);
      });
    });

    it('should handle powers of two', () => {
      const powersOfTwo = [
        1n, 2n, 4n, 8n, 16n, 32n, 64n, 128n, 256n, 512n, 1024n,
        2048n, 4096n, 8192n, 16384n, 32768n, 65536n,
        131072n, 262144n, 524288n, 1048576n,
        0x100000000n, 0x1000000000000n, 0x100000000000000n
      ];

      powersOfTwo.forEach(value => {
        const b64 = bigIntToBase64(value);
        const result = base64ToBigInt(b64);
        expect(result).toBe(value);
      });
    });
  });
});