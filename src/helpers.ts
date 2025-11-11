/// <reference types="node" />

/**
 * Convert byte array to base64 string (URL-safe)
 * @param bytes ArrayBuffer or Uint8Array to convert
 * @returns base64 encoded string
 */
export function byteArrayToBase64(bytes: ArrayBuffer | Uint8Array): string {
  const uint8Array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  
  if (typeof btoa !== "undefined") {
    // Browser environment
    const binary = Array.from(uint8Array, byte => String.fromCharCode(byte)).join('');
    return btoa(binary);
  } else {
    // Node.js environment
    return Buffer.from(uint8Array).toString("base64");
  }
}

/**
 * Convert base64 string to byte array
 * @param base64 base64 encoded string
 * @returns Uint8Array
 */
export function base64StringToByteArr(base64: string): Uint8Array {
  if (!base64) {
    return new Uint8Array(0);
  }
  
  if (typeof atob !== "undefined") {
    // Browser environment
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } else {
    // Node.js environment
    return new Uint8Array(Buffer.from(base64, "base64"));
  }
}

// Cache the crypto import for Node.js
let nodeCrypto: { randomBytes: (length: number) => Uint8Array } | null = null;

/**
 * Generate random bytes cross-platform
 * @param length Number of bytes to generate
 * @returns Uint8Array of random bytes
 */
export async function generateRandomBytes(length: number): Promise<Uint8Array> {
  if (length < 0) {
    throw new Error('Length must be non-negative');
  }
    const globalObj = globalThis as any;
  
  if (globalObj.crypto?.getRandomValues) {
    // Browser environment globalObj will be window
    const array = new Uint8Array(length);
    globalObj.crypto.getRandomValues(array);
    return array;
  } else {
    // Node.js environment - cache the import
    if (!nodeCrypto) {
      const cryptoModule = await import('crypto' as any);
      nodeCrypto = {
        randomBytes: (len: number) => cryptoModule.randomBytes(len)
      };
    }
    return nodeCrypto.randomBytes(length);
  }
}

export interface EncryptionResult {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Convert a BigInt (uint64) to base64 string
 * @param n BigInt value (must be between 0 and 0xFFFFFFFFFFFFFFFFn)
 * @returns base64 encoded string
 */
export function bigIntToBase64(n: bigint): string {
  if (n < 0n || n > 0xFFFFFFFFFFFFFFFFn) {
    throw new RangeError('value out of uint64 range');
  }

  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, n, false); // false = big-endian

  if (typeof btoa !== "undefined") {
    // Browser environment
    const bytes = new Uint8Array(buf);
    return btoa(String.fromCharCode(...bytes));
  } else {
    // Node.js environment
    return Buffer.from(buf).toString("base64");
  }
}

/**
 * Convert base64 string to BigInt (uint64)
 * @param b64 base64 encoded string representing a uint64
 * @returns BigInt value
 */
export function base64ToBigInt(b64: string): bigint {
  if (!b64) {
    throw new Error('Empty base64 string');
  }

  let bytes: Uint8Array;
  
  if (typeof atob !== "undefined") {
    // Browser environment
    const binaryString = atob(b64);
    bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
  } else {
    // Node.js environment
    bytes = new Uint8Array(Buffer.from(b64, "base64"));
  }

  if (bytes.length !== 8) {
    throw new Error(`Expected 8 bytes for uint64, got ${bytes.length}`);
  }

  const view = new DataView(bytes.buffer);
  return view.getBigUint64(0, false); // false = big-endian
}

/**
 * Convert a number (within safe integer range) to base64 string
 * @param num Number value (must be between 0 and Number.MAX_SAFE_INTEGER)
 * @returns base64 encoded string
 */
export function numberToBase64(num: number): string {
  if (num < 0 || num > Number.MAX_SAFE_INTEGER || !Number.isInteger(num)) {
    throw new RangeError('value out of safe integer range');
  }
  return bigIntToBase64(BigInt(num));
}

/**
 * Convert base64 string to number (within safe integer range)
 * @param b64 base64 encoded string representing a uint64
 * @returns number value
 */
export function base64ToNumber(b64: string): number {
  const bigIntValue = base64ToBigInt(b64);
  if (bigIntValue > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError('value exceeds safe integer range');
  }
  return Number(bigIntValue);
}