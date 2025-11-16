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


/**
 * Converts a 32-bit unsigned integer to a big-endian byte array
 * @param num - The number to convert (0 to 4,294,967,295)
 * @returns Uint8Array containing 4 bytes in big-endian order
 * @throws {Error} If number is out of uint32 range
 */
export function uint32ToBytes(num: number): Uint8Array {
  // Validate input range
  if (!Number.isInteger(num) || num < 0 || num > 0xFFFFFFFF) {
    throw new Error(`Number must be a valid uint32 (0-${0xFFFFFFFF}), got: ${num}`);
  }

  const buf = new Uint8Array(4);
  
  // Use DataView for consistent big-endian behavior across platforms
  const view = new DataView(buf.buffer);
  view.setUint32(0, num, false); // false = big-endian
  
  return buf;
}

/**
 * Copies a string or Uint8Array into a destination buffer at the specified offset
 * @param dest - Destination Uint8Array to copy into
 * @param offset - Starting position in destination buffer
 * @param source - String or Uint8Array to copy
 * @returns New offset position after copying
 * @throws {Error} If offset is out of bounds or source type is invalid
 */
export function copyToBuffer(dest: Uint8Array, offset: number, source: string | Uint8Array): number {
  if (offset < 0 || offset >= dest.length) {
    throw new Error(`Offset ${offset} is out of bounds for buffer length ${dest.length}`);
  }

  if (typeof source === "string") {
    // Copy string character by character (platform-independent)
    for (let i = 0; i < source.length; i++) {
      if (offset >= dest.length) {
        throw new Error(`Buffer overflow: cannot write beyond buffer length ${dest.length}`);
      }
      dest[offset++] = source.charCodeAt(i);
    }
  } else if (source instanceof Uint8Array) {
    // Copy Uint8Array byte by byte
    if (offset + source.length > dest.length) {
      throw new Error(`Buffer overflow: need ${source.length} bytes but only ${dest.length - offset} available`);
    }
    for (const byte of source) {
      dest[offset++] = byte;
    }
  } else {
    throw new Error('Source must be a string or Uint8Array');
  }

  return offset;
}

/**
 * Converts a byte array to a UTF-8 string
 * @param bytes - Uint8Array, Array, or ArrayBuffer containing UTF-8 bytes
 * @returns Decoded string
 * @throws {Error} If input is invalid or decoding fails
 */
export function bytesToString(bytes: Uint8Array | number[] | ArrayBuffer): string {
  if (!bytes) {
    throw new Error('Input cannot be null or undefined');
  }

  let byteArray: Uint8Array;
  
  // Handle different input types
  if (bytes instanceof Uint8Array) {
    byteArray = bytes;
  } else if (Array.isArray(bytes)) {
    byteArray = new Uint8Array(bytes);
  } else if (bytes instanceof ArrayBuffer) {
    byteArray = new Uint8Array(bytes);
  } else {
    throw new Error('Input must be Uint8Array, number array, or ArrayBuffer');
  }
  
  // Platform-independent UTF-8 decoding
  const decoder = new TextDecoder('utf-8');
  return decoder.decode(byteArray);
}

/**
 * Converts a 32-bit unsigned integer to a base64 string (big-endian)
 * @param num - The number to convert (0 to 4,294,967,295)
 * @returns Base64 encoded string representing the 4-byte big-endian number
 */
export function uint32ToBase64(num: number): string {
  if (!Number.isInteger(num) || num < 0 || num > 4294967295){
    throw 'Number must be a valid uint32'
  }
  const bytes = new Uint8Array(4);
  // Big-endian: most significant byte first
  bytes[0] = (num >>> 24) & 0xFF; // MSB
  bytes[1] = (num >>> 16) & 0xFF;
  bytes[2] = (num >>> 8) & 0xFF;
  bytes[3] = num & 0xFF;          // LSB

  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  } else {
    const binary = String.fromCharCode(...bytes);
    return btoa(binary);
  }
}

/**
 * Converts a base64 string back to a 32-bit unsigned integer (big-endian)
 * @param b64 - Base64 string representing a 4-byte big-endian number
 * @returns The decoded uint32 number
 */
export function base64ToUint32(b64: string): number {
  let bytes: Uint8Array = new Uint8Array(0);

  try {
    if (typeof Buffer !== 'undefined') {
      bytes = new Uint8Array(Buffer.from(b64, 'base64'));
    } else {
      const binary = atob(b64);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
    }
  } catch {
    throw new Error('Invalid base64 string');
  }

  if (bytes.length !== 4) {
    throw new Error('Base64 must represent exactly 4 bytes');
  }

  // Use >>> 0 to convert to unsigned 32-bit integer
  // @ts-expect-error
  return (bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]) >>> 0;
}