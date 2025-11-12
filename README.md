# Cross-Platform Key Exchange **and** Signature

A TypeScript library for secure cross-platform key exchange and encryption, as well as signature and verification. Works in both Node.js (15+) and browsers.

## Features

- **X25519** for elliptic curve key exchange
- **HKDF** for key derivation
- **AES-GCM** for authenticated encryption
- **Ed25519** signature / verification
- **Cross-platform** - works in Node.js and browsers
- **TypeScript** - fully typed
- **Zero dependencies**

## Installation

```bash

npm install @brilliant-ember/secure-channel --save

```


## Use examples

### NodeJS
```typescript
// server.js
const { KeyExchange, Signature } = require('@brilliant-ember/secure-channel');

async function main() {
  // Initialize
  const crypto = await KeyExchange.getInstance();
  const sig = await Signature.getInstance();
  
  // Server receives client's public key
  const clientPubKey = await importKeyFromBase64('client-pub-key-base64');
  
  // Generate shared keys
  const serverPubKey = await crypto.generateKey(clientPubKey);
  console.log('Send to client:', bufferToBase64(serverPubKey));
  
  // Encrypt message
  const { ciphertext, nonce } = await crypto.encrypt('Hello client!');
  
  // Decrypt message
  const decrypted = await crypto.decrypt(ciphertext, nonce);
  console.log('Decrypted:', new TextDecoder().decode(decrypted));
}

```

### React client
```typescript
// SecureComponent.jsx
import { useState, useEffect } from 'react';
import { KeyExchange, Signature } from '@brilliant-ember/secure-channel';

export function SecureComponent() {
  const [crypto, setCrypto] = useState(null);
  const [message, setMessage] = useState('');

  useEffect(() => {
    KeyExchange.getInstance().then(setCrypto);
  }, []);

  const encryptMessage = async () => {
    const { ciphertext, nonce } = await crypto.encrypt(message);
    console.log('Encrypted:', { ciphertext, nonce });
  };

  return (
    <div>
      <input value={message} onChange={e => setMessage(e.target.value)} />
      <button onClick={encryptMessage}>Encrypt</button>
    </div>
  );
}

```


### Raw browser javascript
```html

<script type="module">
  import { KeyExchange, Signature } from './@brilliant-ember/secure-channel.js';

  // Initialize
  const crypto = await KeyExchange.getInstance();
  const sig = await Signature.getInstance();

  // Generate keys with server's public key
  const serverKey = await importServerKey();
  await crypto.generateKey(serverKey);

  // Encrypt
  const { ciphertext, nonce } = await crypto.encrypt('Hello World!');

  // Decrypt  
  const decrypted = await crypto.decrypt(ciphertext, nonce);
  console.log('Decrypted:', new TextDecoder().decode(decrypted));
</script>

```

### Signature and Verficiation

```typescript

// Any environment
const sig = await Signature.getInstance();

// Initialize with server's key
await sig.initializeServerKey('server-pub-key-base64');

// Sign data
const signature = await sig.sign('important data');
console.log('Signature:', signature);

// Verify signature
const isValid = await sig.verify(signature, 'important data');
console.log('Valid:', isValid);
```

### Helpers

#### Basic Base64 Conversion

```javascript
import { byteArrayToBase64, base64StringToByteArr } from '@brilliant-ember/secure-channel';

// Convert text to base64 and back
const text = "Hello World";
const bytes = new TextEncoder().encode(text);
const base64 = byteArrayToBase64(bytes);
console.log('Base64:', base64); // "SGVsbG8gV29ybGQ="

const decodedBytes = base64StringToByteArr(base64);
const decodedText = new TextDecoder().decode(decodedBytes);
console.log('Decoded:', decodedText); // "Hello World"

```
#### BigInt Helpers for Timestamps/IDs

```javascript
import { bigIntToBase64, base64ToBigInt } from '@brilliant-ember/secure-channel';

// Store timestamps as compact base64
const timestamp = BigInt(Date.now());
const timestampB64 = bigIntToBase64(timestamp);
console.log('Timestamp base64:', timestampB64);

const recovered = base64ToBigInt(timestampB64);
console.log('Recovered timestamp:', Number(recovered));

// For message IDs
const messageId = 1234567890123456789n;
const idB64 = bigIntToBase64(messageId);
console.log('Message ID:', idB64);

```
#### Number Helpers (Safe Integer Range)

```javascript

import { numberToBase64, base64ToNumber } from '@brilliant-ember/secure-channel';

// For smaller numbers
const count = 1234567890;
const countB64 = numberToBase64(count);
console.log('Count base64:', countB64);

const recoveredCount = base64ToNumber(countB64);
console.log('Recovered count:', recoveredCount);
```
#### Random Bytes

```javascript

import { generateRandomBytes } from '@brilliant-ember/secure-channel';

// Generate secure random data
const randomData = await generateRandomBytes(32);
console.log('Random bytes:', randomData);
```