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

// completeNodeExample.js
const sc = require("@brilliant-ember/secure-channel");
const { webcrypto } = require("crypto");
const { subtle } = webcrypto;

async function main() {

    // signature related
    const signer = await sc.Signature.getInstance();
    await signer.initializeServerKey(theOtherPartySignaturePublicKey);
    const ourPublicSignatureKey = await signer.getPublicKey();
    // sign our own response
    const ourSignature = await signer.sign(ourDataBytes); // this has to be base64
    // verify the response we got from the other server
    const isOtherServerSignatureValid = await signer.verify(otherServerSignature, dataBytesFromOtherServer);


    // encrypte and decrypt
    const kx = await sc.KeyExchange.getInstance();
    const otherServerPublicKxKey = getOtherServerKxKey(); // we need this from the other server we are talking to first to generate our own kx keys
    const otherServerKxCryptoKey = await subtle.importKey(
      "raw",
      otherServerPublicKxKeyBytes,
      { name: "X25519" },
      false,
      []
    );
    // we need to send our kxKey to the other server to finish the dh key exchange
    const ourKxPublicKey = await kx.generateKey(otherServerKxCryptoKey);
    sendKxToOtherServer(ourKxPublicKey);

    const { ciphertext, nonce } = await kx.encrypt("Hello other server!");
    const response = await sendDataToOtherServer(ciphertext, nonce); // we must send the nonce too
    const decryptedData = await kx.decrypt(response.ciphertext, response.nonce);
    // this is a helper function
    const plaintext = sc.byteArrToString(decryptedData);
    console.log(plaintext) // will print "Hello client!"


    // helper functions provided
    sc.byteArrToString(Uint8Array);
    sc.base64ToUint32(b64);
    sc.uint32ToBase64(number);
    sc.uint32ToBytes(num);
    sc.copyToBuffer(Uint8Array, number, Uint8Array);
    sc.base64StringtoByteArr(uint8array); 
    sc.byteArrayToBase64(ArrayBuffer | Uint8Array); 
    sc.numberToBase64(num); 
    sc.base64ToNumber(b64); 
    sc.generateRandomBytes(32); 
    sc.bigIntToBase64(1n); 
    sc.base64ToBigInt(b64); 
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

#### Copy To Buffer 


```javascript

function serializeData(data) {
  const { id, type, payload, timestamp } = data;
  
  // Calculate total size
  const idBytes = new TextEncoder().encode(id);
  const typeBytes = new TextEncoder().encode(type);
  const totalSize = idBytes.length + typeBytes.length + payload.length + 8;
  
  const buffer = new Uint8Array(totalSize);
  let offset = 0;
  
  // Serialize structure
  offset = copyToBuffer(buffer, offset, id);                    // String ID
  offset = copyToBuffer(buffer, offset, "|");                   // Separator
  offset = copyToBuffer(buffer, offset, type);                  // String type
  offset = copyToBuffer(buffer, offset, "|");                   // Separator
  
  const timestampBytes = uint32ToBytes(timestamp);
  offset = copyToBuffer(buffer, offset, timestampBytes);        // 4-byte timestamp
  
  offset = copyToBuffer(buffer, offset, payload);               // Binary payload
  
  return buffer;
}

// Usage
const message = {
  id: "msg-123",
  type: "user_message", 
  timestamp: Math.floor(Date.now() / 1000),
  payload: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
};

const serialized = serializeData(message);
console.log('Serialized size:', serialized.length);

```