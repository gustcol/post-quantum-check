// Scenario: WebCrypto API Usage
const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;

async function webCryptoExamples() {
    // RSA-OAEP - QUANTUM VULNERABLE
    const rsaKey = await subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['encrypt', 'decrypt']
    );

    // RSA-PSS - QUANTUM VULNERABLE
    const rsaPssKey = await subtle.generateKey(
        { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify']
    );

    // ECDSA - QUANTUM VULNERABLE
    const ecdsaKey = await subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );

    // ECDH - QUANTUM VULNERABLE
    const ecdhKey = await subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        ['deriveKey', 'deriveBits']
    );

    // AES-GCM - QUANTUM RESISTANT
    const aesKey = await subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );

    // HMAC - QUANTUM RESISTANT
    const hmacKey = await subtle.generateKey(
        { name: 'HMAC', hash: 'SHA-256' },
        true,
        ['sign', 'verify']
    );
}

webCryptoExamples();
