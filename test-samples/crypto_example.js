// Sample JavaScript file with cryptographic usage for testing PQ-check

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// RSA key generation (quantum-vulnerable)
crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// ECDH key exchange (quantum-vulnerable)
const ecdh = crypto.createECDH('secp256k1');
ecdh.generateKeys();

// Digital signature (check algorithm)
const sign = crypto.createSign('SHA256');

// JWT with RSA (quantum-vulnerable)
const token = jwt.sign({ user: 'test' }, 'secret', { algorithm: 'RS256' });

// AES encryption (quantum-resistant - good!)
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
