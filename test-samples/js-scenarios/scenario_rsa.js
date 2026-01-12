// Scenario: RSA Key Generation and Usage
const crypto = require('crypto');
const NodeRSA = require('node-rsa');

// Native crypto RSA - QUANTUM VULNERABLE
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// RSA 4096 - QUANTUM VULNERABLE
const { publicKey: pk4096, privateKey: sk4096 } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// node-rsa library - QUANTUM VULNERABLE
const key = new NodeRSA({ b: 2048 });
const encrypted = key.encrypt('secret message', 'base64');
const decrypted = key.decrypt(encrypted, 'utf8');

// RSA signing - QUANTUM VULNERABLE
const sign = crypto.createSign('SHA256');
sign.update('data to sign');
const signature = sign.sign(privateKey, 'hex');

// RSA verification - QUANTUM VULNERABLE
const verify = crypto.createVerify('SHA256');
verify.update('data to sign');
const isValid = verify.verify(publicKey, signature, 'hex');
