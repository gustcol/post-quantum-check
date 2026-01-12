// Scenario: JWT with Various Algorithms
const jwt = require('jsonwebtoken');
const jose = require('jose');
const crypto = require('crypto');

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Generate EC key pair
const { publicKey: ecPub, privateKey: ecPriv } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const payload = { userId: 123, role: 'admin' };

// JWT with RS256 - QUANTUM VULNERABLE
const tokenRS256 = jwt.sign(payload, privateKey, { algorithm: 'RS256' });

// JWT with RS384 - QUANTUM VULNERABLE
const tokenRS384 = jwt.sign(payload, privateKey, { algorithm: 'RS384' });

// JWT with RS512 - QUANTUM VULNERABLE
const tokenRS512 = jwt.sign(payload, privateKey, { algorithm: 'RS512' });

// JWT with ES256 - QUANTUM VULNERABLE
const tokenES256 = jwt.sign(payload, ecPriv, { algorithm: 'ES256' });

// JWT with ES384 - QUANTUM VULNERABLE
const tokenES384 = jwt.sign(payload, ecPriv, { algorithm: 'ES384' });

// JWT with PS256 - QUANTUM VULNERABLE
const tokenPS256 = jwt.sign(payload, privateKey, { algorithm: 'PS256' });

// JWT with HS256 - QUANTUM RESISTANT (symmetric)
const tokenHS256 = jwt.sign(payload, 'secret_key', { algorithm: 'HS256' });

// Verification - QUANTUM VULNERABLE for RS*/ES*/PS*
jwt.verify(tokenRS256, publicKey, { algorithms: ['RS256'] });
