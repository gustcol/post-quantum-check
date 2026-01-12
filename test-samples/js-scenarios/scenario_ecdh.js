// Scenario: ECDH and ECDSA Usage
const crypto = require('crypto');
const elliptic = require('elliptic');

// ECDH with secp256k1 (Bitcoin curve) - QUANTUM VULNERABLE
const ecdh = crypto.createECDH('secp256k1');
ecdh.generateKeys();
const publicKey = ecdh.getPublicKey('hex');
const privateKey = ecdh.getPrivateKey('hex');

// ECDH with P-256 - QUANTUM VULNERABLE
const ecdh256 = crypto.createECDH('prime256v1');
ecdh256.generateKeys();

// ECDH with P-384 - QUANTUM VULNERABLE
const ecdh384 = crypto.createECDH('secp384r1');
ecdh384.generateKeys();

// ECDH with P-521 - QUANTUM VULNERABLE
const ecdh521 = crypto.createECDH('secp521r1');
ecdh521.generateKeys();

// Key exchange - QUANTUM VULNERABLE
const aliceECDH = crypto.createECDH('secp256k1');
aliceECDH.generateKeys();
const bobECDH = crypto.createECDH('secp256k1');
bobECDH.generateKeys();
const aliceSecret = aliceECDH.computeSecret(bobECDH.getPublicKey());
const bobSecret = bobECDH.computeSecret(aliceECDH.getPublicKey());

// Elliptic library - QUANTUM VULNERABLE
const EC = elliptic.ec;
const ec = new EC('secp256k1');
const keyPair = ec.genKeyPair();
const pubPoint = keyPair.getPublic();
const signature = keyPair.sign('message hash');
