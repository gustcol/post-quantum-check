// Scenario: Diffie-Hellman Key Exchange
const crypto = require('crypto');

// Classic DH - QUANTUM VULNERABLE
const alice = crypto.createDiffieHellman(2048);
alice.generateKeys();
const alicePublicKey = alice.getPublicKey();
const alicePrivateKey = alice.getPrivateKey();

const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator());
bob.generateKeys();
const bobPublicKey = bob.getPublicKey();

// Compute shared secrets - QUANTUM VULNERABLE
const aliceSecret = alice.computeSecret(bobPublicKey);
const bobSecret = bob.computeSecret(alicePublicKey);

// DH with named groups - QUANTUM VULNERABLE
const dh = crypto.getDiffieHellman('modp14');
dh.generateKeys();

// DSA signing - QUANTUM VULNERABLE
const { publicKey, privateKey } = crypto.generateKeyPairSync('dsa', {
    modulusLength: 2048,
    divisorLength: 256,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const sign = crypto.createSign('DSS1');
sign.update('data');
const signature = sign.sign(privateKey, 'hex');
