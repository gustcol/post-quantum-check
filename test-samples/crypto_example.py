# Sample Python file with cryptographic usage for testing PQ-check

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import jwt

# RSA key generation (quantum-vulnerable)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# EC key generation (quantum-vulnerable)
ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

# JWT with RSA (quantum-vulnerable)
token = jwt.encode({"user": "test"}, "secret", algorithm="RS256")

# AES encryption (quantum-resistant - good!)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
