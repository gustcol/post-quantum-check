# Scenario: ECDSA and ECDH Usage
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# EC key generation for signatures - QUANTUM VULNERABLE
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# ECDSA signature - QUANTUM VULNERABLE
from cryptography.hazmat.primitives.asymmetric import utils
data = b"Data to sign"
signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

# ECDH key exchange - QUANTUM VULNERABLE
peer_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
peer_public_key = peer_private_key.public_key()

shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

# Different curves - all QUANTUM VULNERABLE
key_p521 = ec.generate_private_key(ec.SECP521R1(), default_backend())
key_brainpool = ec.generate_private_key(ec.BrainpoolP256R1(), default_backend())
