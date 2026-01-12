# Scenario: Diffie-Hellman Key Exchange
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

# Generate DH parameters - QUANTUM VULNERABLE
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Generate private key - QUANTUM VULNERABLE
private_key = parameters.generate_private_key()
public_key = private_key.public_key()

# Peer key exchange - QUANTUM VULNERABLE
peer_private_key = parameters.generate_private_key()
peer_public_key = peer_private_key.public_key()

# Derive shared key - QUANTUM VULNERABLE
shared_key = private_key.exchange(peer_public_key)

# Using DSA - QUANTUM VULNERABLE
from cryptography.hazmat.primitives.asymmetric import dsa
dsa_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
