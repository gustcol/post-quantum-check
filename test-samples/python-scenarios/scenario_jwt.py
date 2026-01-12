# Scenario: JWT with Various Algorithms
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

# Generate keys
rsa_key = rsa.generate_private_key(65537, 2048, default_backend())
ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

payload = {"user_id": 123, "role": "admin"}

# JWT with RS256 - QUANTUM VULNERABLE
token_rs256 = jwt.encode(payload, rsa_key, algorithm="RS256")

# JWT with RS384 - QUANTUM VULNERABLE
token_rs384 = jwt.encode(payload, rsa_key, algorithm="RS384")

# JWT with RS512 - QUANTUM VULNERABLE
token_rs512 = jwt.encode(payload, rsa_key, algorithm="RS512")

# JWT with ES256 - QUANTUM VULNERABLE
token_es256 = jwt.encode(payload, ec_key, algorithm="ES256")

# JWT with ES384 - QUANTUM VULNERABLE
token_es384 = jwt.encode(payload, ec_key, algorithm="ES384")

# JWT with PS256 - QUANTUM VULNERABLE
token_ps256 = jwt.encode(payload, rsa_key, algorithm="PS256")

# JWT with HS256 - QUANTUM RESISTANT (symmetric)
token_hs256 = jwt.encode(payload, "secret_key", algorithm="HS256")
