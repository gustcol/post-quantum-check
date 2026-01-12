# Post-Quantum Cryptography Readiness Verification Tool

A comprehensive Bash tool to verify if your SSL/TLS configurations, cipher suites, and cryptographic libraries are ready for the post-quantum cryptography era.

## Table of Contents

- [Overview](#overview)
- [What is Post-Quantum Cryptography?](#what-is-post-quantum-cryptography)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Understanding the Output](#understanding-the-output)
- [Code Analysis Reference](#code-analysis-reference)
- [Helm and Kubernetes Analysis](#helm-and-kubernetes-analysis)
- [Web Server Configurations](#web-server-configurations)
- [Post-Quantum Algorithms](#post-quantum-algorithms)
- [Migration Roadmap](#migration-roadmap)
- [Troubleshooting](#troubleshooting)
- [Resources](#resources)

## Overview

The `pq-check.sh` tool performs a comprehensive audit of your system's cryptographic infrastructure to assess readiness for post-quantum cryptography (PQC). It checks:

- **OpenSSL/LibreSSL** version and configuration
- **OQS Provider** installation (Open Quantum Safe)
- **liboqs** library availability
- **Web server configurations** (Nginx, Apache, HAProxy, Caddy)
- **Cipher suite** strength and modern algorithm support
- **TLS protocol** versions enabled
- **Remote server** PQ readiness testing
- **Python code analysis** for quantum-vulnerable cryptographic libraries
- **JavaScript/Node.js code analysis** for quantum-vulnerable dependencies
- **Helm chart analysis** for quantum-vulnerable configurations
- **Kubernetes manifest analysis** for secrets, certificates, and crypto settings

## What is Post-Quantum Cryptography?

### The Quantum Threat

Current public-key cryptography (RSA, ECC, Diffie-Hellman) relies on mathematical problems that are computationally infeasible for classical computers to solve. However, **quantum computers** running Shor's algorithm could break these systems in polynomial time.

### Timeline Concerns

- **"Harvest Now, Decrypt Later"**: Adversaries may be collecting encrypted data today to decrypt once quantum computers become available
- **NIST estimates**: Cryptographically relevant quantum computers could emerge within 10-15 years
- **Migration takes time**: Large organizations need 5-10+ years to fully migrate cryptographic systems

### The Solution: Post-Quantum Cryptography

NIST has standardized new algorithms resistant to quantum attacks:

| Algorithm | Type | Standard | Use Case |
|-----------|------|----------|----------|
| **ML-KEM** (Kyber) | Key Encapsulation | FIPS 203 | Key exchange in TLS |
| **ML-DSA** (Dilithium) | Digital Signature | FIPS 204 | Certificates, authentication |
| **SLH-DSA** (SPHINCS+) | Hash-based Signature | FIPS 205 | Long-term signatures |
| **FN-DSA** (Falcon) | Digital Signature | (Draft) | Compact signatures |

## Features

### System Checks
- OpenSSL/LibreSSL version verification
- OQS provider detection and algorithm enumeration
- liboqs library detection
- TLS 1.3 support verification
- Modern key exchange (X25519, Ed25519) support

### Web Server Analysis
- **Nginx**: SSL protocol and cipher configuration
- **Apache/httpd**: mod_ssl settings and SSLProtocol directives
- **HAProxy**: SSL binding options and minimum versions
- **Caddy**: TLS configuration and Go crypto capabilities

### Security Assessment
- Weak cipher detection
- Legacy protocol identification (TLS 1.0, 1.1, SSLv3)
- HSTS header verification
- ECDH curve configuration analysis

### Remote Testing
- TLS version support probing
- Certificate analysis
- PQ key exchange capability testing

### Code Analysis
- **Python**: Scans `requirements.txt`, `pyproject.toml`, `Pipfile`, and `.py` files for quantum-vulnerable cryptographic patterns
- **JavaScript/Node.js**: Scans `package.json`, lock files, and `.js/.ts/.mjs/.cjs` files for vulnerable dependencies
- Detects vulnerable patterns: RSA key generation, ECDSA/ECDH usage, non-PQ JWT algorithms
- Identifies quantum-resistant patterns: liboqs, Kyber, Dilithium, SPHINCS+

### Helm and Kubernetes Analysis
- **Helm Charts**: Analyzes `values.yaml`, templates, and Chart.yaml for cryptographic configurations
- **Kubernetes Manifests**: Scans Secrets, ConfigMaps, Ingress, and Deployments
- Detects TLS secrets using RSA/ECDSA keys
- Identifies JWT and signing key configurations
- Checks cert-manager certificate configurations
- Validates cipher suite and TLS version settings

## Requirements

### Minimum Requirements
- Bash 4.0+
- OpenSSL (any version for basic checks)

### Recommended for Full PQ Verification
- OpenSSL 3.2+ with OQS provider
- liboqs 0.9.0+
- Root/sudo access for system configuration checks

### Supported Operating Systems
- Linux (Debian, Ubuntu, RHEL, CentOS, Fedora, Arch)
- macOS (with Homebrew OpenSSL)
- BSD variants
- WSL (Windows Subsystem for Linux)

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/gustcol/post-quantum-check.git
cd post-quantum-check

# Make executable
chmod +x pq-check.sh

# Run
./pq-check.sh
```

### System-wide Installation

```bash
# Copy to system path
sudo cp pq-check.sh /usr/local/bin/pq-check
sudo chmod +x /usr/local/bin/pq-check

# Run from anywhere
pq-check
```

## Usage

### Basic Usage

```bash
# Run all checks
./pq-check.sh

# Run all checks (explicit)
./pq-check.sh --all
```

### Specific Checks

```bash
# Check OpenSSL and libraries only
./pq-check.sh --openssl

# Check cipher suites only
./pq-check.sh --ciphers

# Check specific web server
./pq-check.sh --server nginx
./pq-check.sh --server apache
./pq-check.sh --server haproxy
./pq-check.sh --server caddy
```

### Remote Server Testing

```bash
# Test a remote server's PQ readiness
./pq-check.sh --test example.com:443

# Test with custom port
./pq-check.sh --test myserver.com:8443
```

### Code Analysis

```bash
# Analyze Python code in a directory
./pq-check.sh --python /path/to/python/project

# Analyze JavaScript/Node.js code
./pq-check.sh --javascript /path/to/node/project

# Analyze both Python and JavaScript code
./pq-check.sh --code /path/to/project

# Combine with other checks
./pq-check.sh --all --code /path/to/project
```

### Helm and Kubernetes Analysis

```bash
# Analyze Helm charts
./pq-check.sh --helm /path/to/helm/chart

# Analyze Kubernetes manifests
./pq-check.sh --k8s /path/to/k8s/manifests
./pq-check.sh --kubernetes /path/to/k8s/manifests

# Analyze current directory
./pq-check.sh --helm
./pq-check.sh --k8s

# Combine with other checks
./pq-check.sh --all --helm /path/to/chart --k8s /path/to/manifests
```

### Output Options

```bash
# Save detailed report
./pq-check.sh --all --report report.txt

# Quiet mode (summary only) - single line output
./pq-check.sh --quiet --openssl
# Output: PQ-Check: GOOD | Pass: 3 | Warn: 3 | Fail: 0 | Total: 6

# Combine quiet mode with other options
./pq-check.sh --quiet --code ./project --report results.txt

# Disable colors (for logging)
./pq-check.sh --no-color

# Show help
./pq-check.sh --help
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-v, --version` | Show version |
| `-a, --all` | Run all checks (default) |
| `-s, --server TYPE` | Check specific server |
| `-o, --openssl` | Check OpenSSL/LibreSSL only |
| `-l, --libraries` | Check cryptographic libraries |
| `-c, --ciphers` | Check cipher suites |
| `-p, --python PATH` | Analyze Python code for PQ readiness |
| `-j, --javascript PATH` | Analyze JavaScript/Node.js code for PQ readiness |
| `--code PATH` | Analyze both Python and JavaScript code |
| `--helm PATH` | Analyze Helm charts for PQ readiness |
| `--k8s, --kubernetes PATH` | Analyze Kubernetes manifests for PQ readiness |
| `-t, --test HOST:PORT` | Test remote server |
| `-r, --report FILE` | Save report to file |
| `-q, --quiet` | Single line summary output |
| `--no-color` | Disable colored output |

## Understanding the Output

### Status Indicators

| Indicator | Meaning |
|-----------|---------|
| `[PASS]` | Check passed - configuration is secure/ready |
| `[WARN]` | Warning - attention recommended |
| `[FAIL]` | Check failed - action required |
| `[INFO]` | Informational message |

### Example Output

```
══════════════════════════════════════════════════════════════════════
  OPENSSL/LIBRESSL VERIFICATION
══════════════════════════════════════════════════════════════════════

► Version Check
--------------------------------------------------
  Detected: OpenSSL 3.2.1 14 Jan 2024
  [PASS] OpenSSL version 3.2.1 meets recommended version (3.2.0+)

► OQS Provider (Post-Quantum)
--------------------------------------------------
  [PASS] OQS provider found: /usr/local/lib/ossl-modules/oqsprovider.so

  Testing OQS Algorithms:
  [PASS] KEM: kyber768 available
  [PASS] KEM: kyber1024 available
  [PASS] Signature: dilithium3 available
```

### Code Analysis Output

```
══════════════════════════════════════════════════════════════════════
  PYTHON CODE ANALYSIS
══════════════════════════════════════════════════════════════════════

► Scanning directory: /path/to/project
--------------------------------------------------

► Dependency Files
--------------------------------------------------
  Found: requirements.txt
  [WARN] cryptography - Uses RSA/ECC internally (check actual usage)
  [WARN] pyjwt - JWT library (check algorithm configuration)
  [WARN] paramiko - SSH library using RSA/ECDSA keys
  [PASS] bcrypt - Password hashing (quantum-resistant)
  [PASS] argon2-cffi - Password hashing (quantum-resistant)

► Python Source Files
--------------------------------------------------
  Scanning: crypto_example.py
  [WARN] Line 10: RSA key generation detected (quantum-vulnerable)
  [WARN] Line 17: EC key generation detected (quantum-vulnerable)
  [WARN] Line 20: JWT with RS256 algorithm (quantum-vulnerable)

══════════════════════════════════════════════════════════════════════
  JAVASCRIPT/NODE.JS CODE ANALYSIS
══════════════════════════════════════════════════════════════════════

► Dependency Files
--------------------------------------------------
  Found: package.json
  [WARN] node-rsa - RSA implementation (quantum-vulnerable)
  [WARN] elliptic - Elliptic curve library (quantum-vulnerable)
  [WARN] jsonwebtoken - JWT library (check algorithm configuration)
  [PASS] bcrypt - Password hashing (quantum-resistant)

► JavaScript Source Files
--------------------------------------------------
  Scanning: crypto_example.js
  [WARN] Line 7: RSA key generation detected (quantum-vulnerable)
  [WARN] Line 14: ECDH key exchange detected (quantum-vulnerable)
```

### Overall Assessment

At the end of the check, you'll see a summary:

- **EXCELLENT**: System is well-prepared for PQ transition
- **GOOD**: Solid foundation with minor improvements recommended
- **NEEDS ATTENTION**: Several issues need addressing
- **ACTION REQUIRED**: Significant changes needed

## Code Analysis Reference

### Python Libraries

| Library | Status | Notes |
|---------|--------|-------|
| `cryptography` | ⚠️ Warning | Uses RSA/ECC internally - check actual usage |
| `pycryptodome` | ⚠️ Warning | RSA/ECC/DSA implementations |
| `pyjwt` | ⚠️ Warning | Check JWT algorithm (RS*, ES* are vulnerable) |
| `paramiko` | ⚠️ Warning | SSH library using RSA/ECDSA keys |
| `ecdsa` | ⚠️ Warning | Elliptic curve signatures (vulnerable) |
| `rsa` | ⚠️ Warning | RSA implementation (vulnerable) |
| `bcrypt` | ✅ Safe | Password hashing (quantum-resistant) |
| `argon2-cffi` | ✅ Safe | Password hashing (quantum-resistant) |
| `scrypt` | ✅ Safe | Key derivation (quantum-resistant) |
| `liboqs-python` | ✅ PQ-Ready | Post-quantum algorithms |

### JavaScript/Node.js Libraries

| Library | Status | Notes |
|---------|--------|-------|
| `node-rsa` | ⚠️ Warning | RSA implementation (vulnerable) |
| `elliptic` | ⚠️ Warning | Elliptic curve library (vulnerable) |
| `jsrsasign` | ⚠️ Warning | RSA/ECDSA signatures (vulnerable) |
| `jsonwebtoken` | ⚠️ Warning | Check algorithm (RS*, ES* vulnerable) |
| `jose` | ⚠️ Warning | JWT/JWE library (check algorithm config) |
| `crypto-js` | ✅ Safe | AES/SHA (symmetric, quantum-resistant) |
| `bcrypt` | ✅ Safe | Password hashing (quantum-resistant) |
| `argon2` | ✅ Safe | Password hashing (quantum-resistant) |
| `liboqs-node` | ✅ PQ-Ready | Post-quantum algorithms |

### Vulnerable Code Patterns Detected

| Pattern | Language | Risk |
|---------|----------|------|
| `generateKeyPairSync('rsa', ...)` | JavaScript | RSA key generation |
| `crypto.createECDH(...)` | JavaScript | ECDH key exchange |
| `rsa.generate_private_key(...)` | Python | RSA key generation |
| `ec.generate_private_key(...)` | Python | EC key generation |
| `jwt.sign(..., algorithm: 'RS256')` | Both | JWT with RSA signature |
| `jwt.sign(..., algorithm: 'ES256')` | Both | JWT with ECDSA signature |
| `createDiffieHellman(...)` | JavaScript | DH key exchange |
| `dh.generate_parameters(...)` | Python | DH key exchange |

## Helm and Kubernetes Analysis

### Helm Chart Patterns Detected

| Pattern | Location | Risk |
|---------|----------|------|
| `keyAlgorithm: RSA` | values.yaml | RSA certificate keys (quantum-vulnerable) |
| `keyAlgorithm: ECDSA` | values.yaml | ECDSA certificate keys (quantum-vulnerable) |
| `algorithm: RS256/ES256` | values.yaml | JWT with RSA/ECDSA (quantum-vulnerable) |
| `ssl_ciphers: ECDHE-*` | templates | ECDHE cipher suites (key exchange vulnerable) |
| `ssl_ecdh_curve: secp*` | templates | EC curves (quantum-vulnerable) |

### Kubernetes Manifest Patterns Detected

| Resource Type | Pattern | Risk |
|--------------|---------|------|
| Secret | `type: kubernetes.io/tls` | TLS secrets typically use RSA/ECDSA |
| Secret | `ecdsa-*.pem`, `rsa-*.pem` | Key files using vulnerable algorithms |
| Secret | `jwt-algorithm: RS*/ES*` | JWT with RSA/ECDSA signatures |
| ConfigMap | `KEY_EXCHANGE_ALGORITHM: ECDH*` | ECDH key exchange (vulnerable) |
| ConfigMap | `SIGNATURE_ALGORITHM: RSA*/ECDSA` | Signature algorithms (vulnerable) |
| Ingress | `cert-manager.io/private-key-algorithm: RSA/ECDSA` | Certificate key type |
| Ingress | `ssl-ciphers: ECDHE-*` | Cipher suites with ECDHE |

### Safe Kubernetes Patterns

| Resource Type | Pattern | Status |
|--------------|---------|--------|
| ConfigMap | `ENCRYPTION_ALGORITHM: AES-256-GCM` | Quantum-resistant |
| ConfigMap | `HASH_ALGORITHM: SHA-384/SHA-512` | Quantum-resistant |
| ConfigMap | `PASSWORD_HASH_ALGORITHM: argon2id` | Quantum-resistant |
| Ingress | `ssl-protocols: TLSv1.3` | Required for PQ support |

## Web Server Configurations

### Nginx PQ-Ready Configuration

```nginx
# /etc/nginx/nginx.conf or /etc/nginx/conf.d/ssl.conf

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;

# TLS 1.3 ciphers (automatic with TLSv1.3)
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

# Modern ECDH curves (PQ hybrids when available)
ssl_ecdh_curve X25519:secp384r1:secp256r1;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
```

### Apache PQ-Ready Configuration

```apache
# /etc/apache2/mods-enabled/ssl.conf or /etc/httpd/conf.d/ssl.conf

SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLHonorCipherOrder on

SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305

# For TLS 1.3 specific ciphers
SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256

# HSTS
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

### HAProxy PQ-Ready Configuration

```haproxy
# /etc/haproxy/haproxy.cfg

global
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-server-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-server-options ssl-min-ver TLSv1.2 no-tls-tickets

    # When PQ is available:
    # ssl-default-bind-curves X25519Kyber768Draft00:X25519:secp384r1
```

### Caddy PQ-Ready Configuration

```caddy
# /etc/caddy/Caddyfile

{
    servers {
        protocols h1 h2 h3
    }
}

example.com {
    tls {
        protocols tls1.2 tls1.3
        curves x25519 secp384r1 secp256r1
    }
}
```

## Post-Quantum Algorithms

### Key Encapsulation Mechanisms (KEMs)

| Algorithm | Security Level | Public Key | Ciphertext | Use in TLS |
|-----------|---------------|------------|------------|------------|
| ML-KEM-512 | NIST Level 1 | 800 bytes | 768 bytes | Key Exchange |
| ML-KEM-768 | NIST Level 3 | 1,184 bytes | 1,088 bytes | Key Exchange |
| ML-KEM-1024 | NIST Level 5 | 1,568 bytes | 1,568 bytes | Key Exchange |

### Digital Signature Algorithms

| Algorithm | Security Level | Public Key | Signature | Use Case |
|-----------|---------------|------------|-----------|----------|
| ML-DSA-44 | NIST Level 2 | 1,312 bytes | 2,420 bytes | Certificates |
| ML-DSA-65 | NIST Level 3 | 1,952 bytes | 3,293 bytes | Certificates |
| ML-DSA-87 | NIST Level 5 | 2,592 bytes | 4,595 bytes | Certificates |
| Falcon-512 | NIST Level 1 | 897 bytes | 690 bytes | Compact signatures |
| SPHINCS+-128f | NIST Level 1 | 32 bytes | 17,088 bytes | Long-term signatures |

### Hybrid Algorithms (Recommended for Transition)

Hybrid algorithms combine classical and post-quantum cryptography:

- **X25519+Kyber768**: X25519 key exchange + Kyber768 KEM
- **P-256+Kyber512**: ECDH P-256 + Kyber512 KEM
- **P-384+Kyber768**: ECDH P-384 + Kyber768 KEM

Benefits of hybrid approach:
- Maintains security even if PQ algorithms have undiscovered weaknesses
- Compatible with existing infrastructure
- Gradual migration path

## Migration Roadmap

### Phase 1: Assessment (Current)
- [ ] Run `pq-check.sh` on all servers
- [ ] Document current cryptographic inventory
- [ ] Identify systems with long-term data protection needs
- [ ] Establish baseline metrics

### Phase 2: Preparation
- [ ] Upgrade to OpenSSL 3.2+
- [ ] Install OQS provider and liboqs
- [ ] Enable TLS 1.3 on all servers
- [ ] Remove legacy protocols (TLS 1.0, 1.1)
- [ ] Update cipher suites to modern standards

### Phase 3: Testing
- [ ] Deploy hybrid key exchange in test environments
- [ ] Measure performance impact
- [ ] Test client compatibility
- [ ] Validate with security tools

### Phase 4: Deployment
- [ ] Enable hybrid key exchange in production
- [ ] Monitor for issues
- [ ] Prepare for certificate migration
- [ ] Plan for pure PQ algorithms

### Phase 5: Full PQ Migration
- [ ] Deploy PQ certificates
- [ ] Transition to pure PQ algorithms
- [ ] Deprecate classical-only connections
- [ ] Continuous monitoring

## Troubleshooting

### Common Issues

#### "OpenSSL version is below minimum"

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install openssl libssl-dev

# RHEL/CentOS
sudo yum install openssl openssl-devel

# macOS (with Homebrew)
brew install openssl@3
```

#### "OQS provider not found"

Install oqs-provider:

```bash
# Build from source
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
mkdir build && cd build
cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl ..
make
sudo make install
```

#### "TLS 1.3 not supported"

Ensure OpenSSL 1.1.1+ is installed and web server is configured:

```bash
# Verify OpenSSL TLS 1.3 support
openssl ciphers -v 'TLSv1.3'
```

#### "Cannot connect to remote server"

Check network connectivity and firewall rules:

```bash
# Test basic connectivity
nc -zv example.com 443

# Check with openssl
openssl s_client -connect example.com:443 -brief
```

### Debug Mode

Run with verbose logging:

```bash
./pq-check.sh --all 2>&1 | tee debug.log
```

## Resources

### Official Standards
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 - ML-KEM Standard](https://csrc.nist.gov/publications/detail/fips/203/final)
- [FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- [FIPS 205 - SLH-DSA Standard](https://csrc.nist.gov/publications/detail/fips/205/final)

### Open Quantum Safe Project
- [OQS Main Site](https://openquantumsafe.org/)
- [liboqs Library](https://github.com/open-quantum-safe/liboqs)
- [OQS Provider for OpenSSL](https://github.com/open-quantum-safe/oqs-provider)
- [OQS OpenSSL Fork](https://github.com/open-quantum-safe/openssl)

### Implementation Guides
- [Cloudflare PQ Implementation](https://blog.cloudflare.com/post-quantum-cryptography/)
- [Google Chrome PQ Support](https://security.googleblog.com/2023/08/toward-quantum-resilient-security-keys.html)
- [AWS Post-Quantum TLS](https://aws.amazon.com/blogs/security/round-2-post-quantum-tls-is-now-supported-in-aws-kms/)

### Educational Resources
- [Quantum Computing and Cryptography (NIST)](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)
- [Post-Quantum Cryptography Alliance](https://pqca.org/)

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please submit issues and pull requests on GitHub.

### Development

```bash
# Run shellcheck for linting
shellcheck pq-check.sh

# Run tests
./pq-check.sh --all
```

## Changelog

### Version 1.1.0
- Added Python code analysis for quantum-vulnerable cryptographic patterns
- Added JavaScript/Node.js code analysis for vulnerable dependencies
- Added Helm chart analysis for cryptographic configurations
- Added Kubernetes manifest analysis (Secrets, ConfigMaps, Ingress, Deployments)
- New options: `-p, --python`, `-j, --javascript`, `--code`, `--helm`, `--k8s`, `--kubernetes`
- Detects RSA, ECDSA, ECDH, DH usage in source files
- Analyzes requirements.txt, package.json, and other dependency files
- Detects TLS secrets, JWT configurations, and cert-manager settings
- Identifies quantum-safe patterns (liboqs, Kyber, Dilithium, SPHINCS+)
- Added quiet mode (`-q, --quiet`) for single-line summary output
- Improved report file generation for all check options

### Version 1.0.0
- Initial release
- OpenSSL/LibreSSL verification
- Web server configuration checks (Nginx, Apache, HAProxy, Caddy)
- OQS provider detection
- Remote server testing
- Comprehensive recommendations

---

**Stay quantum-safe!** Start your post-quantum migration journey today.
