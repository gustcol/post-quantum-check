#!/bin/bash

#===============================================================================
#
#          FILE: pq-check.sh
#
#         USAGE: ./pq-check.sh [OPTIONS]
#
#   DESCRIPTION: Post-Quantum Cryptography Readiness Verification Tool
#                Checks SSL/TLS configurations, cipher suites, and libraries
#                for post-quantum cryptography readiness across web servers.
#
#       OPTIONS: See usage() function below
#        AUTHOR: Post-Quantum Security Team
#       VERSION: 1.0.0
#       CREATED: 2025
#       LICENSE: MIT
#
#===============================================================================

set -o pipefail

#-------------------------------------------------------------------------------
# Configuration & Constants
#-------------------------------------------------------------------------------

readonly VERSION="1.1.0"
SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME
LOG_FILE="/tmp/pq-check-$(date +%Y%m%d_%H%M%S).log"
readonly LOG_FILE

# Colors for output (not readonly so --no-color can override)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Post-Quantum Algorithms (NIST Standardized)
readonly PQ_KEMs=("kyber512" "kyber768" "kyber1024" "ml-kem-512" "ml-kem-768" "ml-kem-1024")
readonly PQ_SIGNATURES=("dilithium2" "dilithium3" "dilithium5" "ml-dsa-44" "ml-dsa-65" "ml-dsa-87" "falcon512" "falcon1024" "sphincssha2128fsimple" "sphincssha2192fsimple" "sphincssha2256fsimple")

# Hybrid Algorithms (Classical + PQ)
readonly HYBRID_KEMs=("p256_kyber512" "p384_kyber768" "p521_kyber1024" "x25519_kyber512" "x25519_kyber768" "x448_kyber1024" "p256_mlkem512" "p384_mlkem768" "p521_mlkem1024")

# Minimum recommended versions
readonly MIN_OPENSSL_VERSION="3.0.0"
readonly RECOMMENDED_OPENSSL_VERSION="3.2.0"

# Counters for summary
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

#-------------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------------

usage() {
    cat << EOF
${BOLD}Post-Quantum Cryptography Readiness Verification Tool v${VERSION}${NC}

${BOLD}USAGE:${NC}
    $SCRIPT_NAME [OPTIONS]

${BOLD}OPTIONS:${NC}
    -h, --help              Show this help message
    -v, --version           Show version information
    -a, --all               Run all checks (default)
    -s, --server TYPE       Check specific server (nginx, apache, httpd, haproxy, caddy)
    -o, --openssl           Check OpenSSL/LibreSSL only
    -l, --libraries         Check cryptographic libraries only
    -c, --ciphers           Check cipher suites only
    -p, --python [PATH]     Analyze Python code for crypto usage
    -j, --javascript [PATH] Analyze JavaScript/Node.js code for crypto usage
    --code [PATH]           Analyze both Python and JavaScript code
    --helm [PATH]           Analyze Helm charts for crypto configurations
    --k8s [PATH]            Analyze Kubernetes manifests for crypto configurations
    --kubernetes [PATH]     Same as --k8s
    -t, --test HOST:PORT    Test remote server PQ readiness
    -r, --report FILE       Save detailed report to file
    -q, --quiet             Minimal output (summary only)
    --no-color              Disable colored output

${BOLD}EXAMPLES:${NC}
    $SCRIPT_NAME                      # Run all local checks
    $SCRIPT_NAME -s nginx             # Check nginx configuration
    $SCRIPT_NAME -t example.com:443   # Test remote server
    $SCRIPT_NAME -p ./myproject       # Scan Python project
    $SCRIPT_NAME -j ./webapp          # Scan JavaScript project
    $SCRIPT_NAME --code ./fullstack   # Scan both Python and JS
    $SCRIPT_NAME --helm ./charts      # Scan Helm charts
    $SCRIPT_NAME --k8s ./manifests    # Scan Kubernetes manifests
    $SCRIPT_NAME -a -r report.txt     # Full check with report

${BOLD}CODE ANALYSIS FEATURES:${NC}
    Python:     requirements.txt, pyproject.toml, Pipfile, *.py files
    JavaScript: package.json, *.js, *.ts, *.mjs files
    Helm:       Chart.yaml, values.yaml, templates/*.yaml
    Kubernetes: Deployments, Secrets, ConfigMaps, Ingresses
    Detects:    RSA, ECDSA, ECDH, DH, JWT, TLS certificates vulnerabilities

${BOLD}POST-QUANTUM ALGORITHMS CHECKED:${NC}
    KEMs:        ML-KEM (Kyber) - 512, 768, 1024
    Signatures:  ML-DSA (Dilithium), Falcon, SPHINCS+
    Hybrids:     X25519+Kyber, P-256+Kyber, etc.

${BOLD}MORE INFORMATION:${NC}
    https://github.com/open-quantum-safe/oqs-provider
    https://csrc.nist.gov/projects/post-quantum-cryptography

EOF
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

print_header() {
    local title="$1"
    local width=70
    echo ""
    echo -e "${BLUE}$(printf '=%.0s' $(seq 1 $width))${NC}"
    echo -e "${BOLD}${CYAN}  $title${NC}"
    echo -e "${BLUE}$(printf '=%.0s' $(seq 1 $width))${NC}"
    echo ""
    log "SECTION: $title"
}

print_subheader() {
    local title="$1"
    echo ""
    echo -e "${BOLD}${MAGENTA}► $title${NC}"
    echo -e "${MAGENTA}--------------------------------------------------${NC}"
    log "SUBSECTION: $title"
}

print_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    log "PASS: $1"
    ((PASS_COUNT++))
}

print_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    log "WARN: $1"
    ((WARN_COUNT++))
}

print_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    log "FAIL: $1"
    ((FAIL_COUNT++))
}

print_info() {
    echo -e "  ${BLUE}[INFO]${NC} $1"
    log "INFO: $1"
}

print_recommendation() {
    echo -e "  ${CYAN}  └─► ${NC}$1"
    log "RECOMMENDATION: $1"
}

command_exists() {
    command -v "$1" &> /dev/null
}

version_gte() {
    # Returns 0 if $1 >= $2
    printf '%s\n%s' "$2" "$1" | sort -V -C
}

#-------------------------------------------------------------------------------
# System Information
#-------------------------------------------------------------------------------

check_system_info() {
    print_header "SYSTEM INFORMATION"

    echo -e "  ${BOLD}Hostname:${NC}      $(hostname)"
    echo -e "  ${BOLD}OS:${NC}            $(uname -s) $(uname -r)"
    echo -e "  ${BOLD}Architecture:${NC}  $(uname -m)"
    echo -e "  ${BOLD}Date:${NC}          $(date)"
    echo -e "  ${BOLD}Log File:${NC}      $LOG_FILE"

    log "System: $(uname -a)"
}

#-------------------------------------------------------------------------------
# OpenSSL/LibreSSL Checks
#-------------------------------------------------------------------------------

check_openssl() {
    print_header "OPENSSL/LIBRESSL VERIFICATION"

    print_subheader "Version Check"

    if ! command_exists openssl; then
        print_fail "OpenSSL is not installed"
        print_recommendation "Install OpenSSL 3.2+ with OQS provider for PQ support"
        return 1
    fi

    local openssl_version_full=$(openssl version 2>/dev/null)
    local openssl_version=$(openssl version 2>/dev/null | awk '{print $2}')
    local openssl_type=$(openssl version 2>/dev/null | awk '{print $1}')

    echo -e "  ${BOLD}Detected:${NC} $openssl_version_full"
    log "OpenSSL Version: $openssl_version_full"

    if [[ "$openssl_type" == "LibreSSL" ]]; then
        print_warn "LibreSSL detected - limited PQ support"
        print_recommendation "Consider switching to OpenSSL 3.2+ with OQS provider"
    elif version_gte "$openssl_version" "$RECOMMENDED_OPENSSL_VERSION"; then
        print_pass "OpenSSL version $openssl_version meets recommended version ($RECOMMENDED_OPENSSL_VERSION+)"
    elif version_gte "$openssl_version" "$MIN_OPENSSL_VERSION"; then
        print_warn "OpenSSL version $openssl_version meets minimum but not recommended"
        print_recommendation "Upgrade to OpenSSL $RECOMMENDED_OPENSSL_VERSION+ for better PQ support"
    else
        print_fail "OpenSSL version $openssl_version is below minimum ($MIN_OPENSSL_VERSION)"
        print_recommendation "Upgrade to OpenSSL $RECOMMENDED_OPENSSL_VERSION+ for PQ support"
    fi

    # Check OpenSSL build options
    print_subheader "Build Configuration"

    local openssl_dir=$(openssl version -d 2>/dev/null | cut -d'"' -f2)
    echo -e "  ${BOLD}OpenSSL Dir:${NC} $openssl_dir"

    # Check for FIPS mode
    if openssl version 2>/dev/null | grep -qi "fips"; then
        print_info "FIPS mode enabled"
    fi

    # Check supported algorithms
    print_subheader "Cryptographic Algorithms Support"

    # Check for TLS 1.3 support (required for PQ)
    if openssl ciphers -v 2>/dev/null | grep -qi "TLSv1.3"; then
        print_pass "TLS 1.3 support available"
    elif openssl ciphers -v 'TLSv1.3' 2>/dev/null | grep -q "TLS"; then
        print_pass "TLS 1.3 support available"
    else
        print_fail "TLS 1.3 not supported"
        print_recommendation "TLS 1.3 is required for post-quantum key exchange"
    fi

    # Check for X25519 (modern key exchange)
    if openssl ecparam -list_curves 2>/dev/null | grep -q "X25519" || \
       openssl pkey -help 2>&1 | grep -q "X25519"; then
        print_pass "X25519 key exchange supported"
    else
        print_warn "X25519 not detected (may still be available)"
    fi

    # Check for Ed25519
    if openssl pkey -help 2>&1 | grep -qi "ed25519" || \
       openssl genpkey -algorithm ed25519 2>&1 | grep -qv "not found"; then
        print_pass "Ed25519 signatures supported"
    else
        print_warn "Ed25519 not detected"
    fi

    check_oqs_provider
}

check_oqs_provider() {
    print_subheader "OQS Provider (Post-Quantum)"

    local oqs_found=false
    local providers_dir=""

    # Get OpenSSL providers directory
    if command_exists openssl; then
        providers_dir=$(openssl version -a 2>/dev/null | grep "MODULESDIR" | sed 's/.*"\([^"]*\)".*/\1/' || echo "")
    fi

    # Check common locations for OQS provider
    local provider_locations=(
        "$providers_dir/oqsprovider.so"
        "$providers_dir/oqsprovider.dylib"
        "/usr/local/lib/ossl-modules/oqsprovider.so"
        "/usr/local/lib64/ossl-modules/oqsprovider.so"
        "/opt/oqs/lib/ossl-modules/oqsprovider.so"
        "/usr/lib/ossl-modules/oqsprovider.so"
        "/usr/lib64/ossl-modules/oqsprovider.so"
        "/opt/homebrew/lib/ossl-modules/oqsprovider.so"
    )

    for location in "${provider_locations[@]}"; do
        if [[ -f "$location" ]]; then
            print_pass "OQS provider found: $location"
            oqs_found=true
            break
        fi
    done

    if [[ "$oqs_found" == false ]]; then
        print_warn "OQS provider not found in standard locations"
        print_recommendation "Install oqs-provider for post-quantum algorithm support"
        print_recommendation "See: https://github.com/open-quantum-safe/oqs-provider"
    fi

    # Try to list OQS algorithms if provider is available
    if [[ "$oqs_found" == true ]]; then
        echo ""
        echo -e "  ${BOLD}Testing OQS Algorithms:${NC}"

        # Test KEM algorithms
        for kem in "${PQ_KEMs[@]}"; do
            if openssl list -kem-algorithms 2>/dev/null | grep -qi "$kem"; then
                print_pass "KEM: $kem available"
            fi
        done

        # Test signature algorithms
        for sig in "${PQ_SIGNATURES[@]}"; do
            if openssl list -signature-algorithms 2>/dev/null | grep -qi "$sig"; then
                print_pass "Signature: $sig available"
            fi
        done
    fi

    # Check if liboqs is installed
    print_subheader "liboqs Library"

    local liboqs_found=false
    local liboqs_locations=(
        "/usr/local/lib/liboqs.so"
        "/usr/local/lib/liboqs.dylib"
        "/usr/lib/liboqs.so"
        "/usr/lib64/liboqs.so"
        "/opt/liboqs/lib/liboqs.so"
        "/opt/homebrew/lib/liboqs.dylib"
    )

    for location in "${liboqs_locations[@]}"; do
        if [[ -f "$location" ]]; then
            print_pass "liboqs found: $location"
            liboqs_found=true
            break
        fi
    done

    # Check via pkg-config
    if [[ "$liboqs_found" == false ]] && command_exists pkg-config; then
        if pkg-config --exists liboqs 2>/dev/null; then
            local liboqs_version=$(pkg-config --modversion liboqs 2>/dev/null)
            print_pass "liboqs found via pkg-config (version: $liboqs_version)"
            liboqs_found=true
        fi
    fi

    # Check via ldconfig on Linux
    if [[ "$liboqs_found" == false ]] && command_exists ldconfig; then
        if ldconfig -p 2>/dev/null | grep -q "liboqs"; then
            print_pass "liboqs found in system library cache"
            liboqs_found=true
        fi
    fi

    if [[ "$liboqs_found" == false ]]; then
        print_warn "liboqs library not found"
        print_recommendation "Install liboqs: https://github.com/open-quantum-safe/liboqs"
    fi
}

#-------------------------------------------------------------------------------
# Web Server Configuration Checks
#-------------------------------------------------------------------------------

check_nginx() {
    print_header "NGINX CONFIGURATION"

    if ! command_exists nginx; then
        print_info "Nginx is not installed on this system"
        return 0
    fi

    local nginx_version=$(nginx -v 2>&1 | sed -n 's/.*nginx\/\([0-9.]*\).*/\1/p')
    print_info "Nginx version: $nginx_version"

    print_subheader "Nginx SSL/TLS Configuration"

    # Find nginx configuration files
    local nginx_conf_paths=(
        "/etc/nginx/nginx.conf"
        "/usr/local/nginx/conf/nginx.conf"
        "/opt/nginx/conf/nginx.conf"
        "/usr/local/etc/nginx/nginx.conf"
        "/opt/homebrew/etc/nginx/nginx.conf"
    )

    local nginx_conf=""
    for path in "${nginx_conf_paths[@]}"; do
        if [[ -f "$path" ]]; then
            nginx_conf="$path"
            break
        fi
    done

    if [[ -z "$nginx_conf" ]]; then
        print_warn "Nginx configuration file not found"
        return 1
    fi

    print_info "Configuration file: $nginx_conf"

    # Check SSL protocols
    echo ""
    echo -e "  ${BOLD}SSL Protocol Configuration:${NC}"

    local ssl_protocols=$(grep -r "ssl_protocols" /etc/nginx/ 2>/dev/null | head -5)
    if [[ -n "$ssl_protocols" ]]; then
        echo "$ssl_protocols" | while read -r line; do
            echo -e "    $line"
        done

        if echo "$ssl_protocols" | grep -q "TLSv1.3"; then
            print_pass "TLS 1.3 is enabled"
        else
            print_fail "TLS 1.3 is NOT enabled"
            print_recommendation "Add 'TLSv1.3' to ssl_protocols directive"
        fi

        if echo "$ssl_protocols" | grep -qE "SSLv[23]|TLSv1[^.]|TLSv1\.0|TLSv1\.1"; then
            print_warn "Legacy protocols (TLS 1.0/1.1 or SSL) are enabled"
            print_recommendation "Remove SSLv2, SSLv3, TLSv1, TLSv1.1 from ssl_protocols"
        fi
    else
        print_warn "ssl_protocols not explicitly configured"
        print_recommendation "Add: ssl_protocols TLSv1.2 TLSv1.3;"
    fi

    # Check SSL ciphers
    echo ""
    echo -e "  ${BOLD}SSL Cipher Configuration:${NC}"

    local ssl_ciphers=$(grep -r "ssl_ciphers" /etc/nginx/ 2>/dev/null | head -3)
    if [[ -n "$ssl_ciphers" ]]; then
        if echo "$ssl_ciphers" | grep -qiE "DES|RC4|MD5|EXPORT|NULL|anon"; then
            print_fail "Weak ciphers detected in configuration"
            print_recommendation "Remove weak ciphers: DES, RC4, MD5, EXPORT, NULL, anonymous"
        else
            print_pass "No obviously weak ciphers in configuration"
        fi
    fi

    # Check for ssl_prefer_server_ciphers
    if grep -r "ssl_prefer_server_ciphers" /etc/nginx/ 2>/dev/null | grep -q "on"; then
        print_pass "ssl_prefer_server_ciphers is enabled"
    else
        print_warn "ssl_prefer_server_ciphers not set to 'on'"
        print_recommendation "Add: ssl_prefer_server_ciphers on;"
    fi

    # Check for HSTS
    if grep -r "Strict-Transport-Security" /etc/nginx/ 2>/dev/null | grep -q "max-age"; then
        print_pass "HSTS header is configured"
    else
        print_warn "HSTS header not found"
        print_recommendation "Add: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
    fi

    # Check ssl_ecdh_curve for modern curves
    echo ""
    echo -e "  ${BOLD}ECDH Curve Configuration:${NC}"

    local ecdh_curve=$(grep -r "ssl_ecdh_curve" /etc/nginx/ 2>/dev/null)
    if [[ -n "$ecdh_curve" ]]; then
        echo "    $ecdh_curve"
        if echo "$ecdh_curve" | grep -qE "X25519|secp384r1|secp256r1"; then
            print_pass "Modern ECDH curves configured"
        fi
    else
        print_info "ssl_ecdh_curve not explicitly set (using OpenSSL defaults)"
        print_recommendation "Consider: ssl_ecdh_curve X25519:secp384r1:secp256r1;"
    fi

    print_subheader "Post-Quantum Readiness for Nginx"

    print_info "Nginx PQ support requires:"
    echo -e "    • OpenSSL 3.2+ compiled with OQS provider"
    echo -e "    • nginx compiled against PQ-enabled OpenSSL"
    echo -e "    • TLS 1.3 enabled (required for PQ key exchange)"
    echo ""

    # Check if nginx was compiled with OpenSSL version
    local nginx_openssl=$(nginx -V 2>&1 | sed -n 's/.*built with OpenSSL \([0-9.]*\).*/\1/p')
    if [[ -n "$nginx_openssl" ]]; then
        echo -e "  ${BOLD}Nginx built with OpenSSL:${NC} $nginx_openssl"
        if version_gte "$nginx_openssl" "3.0.0"; then
            print_pass "Nginx compiled with OpenSSL 3.x (PQ-capable)"
        else
            print_warn "Nginx compiled with older OpenSSL"
            print_recommendation "Recompile nginx with OpenSSL 3.2+ for PQ support"
        fi
    fi
}

check_apache() {
    print_header "APACHE/HTTPD CONFIGURATION"

    local apache_cmd=""
    if command_exists apache2; then
        apache_cmd="apache2"
    elif command_exists httpd; then
        apache_cmd="httpd"
    elif command_exists apachectl; then
        apache_cmd="apachectl"
    fi

    if [[ -z "$apache_cmd" ]]; then
        print_info "Apache/httpd is not installed on this system"
        return 0
    fi

    local apache_version=$($apache_cmd -v 2>&1 | grep "Server version" | sed -n 's/.*\/\([0-9.]*\).*/\1/p')
    print_info "Apache version: $apache_version"

    print_subheader "Apache SSL/TLS Configuration"

    # Find Apache configuration files
    local apache_conf_paths=(
        "/etc/apache2/apache2.conf"
        "/etc/httpd/conf/httpd.conf"
        "/etc/apache2/sites-enabled"
        "/etc/httpd/conf.d"
        "/usr/local/apache2/conf/httpd.conf"
        "/opt/homebrew/etc/httpd/httpd.conf"
        "/etc/apache2/mods-enabled/ssl.conf"
        "/etc/httpd/conf.d/ssl.conf"
    )

    local ssl_conf_found=false

    for path in "${apache_conf_paths[@]}"; do
        if [[ -e "$path" ]]; then
            print_info "Found config: $path"
            ssl_conf_found=true

            # Check SSL configuration in this path
            if [[ -d "$path" ]]; then
                local ssl_protocol=$(grep -rh "SSLProtocol" "$path" 2>/dev/null | grep -v "^#" | head -3)
            else
                local ssl_protocol=$(grep "SSLProtocol" "$path" 2>/dev/null | grep -v "^#" | head -3)
            fi

            if [[ -n "$ssl_protocol" ]]; then
                echo ""
                echo -e "  ${BOLD}SSLProtocol Configuration:${NC}"
                echo "$ssl_protocol" | while read -r line; do
                    echo -e "    $line"
                done

                if echo "$ssl_protocol" | grep -q "TLSv1.3"; then
                    print_pass "TLS 1.3 is enabled"
                elif echo "$ssl_protocol" | grep -q "+TLSv1.3"; then
                    print_pass "TLS 1.3 is enabled"
                elif echo "$ssl_protocol" | grep -q "all"; then
                    print_info "Using 'all' - TLS 1.3 should be included"
                else
                    print_warn "TLS 1.3 may not be enabled"
                    print_recommendation "Add TLSv1.3 to SSLProtocol directive"
                fi

                if echo "$ssl_protocol" | grep -qiE "SSLv[23]|\-TLSv1\.2"; then
                    print_pass "Legacy protocols appear to be disabled"
                fi
            fi
        fi
    done

    if [[ "$ssl_conf_found" == false ]]; then
        print_warn "No Apache SSL configuration files found"
    fi

    # Check SSLCipherSuite
    echo ""
    echo -e "  ${BOLD}SSLCipherSuite Configuration:${NC}"

    local cipher_suite=$(grep -rh "SSLCipherSuite" /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v "^#" | head -3)
    if [[ -n "$cipher_suite" ]]; then
        if echo "$cipher_suite" | grep -qiE "DES|RC4|MD5|EXPORT|NULL"; then
            print_fail "Weak ciphers may be present"
            print_recommendation "Review and remove weak ciphers from SSLCipherSuite"
        else
            print_pass "No obviously weak ciphers in configuration"
        fi
    fi

    # Check for mod_ssl
    print_subheader "Apache SSL Module"

    if $apache_cmd -M 2>/dev/null | grep -q "ssl_module"; then
        print_pass "mod_ssl is loaded"
    else
        print_warn "mod_ssl may not be loaded"
        print_recommendation "Enable mod_ssl: a2enmod ssl (Debian/Ubuntu) or check LoadModule"
    fi

    # Check OpenSSL version used by Apache
    local apache_openssl=$($apache_cmd -V 2>&1 | grep -i "openssl" | sed -n 's/.*OpenSSL[[:space:]]*\([0-9.]*[a-z]*\).*/\1/p' | head -1)
    if [[ -n "$apache_openssl" ]]; then
        echo ""
        echo -e "  ${BOLD}Apache built with OpenSSL:${NC} $apache_openssl"
    fi

    print_subheader "Post-Quantum Readiness for Apache"

    print_info "Apache PQ support requires:"
    echo -e "    • OpenSSL 3.2+ with OQS provider"
    echo -e "    • Apache compiled against PQ-enabled OpenSSL"
    echo -e "    • mod_ssl configured for TLS 1.3"
    echo -e "    • SSLProtocol TLSv1.3 (minimum for PQ KEMs)"
}

check_haproxy() {
    print_header "HAPROXY CONFIGURATION"

    if ! command_exists haproxy; then
        print_info "HAProxy is not installed on this system"
        return 0
    fi

    local haproxy_version=$(haproxy -v 2>&1 | head -1 | sed -n 's/.*version \([0-9.]*\).*/\1/p')
    print_info "HAProxy version: $haproxy_version"

    print_subheader "HAProxy SSL/TLS Configuration"

    local haproxy_conf_paths=(
        "/etc/haproxy/haproxy.cfg"
        "/usr/local/etc/haproxy/haproxy.cfg"
    )

    local haproxy_conf=""
    for path in "${haproxy_conf_paths[@]}"; do
        if [[ -f "$path" ]]; then
            haproxy_conf="$path"
            break
        fi
    done

    if [[ -z "$haproxy_conf" ]]; then
        print_warn "HAProxy configuration file not found"
        return 1
    fi

    print_info "Configuration file: $haproxy_conf"

    # Check SSL configuration
    if grep -q "ssl-default-bind-ciphers" "$haproxy_conf" 2>/dev/null; then
        local bind_ciphers=$(grep "ssl-default-bind-ciphers" "$haproxy_conf")
        echo -e "  ${BOLD}Default bind ciphers:${NC}"
        echo "    $bind_ciphers"
    fi

    if grep -q "ssl-default-bind-options" "$haproxy_conf" 2>/dev/null; then
        local bind_options=$(grep "ssl-default-bind-options" "$haproxy_conf")
        echo -e "  ${BOLD}Default bind options:${NC}"
        echo "    $bind_options"

        if echo "$bind_options" | grep -q "no-sslv3"; then
            print_pass "SSLv3 is disabled"
        fi
        if echo "$bind_options" | grep -q "no-tlsv10"; then
            print_pass "TLS 1.0 is disabled"
        fi
        if echo "$bind_options" | grep -q "no-tlsv11"; then
            print_pass "TLS 1.1 is disabled"
        fi
    fi

    # Check for ssl-min-ver
    if grep -q "ssl-min-ver" "$haproxy_conf" 2>/dev/null; then
        local min_ver=$(grep "ssl-min-ver" "$haproxy_conf")
        echo -e "  ${BOLD}Minimum SSL version:${NC}"
        echo "    $min_ver"
    fi

    print_subheader "Post-Quantum Readiness for HAProxy"

    print_info "HAProxy PQ support requires:"
    echo -e "    • HAProxy 2.4+ for TLS 1.3 support"
    echo -e "    • Compiled against OpenSSL 3.2+ with OQS provider"
    echo -e "    • ssl-min-ver TLSv1.3 for PQ key exchange"
}

check_caddy() {
    print_header "CADDY CONFIGURATION"

    if ! command_exists caddy; then
        print_info "Caddy is not installed on this system"
        return 0
    fi

    local caddy_version=$(caddy version 2>&1 | head -1)
    print_info "Caddy version: $caddy_version"

    print_subheader "Caddy TLS Configuration"

    local caddyfile_paths=(
        "/etc/caddy/Caddyfile"
        "$HOME/Caddyfile"
        "./Caddyfile"
    )

    local caddyfile=""
    for path in "${caddyfile_paths[@]}"; do
        if [[ -f "$path" ]]; then
            caddyfile="$path"
            break
        fi
    done

    if [[ -n "$caddyfile" ]]; then
        print_info "Caddyfile found: $caddyfile"

        if grep -q "protocols" "$caddyfile" 2>/dev/null; then
            echo -e "  ${BOLD}TLS Protocol Configuration:${NC}"
            grep "protocols" "$caddyfile"
        else
            print_info "Using Caddy's default TLS settings (TLS 1.2+)"
        fi

        if grep -q "curves" "$caddyfile" 2>/dev/null; then
            echo -e "  ${BOLD}Curve Configuration:${NC}"
            grep "curves" "$caddyfile"
        fi
    else
        print_info "No Caddyfile found - Caddy may use automatic HTTPS"
    fi

    print_subheader "Post-Quantum Readiness for Caddy"

    print_info "Caddy PQ support:"
    echo -e "    • Caddy uses Go's crypto/tls library"
    echo -e "    • Go 1.23+ has experimental PQ support (X25519Kyber768Draft00)"
    echo -e "    • Check Caddy plugins for additional PQ support"

    # Check Go version if available
    if command_exists go; then
        local go_version
        go_version=$(go version | sed -n 's/.*\(go[0-9]*\.[0-9]*\).*/\1/p')
        echo -e "  ${BOLD}Go version:${NC} $go_version"

        if [[ "$go_version" > "go1.22" ]]; then
            print_pass "Go version supports experimental PQ features"
        fi
    fi
}

#-------------------------------------------------------------------------------
# Python Code Analysis
#-------------------------------------------------------------------------------

check_python_code() {
    local scan_path="${1:-.}"

    print_header "PYTHON CRYPTOGRAPHIC LIBRARY ANALYSIS"

    print_info "Scanning directory: $scan_path"

    # Check if Python is installed
    if ! command_exists python3 && ! command_exists python; then
        print_warn "Python not installed - skipping some checks"
    fi

    print_subheader "Python Crypto Dependencies"

    local found_crypto=false
    local found_pq_safe=false
    local vulnerable_count=0

    # Check requirements.txt files
    local req_files
    req_files=$(find "$scan_path" -maxdepth 5 -name "requirements*.txt" -type f 2>/dev/null)

    if [[ -n "$req_files" ]]; then
        echo ""
        echo -e "  ${BOLD}Found requirements files:${NC}"

        while IFS= read -r req_file; do
            [[ -z "$req_file" ]] && continue
            echo -e "    • $req_file"

            # Check for vulnerable crypto libraries
            if grep -qi "^cryptography" "$req_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: cryptography - check version for PQ support"
                ((vulnerable_count++))
            fi
            if grep -qi "^pycryptodome" "$req_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: pycryptodome - no native PQ support yet"
                ((vulnerable_count++))
            fi
            if grep -qi "^paramiko" "$req_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: paramiko - uses RSA/ECDSA (quantum-vulnerable)"
                ((vulnerable_count++))
            fi
            if grep -qi "^pyjwt" "$req_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: pyjwt - typically uses RSA/ECDSA"
                ((vulnerable_count++))
            fi
            if grep -qi "^rsa[=>< ]\\|^rsa$" "$req_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: rsa - quantum-vulnerable"
                ((vulnerable_count++))
            fi
            if grep -qi "^ecdsa" "$req_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: ecdsa - quantum-vulnerable"
                ((vulnerable_count++))
            fi
            if grep -qi "^pyopenssl" "$req_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: pyopenssl - depends on system OpenSSL for PQ"
                ((vulnerable_count++))
            fi
            # PQ-safe libraries
            if grep -qi "^liboqs" "$req_file" 2>/dev/null; then
                found_pq_safe=true
                print_pass "Found PQ-safe: liboqs"
            fi
            if grep -qi "^pqcrypto" "$req_file" 2>/dev/null; then
                found_pq_safe=true
                print_pass "Found PQ-safe: pqcrypto"
            fi
            if grep -qi "^oqs" "$req_file" 2>/dev/null; then
                found_pq_safe=true
                print_pass "Found PQ-safe: oqs"
            fi
            # Quantum-resistant (symmetric/hash)
            if grep -qi "^bcrypt" "$req_file" 2>/dev/null; then
                print_info "Found: bcrypt - password hashing (quantum-resistant)"
            fi
            if grep -qi "^argon2" "$req_file" 2>/dev/null; then
                print_info "Found: argon2-cffi - password hashing (quantum-resistant)"
            fi
        done <<< "$req_files"
    fi

    # Check pyproject.toml files
    local pyproject_files
    pyproject_files=$(find "$scan_path" -maxdepth 5 -name "pyproject.toml" -type f 2>/dev/null)

    if [[ -n "$pyproject_files" ]]; then
        echo ""
        echo -e "  ${BOLD}Found pyproject.toml files:${NC}"

        while IFS= read -r pyproject_file; do
            [[ -z "$pyproject_file" ]] && continue
            echo -e "    • $pyproject_file"

            if grep -qi '"cryptography"\|'\''cryptography'\''' "$pyproject_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: cryptography in pyproject.toml"
            fi
            if grep -qi '"paramiko"\|'\''paramiko'\''' "$pyproject_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: paramiko in pyproject.toml"
            fi
            if grep -qi '"pyjwt"\|'\''pyjwt'\''' "$pyproject_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: pyjwt in pyproject.toml"
            fi
            if grep -qi '"liboqs"\|'\''liboqs'\''' "$pyproject_file" 2>/dev/null; then
                found_pq_safe=true
                print_pass "Found PQ-safe: liboqs in pyproject.toml"
            fi
        done <<< "$pyproject_files"
    fi

    print_subheader "Python Source Code Analysis"

    # Scan Python files for crypto usage patterns
    local py_files
    py_files=$(find "$scan_path" -maxdepth 5 -name "*.py" -type f 2>/dev/null | head -100)

    local vulnerable_patterns_found=0

    if [[ -n "$py_files" ]]; then
        echo ""
        echo -e "  ${BOLD}Scanning Python source files...${NC}"

        local scanned_count=0

        while IFS= read -r py_file; do
            [[ -z "$py_file" ]] && continue
            ((scanned_count++))

            # Check for RSA usage
            if grep -q "from cryptography.hazmat.primitives.asymmetric import rsa" "$py_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$py_file"): RSA usage - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $py_file"
            fi
            if grep -q "RSA.generate\|rsa.generate" "$py_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$py_file"): RSA key generation - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $py_file"
            fi
            # Check for EC/ECDSA usage
            if grep -q "from cryptography.hazmat.primitives.asymmetric import ec" "$py_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$py_file"): ECDSA/ECDH - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $py_file"
            fi
            if grep -q "ec.generate_private_key" "$py_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$py_file"): EC key generation - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $py_file"
            fi
            # Check for DH usage
            if grep -q "from cryptography.hazmat.primitives.asymmetric import dh" "$py_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$py_file"): Diffie-Hellman - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $py_file"
            fi
            # Check for JWT with RSA/EC
            if grep -q "jwt.encode.*RS256\|jwt.encode.*RS384\|jwt.encode.*RS512" "$py_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$py_file"): JWT with RSA - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $py_file"
            fi
            if grep -q "jwt.encode.*ES256\|jwt.encode.*ES384\|jwt.encode.*ES512" "$py_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$py_file"): JWT with ECDSA - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $py_file"
            fi
            # Check for PQ-safe patterns
            if grep -q "liboqs\|dilithium\|kyber\|sphincs" "$py_file" 2>/dev/null; then
                print_pass "$(basename "$py_file"): Post-quantum algorithms detected!"
                found_pq_safe=true
            fi
        done <<< "$py_files"

        echo ""
        print_info "Scanned $scanned_count Python files"
    else
        print_info "No Python files found in $scan_path"
    fi

    print_subheader "Python Analysis Summary"

    if [[ $vulnerable_patterns_found -gt 0 ]]; then
        print_fail "Found $vulnerable_patterns_found quantum-vulnerable crypto patterns"
        print_recommendation "Consider migrating to post-quantum alternatives"
        print_recommendation "Use liboqs-python for PQ algorithms: pip install liboqs-python"
    elif [[ "$found_crypto" == true ]]; then
        print_warn "Found crypto libraries that may need PQ migration planning"
    else
        print_info "No obvious crypto patterns detected (may use indirect dependencies)"
    fi

    if [[ "$found_pq_safe" == true ]]; then
        print_pass "Post-quantum safe libraries detected!"
    fi

    print_subheader "Python PQ Migration Recommendations"

    echo -e "  ${BOLD}1. For Key Exchange:${NC}"
    echo "     Replace: ECDH, DH, RSA key exchange"
    echo "     With: ML-KEM (Kyber) via liboqs-python"
    echo ""
    echo -e "  ${BOLD}2. For Digital Signatures:${NC}"
    echo "     Replace: RSA, ECDSA, EdDSA signatures"
    echo "     With: ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)"
    echo ""
    echo -e "  ${BOLD}3. For Symmetric Crypto:${NC}"
    echo "     Keep: AES-256, ChaCha20 (increase key size to 256-bit)"
    echo "     SHA-3 or SHA-256/512 remain secure"
    echo ""
    echo -e "  ${BOLD}4. Python PQ Libraries:${NC}"
    echo "     • liboqs-python: pip install liboqs-python"
    echo "     • pqcrypto: pip install pqcrypto"
    echo "     • oqs: https://github.com/open-quantum-safe/liboqs-python"
}

#-------------------------------------------------------------------------------
# JavaScript/Node.js Code Analysis
#-------------------------------------------------------------------------------

check_javascript_code() {
    local scan_path="${1:-.}"

    print_header "JAVASCRIPT/NODE.JS CRYPTOGRAPHIC LIBRARY ANALYSIS"

    print_info "Scanning directory: $scan_path"

    # Check if Node.js is installed
    if command_exists node; then
        local node_version
        node_version=$(node --version 2>/dev/null)
        print_info "Node.js version: $node_version"
    else
        print_warn "Node.js not installed"
    fi

    print_subheader "JavaScript Crypto Dependencies"

    local found_crypto=false
    local found_pq_safe=false
    local vulnerable_count=0

    # Check package.json files
    local package_files
    package_files=$(find "$scan_path" -maxdepth 5 -name "package.json" -type f ! -path "*/node_modules/*" 2>/dev/null)

    if [[ -n "$package_files" ]]; then
        echo ""
        echo -e "  ${BOLD}Found package.json files:${NC}"

        while IFS= read -r package_file; do
            [[ -z "$package_file" ]] && continue
            echo -e "    • $package_file"

            # Check for vulnerable crypto libraries
            if grep -q '"node-rsa"' "$package_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: node-rsa - RSA library (quantum-vulnerable)"
                ((vulnerable_count++))
            fi
            if grep -q '"elliptic"' "$package_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: elliptic - EC library (quantum-vulnerable)"
                ((vulnerable_count++))
            fi
            if grep -q '"jsrsasign"' "$package_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: jsrsasign - RSA/ECDSA (quantum-vulnerable)"
                ((vulnerable_count++))
            fi
            if grep -q '"jsonwebtoken"' "$package_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: jsonwebtoken - typically uses RSA/ECDSA"
                ((vulnerable_count++))
            fi
            if grep -q '"jose"' "$package_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: jose - JOSE/JWT (uses RSA/ECDSA)"
                ((vulnerable_count++))
            fi
            if grep -q '"node-forge"' "$package_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: node-forge - no PQ support"
                ((vulnerable_count++))
            fi
            if grep -q '"eccrypto"' "$package_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: eccrypto - EC encryption (quantum-vulnerable)"
                ((vulnerable_count++))
            fi
            if grep -q '"secp256k1"' "$package_file" 2>/dev/null; then
                found_crypto=true
                print_warn "Found: secp256k1 - Bitcoin EC (quantum-vulnerable)"
                ((vulnerable_count++))
            fi
            # PQ-safe libraries
            if grep -q '"liboqs-node"\|"crystals-kyber"\|"crystals-dilithium"' "$package_file" 2>/dev/null; then
                found_pq_safe=true
                print_pass "Found PQ-safe library in package.json"
            fi
            # Quantum-resistant (symmetric/hash)
            if grep -q '"bcrypt"' "$package_file" 2>/dev/null; then
                print_info "Found: bcrypt - password hashing (quantum-resistant)"
            fi
            if grep -q '"argon2"' "$package_file" 2>/dev/null; then
                print_info "Found: argon2 - password hashing (quantum-resistant)"
            fi
            if grep -q '"crypto-js"' "$package_file" 2>/dev/null; then
                print_info "Found: crypto-js - symmetric crypto (quantum-resistant)"
            fi
        done <<< "$package_files"
    fi

    # Check lock files for transitive dependencies
    local lock_files
    lock_files=$(find "$scan_path" -maxdepth 3 \( -name "package-lock.json" -o -name "yarn.lock" \) -type f ! -path "*/node_modules/*" 2>/dev/null)

    if [[ -n "$lock_files" ]]; then
        echo ""
        echo -e "  ${BOLD}Checking lock files for transitive dependencies...${NC}"

        while IFS= read -r lock_file; do
            [[ -z "$lock_file" ]] && continue
            if grep -q '"node-rsa"\|"elliptic"\|"jsrsasign"' "$lock_file" 2>/dev/null; then
                print_warn "Quantum-vulnerable dependencies in $(basename "$lock_file")"
            fi
        done <<< "$lock_files"
    fi

    print_subheader "JavaScript Source Code Analysis"

    # Scan JS/TS files for crypto usage patterns
    local js_files
    js_files=$(find "$scan_path" -maxdepth 5 \( -name "*.js" -o -name "*.ts" -o -name "*.mjs" -o -name "*.cjs" \) -type f ! -path "*/node_modules/*" ! -path "*/dist/*" ! -path "*/.next/*" ! -path "*/build/*" 2>/dev/null | head -100)

    local vulnerable_patterns_found=0

    if [[ -n "$js_files" ]]; then
        echo ""
        echo -e "  ${BOLD}Scanning JavaScript/TypeScript source files...${NC}"

        local scanned_count=0

        while IFS= read -r js_file; do
            [[ -z "$js_file" ]] && continue
            ((scanned_count++))

            # Check for RSA usage
            if grep -qi "generateKeyPair.*rsa\|generateKeyPairSync.*rsa" "$js_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$js_file"): RSA key generation - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $js_file"
            fi
            if grep -qi "new NodeRSA\|new RSAKey" "$js_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$js_file"): RSA operations - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $js_file"
            fi
            # Check for ECDH usage
            if grep -qi "createECDH\|createDiffieHellman" "$js_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$js_file"): ECDH/DH key exchange - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $js_file"
            fi
            # Check for elliptic curve usage
            if grep -qi "ec.keyFromPrivate\|ec.keyFromPublic\|elliptic.ec" "$js_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$js_file"): Elliptic curve - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $js_file"
            fi
            # Check for JWT with RSA/EC
            if grep -qi "jwt.sign.*RS256\|jwt.sign.*RS384\|jwt.sign.*RS512" "$js_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$js_file"): JWT with RSA - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $js_file"
            fi
            if grep -qi "jwt.sign.*ES256\|jwt.sign.*ES384\|jwt.sign.*ES512" "$js_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$js_file"): JWT with ECDSA - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $js_file"
            fi
            # Check for secp256k1
            if grep -qi "secp256k1" "$js_file" 2>/dev/null; then
                ((vulnerable_patterns_found++))
                print_warn "$(basename "$js_file"): secp256k1 (Bitcoin EC) - quantum-vulnerable"
                echo -e "      ${CYAN}File:${NC} $js_file"
            fi
            # Check for PQ-safe patterns
            if grep -qi "liboqs\|dilithium\|kyber" "$js_file" 2>/dev/null; then
                print_pass "$(basename "$js_file"): Post-quantum algorithms detected!"
                found_pq_safe=true
            fi
        done <<< "$js_files"

        echo ""
        print_info "Scanned $scanned_count JavaScript/TypeScript files"
    else
        print_info "No JavaScript/TypeScript files found in $scan_path"
    fi

    # Check for WebCrypto API usage
    print_subheader "WebCrypto API Analysis"

    local webcrypto_usage=false
    if [[ -n "$js_files" ]]; then
        while IFS= read -r js_file; do
            [[ -z "$js_file" ]] && continue
            if grep -q "crypto.subtle\|SubtleCrypto\|window.crypto" "$js_file" 2>/dev/null; then
                if [[ "$webcrypto_usage" == false ]]; then
                    echo -e "  ${BOLD}Files using WebCrypto API:${NC}"
                    webcrypto_usage=true
                fi
                echo -e "    • $js_file"
                if grep -qE "RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDSA|ECDH" "$js_file" 2>/dev/null; then
                    print_warn "$(basename "$js_file"): Uses RSA/EC algorithms (quantum-vulnerable)"
                    ((vulnerable_patterns_found++))
                fi
            fi
        done <<< "$js_files"
    fi

    if [[ "$webcrypto_usage" == false ]]; then
        print_info "No WebCrypto API usage detected"
    fi

    print_subheader "JavaScript Analysis Summary"

    if [[ $vulnerable_patterns_found -gt 0 ]]; then
        print_fail "Found $vulnerable_patterns_found quantum-vulnerable crypto patterns"
        print_recommendation "Consider migrating to post-quantum alternatives"
    elif [[ "$found_crypto" == true ]]; then
        print_warn "Found crypto libraries that may need PQ migration planning"
    else
        print_info "No obvious crypto patterns detected"
    fi

    if [[ "$found_pq_safe" == true ]]; then
        print_pass "Post-quantum safe libraries detected!"
    fi

    print_subheader "JavaScript PQ Migration Recommendations"

    echo -e "  ${BOLD}1. For Key Exchange:${NC}"
    echo "     Replace: ECDH, DH, RSA key encapsulation"
    echo "     With: ML-KEM (Kyber) when JS bindings available"
    echo ""
    echo -e "  ${BOLD}2. For Digital Signatures:${NC}"
    echo "     Replace: RSA, ECDSA signatures"
    echo "     With: ML-DSA (Dilithium) or hybrid schemes"
    echo ""
    echo -e "  ${BOLD}3. For Symmetric Crypto:${NC}"
    echo "     Keep: AES-256-GCM, ChaCha20-Poly1305"
    echo "     These remain quantum-resistant"
    echo ""
    echo -e "  ${BOLD}4. For JWTs:${NC}"
    echo "     Current: RS256, ES256 are vulnerable"
    echo "     Future: Wait for PQ JWT standards"
    echo "     Interim: Consider shorter token lifetimes"
    echo ""
    echo -e "  ${BOLD}5. JavaScript PQ Libraries:${NC}"
    echo "     • liboqs-node (Node.js bindings for OQS)"
    echo "     • pqcrypto-js (experimental)"
    echo "     • crystals-kyber (npm package)"
    echo "     • Note: PQ support in JS is still maturing"
}

#-------------------------------------------------------------------------------
# Combined Code Analysis
#-------------------------------------------------------------------------------

check_code() {
    local scan_path="${1:-.}"

    check_python_code "$scan_path"
    check_javascript_code "$scan_path"
}

#-------------------------------------------------------------------------------
# Helm Chart Analysis
#-------------------------------------------------------------------------------

check_helm() {
    local scan_path="${1:-.}"

    print_header "HELM CHART CRYPTOGRAPHIC ANALYSIS"
    echo -e "  ${BLUE}[INFO]${NC} Scanning directory: $scan_path"

    local helm_vuln_count=0
    local values_files
    local template_files

    # Find Helm values files
    values_files=$(find "$scan_path" -type f \( -name "values.yaml" -o -name "values.yml" -o -name "values-*.yaml" -o -name "values-*.yml" \) 2>/dev/null)

    # Find Helm template files
    template_files=$(find "$scan_path" -type f \( -name "*.yaml" -o -name "*.yml" \) -path "*/templates/*" 2>/dev/null)

    # Find Chart.yaml files
    local chart_files
    chart_files=$(find "$scan_path" -type f -name "Chart.yaml" 2>/dev/null)

    if [[ -z "$values_files" && -z "$template_files" && -z "$chart_files" ]]; then
        echo -e "  ${BLUE}[INFO]${NC} No Helm charts found in $scan_path"
        return 0
    fi

    print_subheader "Helm Values Files Analysis"

    if [[ -n "$values_files" ]]; then
        echo -e "  ${BOLD}Found values files:${NC}"
        echo "$values_files" | while read -r file; do
            [[ -z "$file" ]] && continue
            echo "    • $file"
        done
        echo ""

        # Analyze values files for crypto patterns
        echo "$values_files" | while read -r file; do
            [[ -z "$file" ]] && continue

            local filename
            filename=$(basename "$file")

            # Check for RSA configurations
            if grep -qi "RSA\|rsa-private\|rsa-public\|RSA_" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: RSA configuration detected (quantum-vulnerable)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((helm_vuln_count++))
            fi

            # Check for ECDSA/ECDH configurations
            if grep -qi "ECDSA\|ECDH\|ecdsa-\|secp256\|secp384\|P-256\|P-384\|P-521" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: ECDSA/ECDH configuration detected (quantum-vulnerable)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((helm_vuln_count++))
            fi

            # Check for JWT RS*/ES* algorithms
            if grep -qiE "RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: JWT with RSA/ECDSA algorithm (quantum-vulnerable)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((helm_vuln_count++))
            fi

            # Check for ssl-ciphers with ECDHE
            if grep -qi "ssl-ciphers.*ECDHE" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: ECDHE cipher configuration (quantum-vulnerable key exchange)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((helm_vuln_count++))
            fi

            # Check for safe configurations
            if grep -qi "AES-256\|aes-256-gcm\|argon2\|bcrypt\|SHA-256\|SHA-384\|HMAC" "$file" 2>/dev/null; then
                echo -e "  ${BLUE}[INFO]${NC} $filename: Quantum-resistant symmetric crypto found"
            fi
        done
    fi

    print_subheader "Helm Template Files Analysis"

    if [[ -n "$template_files" ]]; then
        local template_count=0
        echo "$template_files" | while read -r file; do
            [[ -z "$file" ]] && continue

            local filename
            filename=$(basename "$file")

            # Check for RSA in templates
            if grep -qi "RSA\|rsa-private\|rsa-public" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: RSA reference in template (quantum-vulnerable)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((helm_vuln_count++))
            fi

            # Check for JWT algorithms in templates
            if grep -qiE "JWT_ALGORITHM.*RS256|JWT_ALGORITHM.*ES256|algorithm.*RS256|algorithm.*ES256" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: JWT algorithm configuration (quantum-vulnerable)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((helm_vuln_count++))
            fi

            # Check for cert-manager RSA/ECDSA
            if grep -qi "private-key-algorithm.*RSA\|private-key-algorithm.*ECDSA" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: cert-manager RSA/ECDSA key type (quantum-vulnerable)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((helm_vuln_count++))
            fi

            ((template_count++))
        done
        echo -e "  ${BLUE}[INFO]${NC} Scanned $template_count template files"
    fi

    print_subheader "Helm Analysis Summary"

    if [[ $helm_vuln_count -gt 0 ]]; then
        print_fail "Found quantum-vulnerable configurations in Helm charts"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        print_pass "No obvious quantum-vulnerable patterns in Helm charts"
    fi

    print_subheader "Helm PQ Migration Recommendations"

    echo -e "  ${BOLD}1. TLS Certificates:${NC}"
    echo "     • Prepare for hybrid certificates (classical + PQ)"
    echo "     • Monitor cert-manager for PQ algorithm support"
    echo ""
    echo -e "  ${BOLD}2. Ingress Configuration:${NC}"
    echo "     • Enable TLS 1.3 minimum"
    echo "     • Prepare for PQ cipher suites when available"
    echo ""
    echo -e "  ${BOLD}3. JWT/Authentication:${NC}"
    echo "     • Plan migration from RS256/ES256 to PQ algorithms"
    echo "     • Consider shorter token lifetimes during transition"
}

#-------------------------------------------------------------------------------
# Kubernetes Manifest Analysis
#-------------------------------------------------------------------------------

check_kubernetes() {
    local scan_path="${1:-.}"

    print_header "KUBERNETES MANIFEST CRYPTOGRAPHIC ANALYSIS"
    echo -e "  ${BLUE}[INFO]${NC} Scanning directory: $scan_path"

    local k8s_vuln_count=0

    # Find Kubernetes manifest files (excluding Helm templates)
    local k8s_files
    k8s_files=$(find "$scan_path" -type f \( -name "*.yaml" -o -name "*.yml" \) ! -path "*/templates/*" ! -name "Chart.yaml" ! -name "values*.yaml" 2>/dev/null)

    if [[ -z "$k8s_files" ]]; then
        echo -e "  ${BLUE}[INFO]${NC} No Kubernetes manifests found in $scan_path"
        return 0
    fi

    print_subheader "Kubernetes Resource Analysis"

    # Categorize files by type
    local secrets=""
    local configmaps=""
    local deployments=""
    local ingresses=""
    local other=""

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        if grep -q "kind: Secret" "$file" 2>/dev/null; then
            secrets="$secrets$file"$'\n'
        elif grep -q "kind: ConfigMap" "$file" 2>/dev/null; then
            configmaps="$configmaps$file"$'\n'
        elif grep -q "kind: Deployment\|kind: StatefulSet\|kind: DaemonSet" "$file" 2>/dev/null; then
            deployments="$deployments$file"$'\n'
        elif grep -q "kind: Ingress" "$file" 2>/dev/null; then
            ingresses="$ingresses$file"$'\n'
        else
            other="$other$file"$'\n'
        fi
    done <<< "$k8s_files"

    # Analyze Secrets
    if [[ -n "$secrets" ]]; then
        echo -e "\n  ${BOLD}Secrets:${NC}"
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            local filename
            filename=$(basename "$file")

            # Check for TLS secrets with RSA
            if grep -qi "kubernetes.io/tls\|tls.crt\|tls.key\|RSA PRIVATE KEY" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: TLS secret (likely RSA/ECDSA - quantum-vulnerable)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((k8s_vuln_count++))
                WARN_COUNT=$((WARN_COUNT + 1))
            fi

            # Check for ECDSA keys
            if grep -qi "EC PRIVATE KEY\|ecdsa-private\|ecdsa-public" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: ECDSA key secret (quantum-vulnerable)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((k8s_vuln_count++))
                WARN_COUNT=$((WARN_COUNT + 1))
            fi

            # Check for JWT secrets
            if grep -qiE "jwt.*RS256|jwt.*ES256|jwt-algorithm.*RS|jwt-algorithm.*ES" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: JWT RSA/ECDSA configuration (quantum-vulnerable)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((k8s_vuln_count++))
                WARN_COUNT=$((WARN_COUNT + 1))
            fi
        done <<< "$secrets"
    fi

    # Analyze ConfigMaps
    if [[ -n "$configmaps" ]]; then
        echo -e "\n  ${BOLD}ConfigMaps:${NC}"
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            local filename
            filename=$(basename "$file")

            # Check for crypto algorithm configurations
            if grep -qiE "KEY_EXCHANGE.*ECDH|KEY_EXCHANGE.*DH|SIGNATURE.*RSA|SIGNATURE.*ECDSA" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: Quantum-vulnerable algorithm configuration"
                echo -e "      ${CYAN}File:${NC} $file"
                ((k8s_vuln_count++))
                WARN_COUNT=$((WARN_COUNT + 1))
            fi

            # Check for JWT algorithm in config
            if grep -qiE "JWT.*RS256|JWT.*ES256|JWT.*PS256" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: JWT RSA/ECDSA algorithm configuration"
                echo -e "      ${CYAN}File:${NC} $file"
                ((k8s_vuln_count++))
                WARN_COUNT=$((WARN_COUNT + 1))
            fi

            # Check for safe configurations
            if grep -qi "AES-256\|argon2\|bcrypt\|SHA-384\|HMAC-SHA256" "$file" 2>/dev/null; then
                echo -e "  ${BLUE}[INFO]${NC} $filename: Quantum-resistant symmetric crypto configured"
            fi
        done <<< "$configmaps"
    fi

    # Analyze Ingresses
    if [[ -n "$ingresses" ]]; then
        echo -e "\n  ${BOLD}Ingress Resources:${NC}"
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            local filename
            filename=$(basename "$file")

            # Check for ssl-ciphers annotations
            if grep -qi "ssl-ciphers.*ECDHE" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: ECDHE cipher suite (quantum-vulnerable key exchange)"
                echo -e "      ${CYAN}File:${NC} $file"
                ((k8s_vuln_count++))
                WARN_COUNT=$((WARN_COUNT + 1))
            fi

            # Check for cert-manager RSA/ECDSA
            if grep -qi "private-key-algorithm.*RSA\|private-key-algorithm.*ECDSA" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: cert-manager RSA/ECDSA key configuration"
                echo -e "      ${CYAN}File:${NC} $file"
                ((k8s_vuln_count++))
                WARN_COUNT=$((WARN_COUNT + 1))
            fi

            # Check for TLS 1.3
            if grep -qi "TLSv1.3\|ssl-protocols.*1.3" "$file" 2>/dev/null; then
                echo -e "  ${GREEN}[PASS]${NC} $filename: TLS 1.3 enabled (required for PQ)"
                PASS_COUNT=$((PASS_COUNT + 1))
            fi
        done <<< "$ingresses"
    fi

    # Analyze Deployments
    if [[ -n "$deployments" ]]; then
        echo -e "\n  ${BOLD}Deployments/StatefulSets/DaemonSets:${NC}"
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            local filename
            filename=$(basename "$file")

            # Check for env vars with crypto settings
            if grep -qiE "JWT_ALGORITHM.*RS|JWT_ALGORITHM.*ES|SIGNING_KEY_TYPE.*RSA|KEY_EXCHANGE.*ECDH" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}[WARN]${NC} $filename: Quantum-vulnerable crypto env vars"
                echo -e "      ${CYAN}File:${NC} $file"
                ((k8s_vuln_count++))
                WARN_COUNT=$((WARN_COUNT + 1))
            fi

            # Check for safe configurations
            if grep -qiE "ENCRYPTION.*AES|HASH.*SHA-256|PASSWORD_HASH.*argon2" "$file" 2>/dev/null; then
                echo -e "  ${BLUE}[INFO]${NC} $filename: Quantum-resistant symmetric crypto"
            fi
        done <<< "$deployments"
    fi

    print_subheader "Kubernetes Analysis Summary"

    local total_files
    total_files=$(echo "$k8s_files" | grep -c "." 2>/dev/null || echo "0")
    echo -e "  ${BLUE}[INFO]${NC} Scanned $total_files Kubernetes manifest files"

    if [[ $k8s_vuln_count -gt 0 ]]; then
        print_fail "Found $k8s_vuln_count quantum-vulnerable configurations in Kubernetes manifests"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        print_pass "No obvious quantum-vulnerable patterns in Kubernetes manifests"
    fi

    print_subheader "Kubernetes PQ Migration Recommendations"

    echo -e "  ${BOLD}1. Certificate Management:${NC}"
    echo "     • Monitor cert-manager for PQ algorithm support"
    echo "     • Plan for hybrid certificate deployment"
    echo "     • Update certificate rotation procedures"
    echo ""
    echo -e "  ${BOLD}2. Secrets Management:${NC}"
    echo "     • Inventory all TLS secrets using RSA/ECDSA"
    echo "     • Prepare migration plan for signing keys"
    echo "     • Update secret rotation procedures"
    echo ""
    echo -e "  ${BOLD}3. Ingress Controllers:${NC}"
    echo "     • Ensure TLS 1.3 is enabled"
    echo "     • Monitor for PQ cipher suite support"
    echo "     • Consider service mesh for mTLS with PQ"
    echo ""
    echo -e "  ${BOLD}4. Application Configuration:${NC}"
    echo "     • Audit JWT algorithms in use"
    echo "     • Plan migration from RS*/ES* to PQ algorithms"
    echo "     • Update ConfigMaps with PQ-ready defaults"
}

check_k8s() {
    local scan_path="${1:-.}"
    check_helm "$scan_path"
    check_kubernetes "$scan_path"
}

#-------------------------------------------------------------------------------
# Cipher Suite Analysis
#-------------------------------------------------------------------------------

check_system_ciphers() {
    print_header "SYSTEM CIPHER SUITE ANALYSIS"

    if ! command_exists openssl; then
        print_fail "OpenSSL not available for cipher analysis"
        return 1
    fi

    print_subheader "Available TLS 1.3 Cipher Suites"

    local tls13_ciphers
    tls13_ciphers=$(openssl ciphers -v 2>/dev/null | grep -i "TLSv1.3")

    if [[ -z "$tls13_ciphers" ]]; then
        tls13_ciphers=$(openssl ciphers -v 'TLSv1.3' 2>/dev/null)
    fi

    if [[ -n "$tls13_ciphers" ]]; then
        echo "$tls13_ciphers" | while read -r line; do
            echo -e "    ${GREEN}✓${NC} $line"
        done
        print_pass "TLS 1.3 cipher suites available"
    else
        print_fail "No TLS 1.3 cipher suites available"
    fi

    print_subheader "Weak Cipher Detection"

    # Check for weak ciphers (always exclude TLS 1.3 which are strong AEAD ciphers)
    local weak_ciphers
    weak_ciphers=$(openssl ciphers -v 'LOW:EXPORT:NULL:DES:RC4:MD5:aNULL:eNULL' 2>/dev/null | grep -v "TLSv1\.3")

    if [[ -n "$weak_ciphers" ]]; then
        print_warn "Weak ciphers are available in OpenSSL (but may not be enabled)"
        echo "$weak_ciphers" | head -10 | while read -r line; do
            echo -e "    ${RED}✗${NC} $line"
        done
        local weak_count
        weak_count=$(echo "$weak_ciphers" | wc -l | tr -d ' ')
        if [[ $weak_count -gt 10 ]]; then
            echo -e "    ... and $((weak_count - 10)) more"
        fi
    else
        print_pass "No weak ciphers available"
    fi

    print_subheader "Recommended Modern Cipher Configuration"

    echo -e "  ${BOLD}For TLS 1.3 (PQ-ready):${NC}"
    echo "    TLS_AES_256_GCM_SHA384"
    echo "    TLS_CHACHA20_POLY1305_SHA256"
    echo "    TLS_AES_128_GCM_SHA256"
    echo ""
    echo -e "  ${BOLD}For TLS 1.2 (fallback):${NC}"
    echo "    ECDHE-ECDSA-AES256-GCM-SHA384"
    echo "    ECDHE-RSA-AES256-GCM-SHA384"
    echo "    ECDHE-ECDSA-CHACHA20-POLY1305"
    echo "    ECDHE-RSA-CHACHA20-POLY1305"

    print_subheader "Post-Quantum Key Exchange (when available)"

    echo -e "  ${BOLD}Hybrid KEMs (recommended for transition):${NC}"
    for kem in "${HYBRID_KEMs[@]}"; do
        echo "    • $kem"
    done

    echo ""
    echo -e "  ${BOLD}Pure PQ KEMs:${NC}"
    for kem in "${PQ_KEMs[@]}"; do
        echo "    • $kem"
    done
}

#-------------------------------------------------------------------------------
# Remote Server Testing
#-------------------------------------------------------------------------------

test_remote_server() {
    local host_port="$1"

    print_header "REMOTE SERVER TEST: $host_port"

    if ! command_exists openssl; then
        print_fail "OpenSSL not available for remote testing"
        return 1
    fi

    local host=$(echo "$host_port" | cut -d: -f1)
    local port=$(echo "$host_port" | cut -d: -f2)
    port=${port:-443}

    print_info "Testing: $host:$port"

    print_subheader "Connection Test"

    # Basic connectivity test
    if ! timeout 10 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        print_fail "Cannot connect to $host:$port"
        return 1
    fi
    print_pass "Connection successful"

    print_subheader "Certificate Information"

    local cert_info=$(echo | timeout 10 openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)

    if [[ -n "$cert_info" ]]; then
        local subject issuer sig_algo pubkey
        subject=$(echo "$cert_info" | grep "Subject:" | head -1)
        issuer=$(echo "$cert_info" | grep "Issuer:" | head -1)
        sig_algo=$(echo "$cert_info" | grep "Signature Algorithm" | head -1)
        pubkey=$(echo "$cert_info" | grep "Public Key Algorithm" | head -1)

        echo -e "  $subject"
        echo -e "  $issuer"
        echo -e "  $sig_algo"
        echo -e "  $pubkey"

        # Check for PQ signatures
        if echo "$sig_algo" | grep -qiE "dilithium|falcon|sphincs|ml-dsa"; then
            print_pass "Post-quantum signature algorithm detected!"
        else
            print_info "Classical signature algorithm (expected during transition)"
        fi

        # Check key size
        local key_bits=$(echo "$cert_info" | grep -o '([0-9]* bit)' | head -1)
        if [[ -n "$key_bits" ]]; then
            echo -e "  Key size: $key_bits"
        fi
    fi

    print_subheader "TLS Version Support"

    # Test TLS versions
    for tls_ver in "tls1" "tls1_1" "tls1_2" "tls1_3"; do
        local display_ver=$(echo "$tls_ver" | sed 's/tls1$/TLS 1.0/' | sed 's/tls1_1/TLS 1.1/' | sed 's/tls1_2/TLS 1.2/' | sed 's/tls1_3/TLS 1.3/')

        if echo | timeout 5 openssl s_client -connect "$host:$port" -servername "$host" -"$tls_ver" 2>/dev/null | grep -q "Cipher is"; then
            case "$tls_ver" in
                tls1|tls1_1)
                    print_fail "$display_ver is ENABLED (insecure)"
                    ;;
                tls1_2)
                    print_pass "$display_ver is enabled"
                    ;;
                tls1_3)
                    print_pass "$display_ver is enabled (required for PQ)"
                    ;;
            esac
        else
            case "$tls_ver" in
                tls1|tls1_1)
                    print_pass "$display_ver is disabled (good)"
                    ;;
                tls1_3)
                    print_warn "$display_ver is NOT enabled"
                    print_recommendation "Enable TLS 1.3 for post-quantum key exchange support"
                    ;;
                *)
                    print_info "$display_ver is disabled"
                    ;;
            esac
        fi
    done

    print_subheader "Cipher Suite Analysis"

    # Get negotiated cipher
    local cipher_info=$(echo | timeout 10 openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null | grep "Cipher is")
    if [[ -n "$cipher_info" ]]; then
        echo -e "  ${BOLD}Negotiated:${NC} $cipher_info"
    fi

    # Test for PQ key exchange (if s_client supports it)
    print_subheader "Post-Quantum Key Exchange Test"

    # Check if OpenSSL supports PQ groups
    local pq_groups=("kyber768" "x25519_kyber768" "p256_kyber768")
    local pq_supported=false

    for group in "${pq_groups[@]}"; do
        local result=$(echo | timeout 10 openssl s_client -connect "$host:$port" -servername "$host" -groups "$group" 2>&1)
        if echo "$result" | grep -q "Cipher is" && ! echo "$result" | grep -qi "error\|unknown"; then
            print_pass "Server supports PQ key exchange: $group"
            pq_supported=true
        fi
    done

    if [[ "$pq_supported" == false ]]; then
        print_info "Server does not appear to support PQ key exchange (or local OpenSSL lacks PQ support)"
        print_recommendation "This is expected - PQ deployment is still in early stages"
    fi
}

#-------------------------------------------------------------------------------
# Recommendations & Summary
#-------------------------------------------------------------------------------

print_recommendations() {
    print_header "POST-QUANTUM MIGRATION RECOMMENDATIONS"

    print_subheader "Immediate Actions (Do Now)"

    echo -e "  ${BOLD}1. Enable TLS 1.3${NC}"
    echo "     TLS 1.3 is required for post-quantum key exchange."
    echo "     • Nginx:  ssl_protocols TLSv1.2 TLSv1.3;"
    echo "     • Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3"
    echo ""

    echo -e "  ${BOLD}2. Disable Legacy Protocols${NC}"
    echo "     Remove support for TLS 1.0, TLS 1.1, SSLv2, SSLv3"
    echo ""

    echo -e "  ${BOLD}3. Use Strong Cipher Suites${NC}"
    echo "     Prefer AEAD ciphers: AES-GCM, ChaCha20-Poly1305"
    echo ""

    print_subheader "Short-Term Actions (This Quarter)"

    echo -e "  ${BOLD}4. Upgrade OpenSSL${NC}"
    echo "     • Minimum: OpenSSL 3.0.x"
    echo "     • Recommended: OpenSSL 3.2+ (native provider support)"
    echo ""

    echo -e "  ${BOLD}5. Install OQS Provider${NC}"
    echo "     • GitHub: https://github.com/open-quantum-safe/oqs-provider"
    echo "     • Provides ML-KEM, ML-DSA, and hybrid algorithms"
    echo ""

    echo -e "  ${BOLD}6. Test Hybrid Key Exchange${NC}"
    echo "     • Start with X25519+Kyber768 hybrid"
    echo "     • Maintains classical security while adding PQ protection"
    echo ""

    print_subheader "Long-Term Strategy"

    echo -e "  ${BOLD}7. Monitor NIST Standards${NC}"
    echo "     • ML-KEM (FIPS 203) - Key Encapsulation"
    echo "     • ML-DSA (FIPS 204) - Digital Signatures"
    echo "     • SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures"
    echo ""

    echo -e "  ${BOLD}8. Plan Certificate Migration${NC}"
    echo "     • Prepare for PQ certificate issuance"
    echo "     • Consider hybrid certificates during transition"
    echo ""

    echo -e "  ${BOLD}9. Inventory Cryptographic Assets${NC}"
    echo "     • Document all systems using public key cryptography"
    echo "     • Prioritize systems with long-term data protection needs"
    echo ""

    print_subheader "Additional Resources"

    echo "  • NIST PQC Project: https://csrc.nist.gov/projects/post-quantum-cryptography"
    echo "  • Open Quantum Safe: https://openquantumsafe.org/"
    echo "  • OQS Provider: https://github.com/open-quantum-safe/oqs-provider"
    echo "  • liboqs: https://github.com/open-quantum-safe/liboqs"
    echo "  • Cloudflare PQ: https://blog.cloudflare.com/post-quantum-cryptography/"
}

print_summary() {
    print_header "VERIFICATION SUMMARY"

    local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))

    echo -e "  ${GREEN}Passed:${NC}   $PASS_COUNT"
    echo -e "  ${YELLOW}Warnings:${NC} $WARN_COUNT"
    echo -e "  ${RED}Failed:${NC}   $FAIL_COUNT"
    echo -e "  ${BOLD}Total:${NC}    $total checks"
    echo ""

    # Overall assessment
    if [[ $FAIL_COUNT -eq 0 && $WARN_COUNT -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}Overall: EXCELLENT${NC}"
        echo "  Your system appears well-prepared for post-quantum transition."
    elif [[ $FAIL_COUNT -eq 0 ]]; then
        echo -e "  ${YELLOW}${BOLD}Overall: GOOD (with recommendations)${NC}"
        echo "  Your system has a solid foundation. Review warnings above."
    elif [[ $FAIL_COUNT -lt 3 ]]; then
        echo -e "  ${YELLOW}${BOLD}Overall: NEEDS ATTENTION${NC}"
        echo "  Several issues require attention before PQ readiness."
    else
        echo -e "  ${RED}${BOLD}Overall: ACTION REQUIRED${NC}"
        echo "  Significant changes needed for post-quantum readiness."
    fi

    echo ""
    echo -e "  ${BOLD}Log file:${NC} $LOG_FILE"
}

print_summary_quiet() {
    local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))

    # One-line summary for quiet mode
    local status=""
    if [[ $FAIL_COUNT -eq 0 && $WARN_COUNT -eq 0 ]]; then
        status="${GREEN}EXCELLENT${NC}"
    elif [[ $FAIL_COUNT -eq 0 ]]; then
        status="${YELLOW}GOOD${NC}"
    elif [[ $FAIL_COUNT -lt 3 ]]; then
        status="${YELLOW}NEEDS ATTENTION${NC}"
    else
        status="${RED}ACTION REQUIRED${NC}"
    fi

    echo -e "PQ-Check: ${status} | Pass: $PASS_COUNT | Warn: $WARN_COUNT | Fail: $FAIL_COUNT | Total: $total"
}

#-------------------------------------------------------------------------------
# Main Execution
#-------------------------------------------------------------------------------

main() {
    local run_all=true
    local check_server=""
    local test_host=""
    local report_file=""
    local quiet_mode=false
    local check_openssl_only=false
    local check_libraries_only=false
    local check_ciphers_only=false
    local check_python_path=""
    local check_javascript_path=""
    local check_code_path=""
    local check_helm_path=""
    local check_k8s_path=""

    # Parse command line arguments (collect all options first)
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                echo "pq-check version $VERSION"
                exit 0
                ;;
            -a|--all)
                run_all=true
                shift
                ;;
            -s|--server)
                check_server="$2"
                run_all=false
                shift 2
                ;;
            -o|--openssl)
                check_openssl_only=true
                run_all=false
                shift
                ;;
            -l|--libraries)
                check_libraries_only=true
                run_all=false
                shift
                ;;
            -c|--ciphers)
                check_ciphers_only=true
                run_all=false
                shift
                ;;
            -p|--python)
                run_all=false
                check_python_path="."
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    check_python_path="$2"
                    shift
                fi
                shift
                ;;
            -j|--javascript)
                run_all=false
                check_javascript_path="."
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    check_javascript_path="$2"
                    shift
                fi
                shift
                ;;
            --code)
                run_all=false
                check_code_path="."
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    check_code_path="$2"
                    shift
                fi
                shift
                ;;
            -t|--test)
                test_host="$2"
                run_all=false
                shift 2
                ;;
            -r|--report)
                report_file="$2"
                shift 2
                ;;
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            --no-color)
                RED=''
                GREEN=''
                YELLOW=''
                BLUE=''
                CYAN=''
                MAGENTA=''
                NC=''
                BOLD=''
                shift
                ;;
            --helm)
                run_all=false
                check_helm_path="."
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    check_helm_path="$2"
                    shift
                fi
                shift
                ;;
            --k8s|--kubernetes)
                run_all=false
                check_k8s_path="."
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    check_k8s_path="$2"
                    shift
                fi
                shift
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Helper function to save report
    save_report() {
        if [[ -n "$report_file" ]]; then
            cp "$LOG_FILE" "$report_file"
            echo ""
            echo -e "  ${GREEN}Report saved to:${NC} $report_file"
        fi
    }

    # Header (skip in quiet mode for specific checks)
    if [[ "$quiet_mode" != true || "$run_all" == true ]]; then
        echo ""
        echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${CYAN}║     POST-QUANTUM CRYPTOGRAPHY READINESS VERIFICATION TOOL        ║${NC}"
        echo -e "${BOLD}${CYAN}║                        Version $VERSION                              ║${NC}"
        echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    fi

    log "Starting PQ-Check version $VERSION"

    # Run checks based on options
    if [[ -n "$test_host" ]]; then
        if [[ "$quiet_mode" != true ]]; then
            test_remote_server "$test_host"
            print_summary
        else
            test_remote_server "$test_host" > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ -n "$check_server" ]]; then
        if [[ "$quiet_mode" != true ]]; then
            case "$check_server" in
                nginx)
                    check_nginx
                    ;;
                apache|httpd)
                    check_apache
                    ;;
                haproxy)
                    check_haproxy
                    ;;
                caddy)
                    check_caddy
                    ;;
                *)
                    echo "Unknown server type: $check_server"
                    echo "Supported: nginx, apache, httpd, haproxy, caddy"
                    exit 1
                    ;;
            esac
            print_summary
        else
            case "$check_server" in
                nginx)
                    check_nginx > /dev/null 2>&1
                    ;;
                apache|httpd)
                    check_apache > /dev/null 2>&1
                    ;;
                haproxy)
                    check_haproxy > /dev/null 2>&1
                    ;;
                caddy)
                    check_caddy > /dev/null 2>&1
                    ;;
                *)
                    echo "Unknown server type: $check_server"
                    echo "Supported: nginx, apache, httpd, haproxy, caddy"
                    exit 1
                    ;;
            esac
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ "$check_openssl_only" == true ]]; then
        if [[ "$quiet_mode" != true ]]; then
            check_openssl
            print_summary
        else
            check_openssl > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ "$check_libraries_only" == true ]]; then
        if [[ "$quiet_mode" != true ]]; then
            check_openssl
            print_summary
        else
            check_openssl > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ "$check_ciphers_only" == true ]]; then
        if [[ "$quiet_mode" != true ]]; then
            check_system_ciphers
            print_summary
        else
            check_system_ciphers > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ -n "$check_python_path" ]]; then
        if [[ "$quiet_mode" != true ]]; then
            check_python_code "$check_python_path"
            print_summary
        else
            check_python_code "$check_python_path" > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ -n "$check_javascript_path" ]]; then
        if [[ "$quiet_mode" != true ]]; then
            check_javascript_code "$check_javascript_path"
            print_summary
        else
            check_javascript_code "$check_javascript_path" > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ -n "$check_code_path" ]]; then
        if [[ "$quiet_mode" != true ]]; then
            check_code "$check_code_path"
            print_summary
        else
            check_code "$check_code_path" > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ -n "$check_helm_path" ]]; then
        if [[ "$quiet_mode" != true ]]; then
            check_helm "$check_helm_path"
            print_summary
        else
            check_helm "$check_helm_path" > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ -n "$check_k8s_path" ]]; then
        if [[ "$quiet_mode" != true ]]; then
            check_k8s "$check_k8s_path"
            print_summary
        else
            check_k8s "$check_k8s_path" > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
        exit 0
    fi

    if [[ "$run_all" == true ]]; then
        if [[ "$quiet_mode" != true ]]; then
            check_system_info
            check_openssl
            check_nginx
            check_apache
            check_haproxy
            check_caddy
            check_system_ciphers
            check_python_code "."
            check_javascript_code "."
            print_recommendations
            print_summary
        else
            # Quiet mode: still run checks but suppress output, show summary only
            check_openssl > /dev/null 2>&1
            check_nginx > /dev/null 2>&1
            check_apache > /dev/null 2>&1
            check_haproxy > /dev/null 2>&1
            check_caddy > /dev/null 2>&1
            check_system_ciphers > /dev/null 2>&1
            print_summary_quiet
        fi
        save_report
    fi
}

# Run main function
main "$@"
