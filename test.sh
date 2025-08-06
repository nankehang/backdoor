#!/bin/bash

# C2 Framework Test Script
# For educational and authorized testing purposes only

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                            C2 Framework Test Suite                          ║${NC}"
    echo -e "${PURPLE}║                     Educational & Authorized Testing Only                   ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

test_rust_installation() {
    print_status "Testing Rust installation..."
    if command -v cargo >/dev/null 2>&1; then
        local rust_version=$(rustc --version)
        print_success "Rust installed: $rust_version"
        return 0
    else
        print_error "Rust not found. Install from https://rustup.rs/"
        return 1
    fi
}

test_compilation() {
    print_status "Testing compilation..."
    
    # Test server compilation
    print_status "Compiling C2 server..."
    cd c2_server
    if cargo check --quiet; then
        print_success "Server compilation check passed"
    else
        print_error "Server compilation failed"
        return 1
    fi
    cd ..
    
    # Test client compilation
    print_status "Compiling C2 client..."
    cd c2_client
    if cargo check --quiet; then
        print_success "Client compilation check passed"
    else
        print_error "Client compilation failed"
        return 1
    fi
    cd ..
    
    return 0
}

test_crypto_functions() {
    print_status "Testing cryptographic functions..."
    
    # Create a simple test for crypto functions
    cat > crypto_test.rs << 'EOF'
use base64::{engine::general_purpose, Engine as _};
use aes_gcm::{aead::{Aead, KeyInit, generic_array::GenericArray}, Aes256Gcm, Nonce};
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing AES-256-GCM...");
    
    // Test AES encryption/decryption
    let key = [0u8; 32]; // Test key
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let plaintext = b"Hello, C2 Framework!";
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
    let decrypted = cipher.decrypt(nonce, ciphertext.as_ref())?;
    
    assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    println!("✓ AES-256-GCM encryption/decryption works");
    
    println!("Testing RSA key generation...");
    
    // Test RSA key generation and encryption/decryption
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = RsaPublicKey::from(&private_key);
    
    let test_data = b"Test RSA encryption";
    let encrypted = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, test_data)?;
    let decrypted = private_key.decrypt(Pkcs1v15Encrypt, &encrypted)?;
    
    assert_eq!(test_data.as_ref(), decrypted.as_slice());
    println!("✓ RSA-2048 encryption/decryption works");
    
    println!("All cryptographic tests passed!");
    Ok(())
}
EOF

    # Create temporary Cargo.toml for crypto test
    cat > Cargo.toml << 'EOF'
[package]
name = "crypto_test"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "crypto_test"
path = "crypto_test.rs"

[dependencies]
aes-gcm = "0.10"
rsa = { version = "0.9", features = ["pem"] }
rand = "0.8"
base64 = "0.21"
EOF

    if cargo run --bin crypto_test --quiet; then
        print_success "Cryptographic functions test passed"
        rm -f crypto_test.rs Cargo.toml Cargo.lock
        rm -rf target
        return 0
    else
        print_error "Cryptographic functions test failed"
        rm -f crypto_test.rs Cargo.toml Cargo.lock
        rm -rf target
        return 1
    fi
}

test_network_functionality() {
    print_status "Testing network functionality..."
    
    # Test if we can bind to localhost (basic network test)
    cat > network_test.rs << 'EOF'
use std::net::TcpListener;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing TCP binding...");
    
    // Try to bind to a high port
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    println!("✓ Successfully bound to {}", addr);
    
    drop(listener);
    println!("✓ Socket cleanup successful");
    
    Ok(())
}
EOF

    cat > Cargo.toml << 'EOF'
[package]
name = "network_test"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "network_test"
path = "network_test.rs"
EOF

    if cargo run --bin network_test --quiet; then
        print_success "Network functionality test passed"
        rm -f network_test.rs Cargo.toml Cargo.lock
        rm -rf target
        return 0
    else
        print_error "Network functionality test failed"
        rm -f network_test.rs Cargo.toml Cargo.lock
        rm -rf target
        return 1
    fi
}

test_cross_compilation() {
    print_status "Testing cross-compilation capabilities..."
    
    # Check available targets
    local targets=$(rustup target list --installed)
    print_status "Installed targets: $targets"
    
    # Test if we can add a target (but don't actually compile for it)
    if rustup target list | grep -q "x86_64-pc-windows-gnu"; then
        print_success "Windows target available for cross-compilation"
    else
        print_warning "Windows cross-compilation target not available"
    fi
    
    if rustup target list | grep -q "x86_64-unknown-linux-gnu"; then
        print_success "Linux target available"
    else
        print_warning "Linux target not available"
    fi
    
    return 0
}

test_dependencies() {
    print_status "Testing project dependencies..."
    
    # Check server dependencies
    cd c2_server
    if cargo tree --quiet >/dev/null 2>&1; then
        print_success "Server dependencies resolved"
    else
        print_error "Server dependency issues found"
        cd ..
        return 1
    fi
    cd ..
    
    # Check client dependencies
    cd c2_client
    if cargo tree --quiet >/dev/null 2>&1; then
        print_success "Client dependencies resolved"
    else
        print_error "Client dependency issues found"
        cd ..
        return 1
    fi
    cd ..
    
    return 0
}

run_security_checks() {
    print_status "Running basic security checks..."
    
    # Check for common security issues in Cargo.toml files
    if grep -r "version.*\*" c2_*/Cargo.toml; then
        print_warning "Wildcard versions found in dependencies (potential security risk)"
    else
        print_success "No wildcard versions in dependencies"
    fi
    
    # Check for debug assertions in release builds
    if grep -r "debug_assertions" c2_*/src/; then
        print_success "Debug assertions conditionally compiled"
    fi
    
    # Check for proper error handling
    if grep -r "unwrap()" c2_*/src/ | grep -v "test" | grep -v "expect"; then
        print_warning "Found unwrap() calls that might cause panics"
    else
        print_success "No unsafe unwrap() calls found"
    fi
    
    return 0
}

run_performance_tests() {
    print_status "Running performance tests..."
    
    # Test compilation time
    print_status "Testing compilation performance..."
    cd c2_server
    local start_time=$(date +%s)
    cargo build --release --quiet
    local end_time=$(date +%s)
    local compile_time=$((end_time - start_time))
    
    if [ $compile_time -lt 60 ]; then
        print_success "Server compilation time: ${compile_time}s (Good)"
    elif [ $compile_time -lt 120 ]; then
        print_warning "Server compilation time: ${compile_time}s (Acceptable)"
    else
        print_warning "Server compilation time: ${compile_time}s (Slow)"
    fi
    cd ..
    
    return 0
}

cleanup_test_artifacts() {
    print_status "Cleaning up test artifacts..."
    
    # Remove any test files
    rm -f crypto_test.rs network_test.rs Cargo.toml Cargo.lock
    rm -rf target
    
    print_success "Cleanup completed"
}

main() {
    print_header
    
    local tests_passed=0
    local tests_failed=0
    
    # Run all tests
    if test_rust_installation; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    
    if test_dependencies; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    
    if test_compilation; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    
    if test_crypto_functions; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    
    if test_network_functionality; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    
    if test_cross_compilation; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    
    if run_security_checks; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    
    if run_performance_tests; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi
    
    cleanup_test_artifacts
    
    # Print summary
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                              Test Summary                                    ║${NC}"
    echo -e "${PURPLE}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${PURPLE}║${NC} Tests Passed: ${GREEN}${tests_passed}${NC}                                                           ${PURPLE}║${NC}"
    echo -e "${PURPLE}║${NC} Tests Failed: ${RED}${tests_failed}${NC}                                                           ${PURPLE}║${NC}"
    
    if [ $tests_failed -eq 0 ]; then
        echo -e "${PURPLE}║${NC} Status: ${GREEN}ALL TESTS PASSED${NC}                                                  ${PURPLE}║${NC}"
        echo -e "${PURPLE}║${NC} ${GREEN}✓ C2 Framework is ready for deployment${NC}                                   ${PURPLE}║${NC}"
    else
        echo -e "${PURPLE}║${NC} Status: ${RED}SOME TESTS FAILED${NC}                                                 ${PURPLE}║${NC}"
        echo -e "${PURPLE}║${NC} ${RED}✗ Please fix issues before deployment${NC}                                    ${PURPLE}║${NC}"
    fi
    
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    if [ $tests_failed -eq 0 ]; then
        echo ""
        echo -e "${GREEN}🚀 Ready to build with: ./build.sh${NC}"
        echo -e "${GREEN}📖 Read README.md for usage instructions${NC}"
        echo -e "${YELLOW}⚠️  Remember: Use only for authorized testing!${NC}"
    fi
    
    return $tests_failed
}

# Run main function
main "$@"
