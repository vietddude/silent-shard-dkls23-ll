# Testing Guide for DKLS23-LL Rust Library

This guide explains how to test the Rust core library (`dkls23-ll`).

## Prerequisites

Make sure Rust is installed:
```bash
# Check if Rust is installed
rustc --version
cargo --version

# If not installed, install from https://rustup.rs/
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Running Tests

### Run All Tests

```bash
cd /home/carmy/Documents/other/silent-shard-dkls23-ll
cargo test
```

### Run Tests with Output

```bash
cargo test -- --nocapture
```

### Run Specific Test Modules

#### Distributed Key Generation (DKG) Tests

```bash
# 2-of-2 key generation
cargo test dkg::tests::dkg2_out_of_2

# 2-of-3 key generation  
cargo test dkg::tests::dkg2_out_of_3

# 3-of-3 key generation
cargo test dkg::tests::dkg_3_out_of_3

# Key rotation
cargo test dkg::tests::key_rotation

# Recover lost share
cargo test dkg::tests::recover_lost_share
```

#### Distributed Signature Generation (DSG) Tests

```bash
# 2-of-2 signing
cargo test dsg::tests::sign_2_out_of_2

# 2-of-3 signing
cargo test dsg::tests::sign_2_out_3

# 3-of-3 signing
cargo test dsg::tests::sign_3_out_3

# 2-of-4 signing
cargo test dsg::tests::sign_2_out_4

# 3-of-4 signing
cargo test dsg::tests::sign_3_out_4

# Sign and rotate keyshares
cargo test dsg::tests::sign_2_out_of_3_and_rotate_keyshares

# Recover lost share and sign
cargo test dsg::tests::recover_lost_share_and_sign
```

#### OT Variant Signing Tests

```bash
# 2-of-2 OT variant signing
cargo test dsg_ot_variant::tests::sign_2_out_of_2

# 2-of-3 OT variant signing
cargo test dsg_ot_variant::tests::sign_2_out_3

# 3-of-3 OT variant signing
cargo test dsg_ot_variant::tests::sign_3_out_3

# 2-of-4 OT variant signing
cargo test dsg_ot_variant::tests::sign_2_out_4

# 3-of-4 OT variant signing
cargo test dsg_ot_variant::tests::sign_3_out_4

# Sign and rotate keyshares (OT variant)
cargo test dsg_ot_variant::tests::sign_2_out_of_3_and_rotate_keyshares

# Recover lost share and sign (OT variant)
cargo test dsg_ot_variant::tests::recover_lost_share_and_sign
```

### Run Tests by Pattern

```bash
# Run all DKG tests
cargo test dkg

# Run all signing tests
cargo test sign

# Run all OT variant tests
cargo test ot_variant
```

### Run Tests in Release Mode

```bash
cargo test --release
```

### Run Tests with Verbose Output

```bash
cargo test -- --nocapture --test-threads=1
```

## Test Structure

The tests are organized in modules:

- **`src/dkg.rs`** - Distributed Key Generation tests
- **`src/dsg.rs`** - Distributed Signature Generation tests  
- **`src/dsg_ot_variant.rs`** - OT Variant signing tests

Each test module includes:
- Basic protocol execution tests
- Serialization/deserialization checks (bincode, JSON, CBOR)
- Key rotation tests
- Lost share recovery tests

## Example: Running a Complete Test Suite

```bash
# Navigate to project root
cd /home/carmy/Documents/other/silent-shard-dkls23-ll

# Run all tests
cargo test

# Run with detailed output
cargo test -- --nocapture

# Run specific test
cargo test dkg::tests::dkg2_out_of_2 -- --nocapture
```

## Troubleshooting

If tests fail:

1. **Check Rust version**: Minimum required is 1.70.0
   ```bash
   rustc --version
   ```

2. **Clean and rebuild**:
   ```bash
   cargo clean
   cargo test
   ```

3. **Run with more verbose output**:
   ```bash
   cargo test -- --nocapture --test-threads=1
   ```

4. **Check for specific test failures**:
   ```bash
   cargo test --lib 2>&1 | grep -A 10 "FAILED"
   ```

