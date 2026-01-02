# FROST Root of Trust - Production-Ready Hardware Security Module

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Manufacturing](https://img.shields.io/badge/manufacturing-ready-green.svg)](docs/manufacturing/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20iOS-lightgrey.svg)](docs/integration/)

## Overview

**FROST RoT** is a production-ready, manufacturable Root of Trust (RoT) using FROST (Flexible Round-Optimized Schnorr Threshold) signatures. Designed to replace traditional hardware security modules like Apple's Secure Enclave with a geographically distributed, transparent, and trustworthy alternative.

### Key Features

- ✅ **Threshold Cryptography**: 2-of-3 distributed signing eliminates single point of failure
- ✅ **Ready for Manufacturing**: Complete BOM, PCB specs, and assembly guide for Chinese factories  
- ✅ **Hardware Support**: GigaDevice GD32, Nations Technologies, Feitian HSM
- ✅ **Apple Integration**: macOS/iOS kernel extensions and frameworks
- ✅ **Geographic Distribution**: Shares in Shenzhen, Zürich, and São Paulo
- ✅ **Transparent & Auditable**: All operations logged to public transparency log
- ✅ **No Single Point of Compromise**: Attacker must compromise multiple jurisdictions

---

## Quick Start

```bash
# Clone and build
git clone https://github.com/your-org/frost-rot.git && cd frost-rot
cargo build --release

# Run DKG simulation
cargo run --example dkg_simulation -- --threshold 2 --participants 3

# Build for embedded hardware
cargo build --release --no-default-features --features no_std
```

---

## Manufacturing Ready

This project includes **complete manufacturing documentation** for Chinese factories:

- ✅ [Bill of Materials](docs/manufacturing/BOM.md) with Shenzhen suppliers
- ✅ [PCB Specifications](docs/manufacturing/PCB_SPECIFICATIONS.md) - 4-layer with tamper mesh  
- ✅ [Assembly Guide](docs/manufacturing/ASSEMBLY_GUIDE.md) - Step-by-step SMT instructions
- ✅ **Target Cost**: $7.85/unit @ 10K quantity

**Form Factors:**
- M.2 2242 module (for MacBooks)
- USB-C security key (iPhone/iPad)
- Bare chip (OEM integration)

**Recommended Manufacturers:**
- Shenzhen Wonderful (MOQ: 1K)
- Seeed Studio (MOQ: 5 - prototyping)
- JLCPCB (integrated PCB + assembly)

---

## macOS/iOS Integration

Full integration guide for Apple platforms: [docs/integration/MACOS_INTEGRATION.md](docs/integration/MACOS_INTEGRATION.md)

**Supported:**
- FileVault encryption with threshold keys
- Touch ID / Face ID authentication
- Keychain protection
- Code signing

**Example:**
```swift
import FROSTSecurity

let key = FROSTSecurityKey.enrolledKey()
let signature = try await key.sign(data: myDocument)
```

---

## Project Structure

```
frost-rot/
├── crates/
│   ├── frost-core/          # DKG, signing, rotation
│   ├── hardware-hal/        # GigaDevice, Nations Tech, Feitian
│   └── ...
├── docs/
│   ├── manufacturing/       # BOM, PCB, assembly
│   └── integration/         # macOS/iOS guides
└── README.md
```

See original design notes: [README_ORIGINAL.md](README_ORIGINAL.md)

---

**License:** MIT OR Apache-2.0  
**Status:** Active Development (v0.1.0)  
**Contact:** frost-rot-project@example.com
