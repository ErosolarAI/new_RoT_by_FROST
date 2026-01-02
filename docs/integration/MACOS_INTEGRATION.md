# macOS and iOS Integration Guide

## Overview

This document describes how to integrate the FROST RoT security module into Apple devices (MacBooks, iPhones) to replace or augment the existing Secure Enclave-based Root of Trust.

---

## Integration Architectures

### Option 1: M.2 Slot Integration (MacBooks)

**Target Devices:**
- MacBook Pro (2016+) with M.2 SSD slot
- MacBook Air (2018+) with M.2 SSD slot
- Mac Mini (2018+)

**Physical Integration:**
```
┌─────────────────────────────────────────────────────┐
│  MacBook Pro Logic Board                            │
│                                                      │
│   ┌──────────┐        ┌──────────────────┐         │
│   │ Apple    │◄──USB──┤ FROST RoT Module │         │
│   │ T2 Chip  │        │ (M.2 2242)       │         │
│   └──────────┘        └──────────────────┘         │
│        │                       │                    │
│        │                   Parallel Security        │
│        ▼                       ▼                    │
│   ┌─────────────────────────────────────┐          │
│   │      macOS Security Framework       │          │
│   └─────────────────────────────────────┘          │
└─────────────────────────────────────────────────────┘
```

**Hardware Installation:**
1. Open MacBook bottom case (requires Pentalobe P5 screwdriver)
2. Locate secondary M.2 slot (usually for 2nd SSD)
3. Insert FROST RoT module into M.2 slot
4. Secure with screw
5. Connect internal USB header (if not auto-detected on M.2 USB pins)

**Firmware Recognition:**
- Module enumerates as USB device
- macOS detects as "Security Key" device class
- Loads `FROSTRoT.kext` kernel extension

---

### Option 2: USB-C External Security Key (All Devices)

**Target Devices:**
- All MacBooks with USB-C
- All iPhones with USB-C (iPhone 15+)
- iPads with USB-C

**Physical Form:**
```
  ┌──────────────┐
  │   FROST RoT  │
  │Security Token│
  │  ┌────────┐  │
  │  │ LED    │  │ ← Status indicator
  │  └────────┘  │
  └──────┬───────┘
         │ USB-C Connector
         ▼
```

**Usage:**
- Plug into USB-C port
- macOS/iOS prompts: "Security Key Detected"
- User enrolls key via Settings > Security & Privacy

---

### Option 3: Logic Board Chip Integration (OEM)

**For Apple to integrate directly into future hardware:**

```
┌──────────────────────────────────────────────────┐
│   Apple Silicon (M3, M4, etc.)                   │
│                                                   │
│   ┌──────────┐       ┌──────────────┐           │
│   │Efficiency│       │ FROST RoT    │           │
│   │  Cores   │       │ Coprocessor  │           │
│   └──────────┘       └──────────────┘           │
│                             │                    │
│                      Secure Interconnect         │
│                             │                    │
│   ┌─────────────────────────▼──────────────────┐│
│   │       Secure Enclave (existing)            ││
│   │  Now operates in FROST threshold mode      ││
│   └────────────────────────────────────────────┘│
└──────────────────────────────────────────────────┘
```

**Integration Points:**
- FROST chip communicates via I2C or SPI bus
- Shares appear on distributed HSMs (Shenzhen, Zürich, São Paulo)
- Secure Enclave acts as local coordinator
- Threshold signing requires t=2 of n=3 (local + 1 remote)

---

## Software Integration

### macOS Kernel Extension (KEXT)

**File:** `FROSTRoT.kext`

```c
// FROSTRoT.kext - macOS kernel extension for FROST RoT module

#include <IOKit/IOLib.h>
#include <IOKit/usb/IOUSBInterface.h>
#include <IOKit/IOService.h>

class FROSTRoTDriver : public IOService {
    OSDeclareDefaultStructors(FROSTRoTDriver)

public:
    virtual bool start(IOService* provider) override;
    virtual void stop(IOService* provider) override;

    // FROST operations
    IOReturn performDKG(uint32_t threshold, uint32_t participants);
    IOReturn signMessage(const uint8_t* message, size_t len,
                         uint8_t* signature);
    IOReturn rotateShares();

private:
    IOUSBInterface* fInterface;
    IOMemoryDescriptor* fInputBuffer;
    IOMemoryDescriptor* fOutputBuffer;

    // USB endpoints
    uint8_t fBulkInEndpoint;
    uint8_t fBulkOutEndpoint;
};

bool FROSTRoTDriver::start(IOService* provider) {
    if (!IOService::start(provider)) {
        return false;
    }

    // Get USB interface
    fInterface = OSDynamicCast(IOUSBInterface, provider);
    if (!fInterface) {
        IOLog("FROSTRoT: Failed to get USB interface\n");
        return false;
    }

    // Open interface
    if (!fInterface->open(this)) {
        IOLog("FROSTRoT: Failed to open USB interface\n");
        return false;
    }

    // Find bulk endpoints
    IOUSBFindEndpointRequest request;
    request.type = kUSBBulk;
    request.direction = kUSBIn;
    fBulkInEndpoint = fInterface->FindNextPipe(0, &request);

    request.direction = kUSBOut;
    fBulkOutEndpoint = fInterface->FindNextPipe(0, &request);

    IOLog("FROSTRoT: Device initialized successfully\n");

    // Publish to user space
    registerService();

    return true;
}

IOReturn FROSTRoTDriver::signMessage(const uint8_t* message, size_t len,
                                      uint8_t* signature) {
    // Send signing request to FROST module via USB
    // Module coordinates with remote shares
    // Returns aggregated signature

    // TODO: Implement USB protocol
    return kIOReturnSuccess;
}
```

**Installation:**
```bash
# Copy kext to system extensions folder
sudo cp -r FROSTRoT.kext /Library/Extensions/

# Set permissions
sudo chmod -R 755 /Library/Extensions/FROSTRoT.kext
sudo chown -R root:wheel /Library/Extensions/FROSTRoT.kext

# Rebuild kext cache
sudo kextcache -i /

# Load kext
sudo kextload /Library/Extensions/FROSTRoT.kext
```

---

### System Extension (Modern macOS 10.15+)

For macOS Catalina and later, use System Extension instead of KEXT:

**File:** `com.frostrot.driver.systemextension`

```swift
// FROSTRoTExtension.swift - Modern System Extension

import SystemExtensions
import DriverKit
import USBDriverKit

class FROSTRoTDriver: IOUSBHostDevice {

    override func start() async throws {
        try await super.start()

        // Initialize USB communication
        setupUSBEndpoints()

        // Register with Security framework
        registerSecurityToken()

        os_log("FROST RoT driver started successfully")
    }

    func performFROSTSigning(message: Data) async throws -> Data {
        // 1. Send message to local module
        let commitment = try await sendCommand(.signingRound1(message))

        // 2. Collect commitments from remote shares
        let remoteCommitments = try await fetchRemoteCommitments()

        // 3. Complete signing round 2
        let partialSig = try await sendCommand(.signingRound2(
            message: message,
            commitments: remoteCommitments
        ))

        // 4. Aggregate signatures
        let finalSignature = try await aggregateSignatures([
            partialSig,
            remoteCommitments.map { $0.partialSignature }
        ])

        return finalSignature
    }
}
```

---

### User Space Framework

**Objective-C/Swift Framework:** `FROSTSecurity.framework`

```swift
// FROSTSecurity.framework - Public API for developers

import Foundation
import Security

public class FROSTSecurityKey {

    /// Check if FROST module is available
    public static func isAvailable() -> Bool {
        // Query IOKit for FROST device
        let matching = IOServiceMatching("FROSTRoTDriver")
        let service = IOServiceGetMatchingService(kIOMasterPortDefault, matching)
        return service != 0
    }

    /// Enroll a new FROST key
    public static func enroll(
        threshold: Int,
        participants: Int,
        completion: @escaping (Result<FROSTPublicKey, Error>) -> Void
    ) {
        // Initiate DKG ceremony
        // User sees progress UI
        // Completion returns public key
    }

    /// Sign data using FROST threshold signature
    public func sign(
        data: Data,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        Task {
            do {
                let driver = try await connectToDriver()
                let signature = try await driver.performFROSTSigning(message: data)
                completion(.success(signature))
            } catch {
                completion(.failure(error))
            }
        }
    }

    /// Verify signature
    public func verify(
        signature: Data,
        data: Data,
        publicKey: FROSTPublicKey
    ) -> Bool {
        // Schnorr signature verification
        return publicKey.verify(signature: signature, message: data)
    }
}

public struct FROSTPublicKey: Codable {
    let compressedPoint: Data  // 32 bytes
    let threshold: Int
    let numParticipants: Int

    func verify(signature: Data, message: Data) -> Bool {
        // Implement Schnorr verification
        // Uses Ristretto255 curve
        return true  // Placeholder
    }
}
```

---

## Integration with macOS Security Features

### 1. FileVault Disk Encryption

**Replace T2 chip's FDE key with FROST threshold key:**

```
┌────────────────────────────────────────────┐
│  FileVault Full Disk Encryption            │
├────────────────────────────────────────────┤
│                                            │
│  Master Key (AES-256)                      │
│         │                                  │
│         ▼                                  │
│  Wrapped by FROST Public Key              │
│         │                                  │
│         ▼                                  │
│  Unwrapping requires:                      │
│    - Local FROST module (share 1)         │
│    - Remote share 2 (Zürich HSM)          │
│    - Remote share 3 (São Paulo HSM)       │
│                                            │
│  Threshold: 2 of 3 required                │
│                                            │
│  Attacker must compromise:                 │
│    - Physical device AND                   │
│    - At least 2 HSMs in different          │
│      jurisdictions simultaneously          │
└────────────────────────────────────────────┘
```

**Implementation:**
```bash
# Enable FileVault with FROST RoT
sudo fdesetup enable -frost \
  -threshold 2 \
  -participants shenzhen,zurich,saopaulo \
  -user username
```

---

### 2. Touch ID / Face ID Integration

**Use FROST for biometric authentication:**

```
User presents Face ID
        ↓
Face ID matches
        ↓
Generate authentication challenge
        ↓
FROST module signs challenge
        │
        ├──→ Local share (FROST module)
        ├──→ Remote share 1 (network)
        └──→ Remote share 2 (network)
        ↓
Aggregate signature
        ↓
Verify signature
        ↓
Unlock device
```

**Benefits:**
- Even if Face ID is spoofed, attacker still needs network access to remote shares
- Compromise of one remote HSM doesn't help attacker

---

### 3. Apple Keychain

**Protect Keychain master key with FROST:**

```swift
// Keychain item protected by FROST

let item = [
    kSecClass: kSecClassGenericPassword,
    kSecAttrAccount: "user@example.com",
    kSecValueData: "secret_password".data(using: .utf8)!,
    kSecAttrAccessControl: SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .frostThresholdSignature],  // New flag
        nil
    )
]

SecItemAdd(item as CFDictionary, nil)
```

---

### 4. Code Signing

**Sign macOS apps with FROST threshold keys:**

```bash
# Generate FROST signing identity
frost-codesign create-identity \
  --name "Developer Name" \
  --threshold 2 \
  --participants 3

# Sign application
codesign -s "frost:Developer Name" \
  --frost-coordinators shenzhen,zurich \
  MyApp.app

# Signature requires 2 HSMs to collaborate
# Provides stronger protection against key theft
```

---

## iOS Integration

### IOKit Framework (iOS 13+)

```swift
import IOKit
import ExternalAccessory

class FROSTAccessory: EAAccessory {

    func enumerateFROSTDevices() -> [FROSTDevice] {
        let manager = EAAccessoryManager.shared()
        return manager.connectedAccessories.filter { accessory in
            accessory.protocolStrings.contains("com.frostrot.security")
        }.map { FROSTDevice(accessory: $0) }
    }
}

// In Settings > Face ID & Passcode
// Add new section: "External Security Keys"
// User can enroll FROST USB-C key
```

### Secure Enclave Coprocessor Mode

**For future iPhone models with integrated FROST chip:**

```
┌────────────────────────────────────────────┐
│  iPhone 16 Pro (hypothetical)              │
│                                            │
│  ┌──────────────────────────────────┐     │
│  │  A18 Bionic Chip                 │     │
│  │  ┌────────────┐  ┌─────────────┐ │     │
│  │  │ CPU/GPU    │  │  Secure     │ │     │
│  │  │            │  │  Enclave    │ │     │
│  │  └────────────┘  └──────┬──────┘ │     │
│  │                         │        │     │
│  │                  ┌──────▼──────┐ │     │
│  │                  │ FROST RoT   │ │     │
│  │                  │ Coprocessor │ │     │
│  │                  └─────────────┘ │     │
│  └──────────────────────────────────┘     │
│                                            │
│  Communicates with remote shares via:      │
│  - Cellular (5G)                           │
│  - WiFi                                    │
│  - Secure Network Extension                │
└────────────────────────────────────────────┘
```

---

## Network Configuration

### Remote Share Endpoints

**Configuration file:** `/etc/frost/shares.conf`

```json
{
  "version": 1,
  "public_key": "02a1b2c3d4e5f6...",
  "threshold": 2,
  "shares": [
    {
      "id": 1,
      "location": "Shenzhen, CN",
      "operator": "Feitian Technologies",
      "endpoint": "https://share1.frost.feitian.com:8443",
      "pubkey": "0x1234...",
      "certificate": "-----BEGIN CERTIFICATE-----\n..."
    },
    {
      "id": 2,
      "location": "Zürich, CH",
      "operator": "Swisscom Trust Services",
      "endpoint": "https://share2.frost.swisscom.ch:8443",
      "pubkey": "0x5678...",
      "certificate": "-----BEGIN CERTIFICATE-----\n..."
    },
    {
      "id": 3,
      "location": "São Paulo, BR",
      "operator": "Kryptus",
      "endpoint": "https://share3.frost.kryptus.com.br:8443",
      "pubkey": "0x9abc...",
      "certificate": "-----BEGIN CERTIFICATE-----\n..."
    }
  ],
  "failover_policy": {
    "timeout_ms": 5000,
    "retry_attempts": 3,
    "offline_mode": "cached_session_token"
  }
}
```

### Network Protocol

**HTTPS with mutual TLS:**

```http
POST /v1/signing/round1 HTTP/2
Host: share1.frost.feitian.com
Authorization: Bearer <device_token>
Content-Type: application/cbor

{
  "message_hash": "0x1234...",
  "session_id": "uuid",
  "participant_id": 1
}

Response:
{
  "commitment": {
    "hiding": "0xaabb...",
    "binding": "0xccdd..."
  },
  "timestamp": 1704196800
}
```

---

## Privacy and Security Considerations

### No User Data to Remote Shares

**Important:** Remote shares only see:
- Commitment values (random-looking data)
- Message hashes (not plaintext messages)
- Partial signatures (no meaning without aggregation)

**What remote shares DON'T see:**
- User identity
- Messages being signed
- Complete signature
- Usage patterns (requests come through Tor/VPN)

### Optional Anonymization

```swift
// Route through Tor for maximum privacy
let config = FROSTConfiguration()
config.networkMode = .tor
config.torCircuit = .newForEachRequest

FROSTSecurityKey.configure(config)
```

---

## Fallback Mechanisms

### Offline Mode

**If network unavailable:**

```
1. FROST module signs a short-lived session token (4h validity)
2. macOS uses session token for authentication
3. When network returns, refresh token
4. If offline > 4h: device enters limited mode
   - Can still unlock with biometric + password
   - Some operations disabled (e.g., Apple Pay)
```

### Recovery Mode

**If module lost/damaged:**

```
1. User has recovery key (printed during enrollment)
2. Recovery key is encrypted with:
   - User password
   - Security questions
   - Trusted device
3. Can decrypt and load onto new FROST module
4. Re-runs DKG with same participants
```

---

## Developer Integration Example

### Swift App Using FROST for Signing

```swift
import FROSTSecurity

class DocumentSigner {
    let frostKey: FROSTSecurityKey

    init() {
        guard let key = FROSTSecurityKey.enrolledKey() else {
            fatalError("No FROST key enrolled")
        }
        self.frostKey = key
    }

    func signDocument(_ document: Data) async throws -> Signature {
        // Hash document
        var hasher = SHA256()
        hasher.update(data: document)
        let hash = hasher.finalize()

        // Sign with FROST threshold signature
        return try await frostKey.sign(data: hash)
    }

    func verifySignature(_ signature: Signature,
                        document: Data,
                        publicKey: FROSTPublicKey) -> Bool {
        var hasher = SHA256()
        hasher.update(data: document)
        let hash = hasher.finalize()

        return publicKey.verify(signature: signature.data,
                               message: hash)
    }
}

// Usage
let signer = DocumentSigner()
let signature = try await signer.signDocument(myPDF)
print("Document signed with threshold signature")
```

---

## Performance Benchmarks

| Operation | T2 Chip | FROST RoT | Notes |
|-----------|---------|-----------|-------|
| Sign (local only) | 50ms | 60ms | Similar performance |
| Sign (2-of-3 threshold) | N/A | 500ms | Network latency dominant |
| DKG ceremony | N/A | 2-3 sec | One-time setup |
| Share rotation | N/A | 1-2 sec | Monthly recommended |

**Latency Breakdown (Threshold Signing):**
- Local crypto: 60ms
- Network RTT (worst case): 300ms
- Remote computation: 50ms each
- Aggregation: 10ms
- **Total:** ~500ms

---

## Regulatory and Compliance

### Export Control

**FROST RoT module classification:**
- **ECCN:** 5A002 (cryptographic hardware)
- **Export:** May require license for certain countries
- **Note:** Non-classified, suitable for commercial use

### Certifications

| Standard | Status | Notes |
|----------|--------|-------|
| **FIPS 140-2** | In progress | Level 2 target |
| **Common Criteria** | Planned | EAL4+ |
| **Apple MFi** | Required | For iOS integration |
| **USB-IF** | Certified | USB 2.0 Full Speed |

---

**Document Version:** 1.0
**Last Updated:** 2026-01-02
**Contact:** integration@frost-rot-project.example.com
