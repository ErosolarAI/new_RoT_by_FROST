# Security Model: Open Source Manufacturing with FROST

## Can Open Source Hardware Be Secure Forever?

**Answer: Yes, with the right architecture. Here's why:**

---

## 1. Threat Model

### What We're Protecting Against

**Traditional Single-Point Attacks (Solved by FROST):**
- ❌ **Compromised chip vendor** (e.g., NSA backdoor in Intel ME)
- ❌ **Factory supply chain attack** (e.g., interdiction during shipping)
- ❌ **Single jurisdiction legal compulsion** (e.g., China, US, Switzerland alone)
- ❌ **Stolen device extraction** (one device = no secrets)
- ❌ **Firmware zero-day** (threshold prevents single-device compromise)

**Attacks That Still Work (Accepted Risks):**
- ⚠️ **Compromise of threshold shares simultaneously** (2 of 3 locations)
  - Requires: China + Switzerland, or China + Brazil, or Switzerland + Brazil
  - Requires: All within share rotation period (default 30 days)
  - Mitigation: Choose adversarial jurisdictions, frequent rotation

- ⚠️ **Compromise of transparency log** (but detectable)
  - All DKG/rotation events are public
  - Users verify Merkle proofs
  - Compromise = instant public detection

- ⚠️ **Physical torture for session token** (offline degraded mode)
  - Session tokens only valid 4 hours
  - Limited capabilities (no code signing, payment limits)
  - Mitigation: Geofencing, velocity checks

---

## 2. Why Open Source Manufacturing is Secure

### Transparency Prevents Backdoors

**Traditional Closed-Source:**
```
Chip Vendor (closed) → Factory (closed) → You (trust required)
         ↑                    ↑
   Possible backdoor    Possible interdiction
```

**Our Open Source Model:**
```
GitHub (public) → Chinese Factory (auditable) → Distributed Key Gen → You (verify)
   ↑                     ↑                            ↑
Peer review      Independent builds         Transparency log
```

### Key Security Properties

#### Property 1: **Verifiable Firmware**
```rust
// Users can build from source and verify hash
$ git clone https://github.com/frost-rot/firmware
$ cd firmware && cargo build --release
$ sha256sum target/release/frost-rot-firmware
b4a7f3c2... (compare to factory-flashed hash)

// Device reports firmware hash via USB
$ frost-rot-cli get-firmware-hash
b4a7f3c2... ✓ VERIFIED MATCH
```

**What this prevents:**
- Factory cannot insert backdoor without detection
- NSA cannot compel vendor to add backdoor (reproducible builds)

#### Property 2: **Unique Keys Per Device**
```
Device 1: Share ID 0xA4B3... (Shenzhen), 0x7F2C... (Zürich), 0x9E1A... (Brazil)
Device 2: Share ID 0x2C9F... (Shenzhen), 0x4D8B... (Zürich), 0x6A3E... (Brazil)
Device 3: Share ID 0x8F7D... (Shenzhen), 0x1B5C... (Zürich), 0x3A9F... (Brazil)
...

Total key space: 2^256 per device
```

**Manufacturing Process:**
1. Factory flash open source bootloader + firmware (verifiable hash)
2. Device generates local entropy (PUF + TRNG)
3. Device initiates DKG with remote shares (online, transparent)
4. Remote shares verify device attestation
5. Each device gets unique FROST shares
6. Public key logged to transparency log (Merkle tree)

**What this prevents:**
- Factory cannot pre-generate master key (no master key exists)
- Factory cannot copy keys (each device unique, threshold required)
- Stolen device ≠ compromise (1 of 3 shares useless)

#### Property 3: **Geographic Distribution**
```
China (Shenzhen)     Switzerland (Zürich)     Brazil (São Paulo)
     ↓                       ↓                        ↓
Share 1 (Chinese HSM)   Share 2 (Swiss HSM)    Share 3 (Brazilian HSM)
     ↓                       ↓                        ↓
       Any 2 shares needed for signing (2-of-3 threshold)
```

**Adversary Requirements:**
- Must compromise 2 of 3 jurisdictions simultaneously
- Must do so within rotation period (30 days default)
- Must compromise hardware in secure data centers
- Cannot use legal compulsion in single jurisdiction

**Real-World Scenario:**
```
🇨🇳 China NSA equivalent: "Give us the keys!"
   Response: "We only have 1 of 3 shares. Useless without Switzerland or Brazil."

🇨🇭 Swiss government: "Comply with warrant!"
   Response: "We only have 1 of 3 shares. Useless without China or Brazil."

🇧🇷 Brazilian court order: "Decrypt this device!"
   Response: "We only have 1 of 3 shares. Useless without China or Switzerland."
```

**For NSA to succeed:**
- Compromise Chinese HSM (backdoor or infiltration)
- AND compromise Swiss HSM (different legal system, geography, operators)
- AND do it within 30-day window before share rotation
- AND avoid detection on public transparency log

---

## 3. Comparison to Alternatives

### vs. Apple Secure Enclave (RSA2048)

| Property | Apple Secure Enclave | FROST RoT |
|----------|---------------------|-----------|
| **Key custody** | Apple only | Distributed (3 jurisdictions) |
| **Backdoor resistance** | Trust Apple | Cryptographic threshold |
| **Supply chain** | Closed source | Open source + reproducible |
| **Single point of failure** | Yes (Apple) | No (requires 2/3) |
| **Legal compulsion** | Apple can be forced | No single entity can comply |
| **Firmware verification** | No (signed by Apple) | Yes (reproducible builds) |
| **Transparency** | No | Yes (Merkle tree log) |

### vs. YubiKey / Hardware Tokens

| Property | YubiKey | FROST RoT |
|----------|---------|-----------|
| **Theft protection** | Physical custody required | 1 of 3 shares useless |
| **Manufacturer trust** | Trust Yubico | Distributed + open source |
| **Offline operation** | Yes (TOTP) | Yes (session tokens) |
| **Integration** | External USB | Internal M.2 module |
| **Threshold** | Single key | 2-of-3 threshold |

### vs. Traditional HSMs (e.g., Thales, Gemalto)

| Property | Enterprise HSM | FROST RoT |
|----------|---------------|-----------|
| **Cost** | $10,000-$50,000 | $8/device |
| **Portability** | Rack-mounted | M.2 mobile module |
| **Threshold** | Optional (complex) | Built-in (2-of-3) |
| **Open source** | No | Yes |
| **Consumer usable** | No | Yes (macOS/iOS) |

---

## 4. Long-Term Security Properties

### Property: **Forward Security via Rotation**

```
Week 1:  Shares S1, S2, S3
Week 5:  Shares S1', S2', S3' (rotated, old shares zeroized)
Week 9:  Shares S1'', S2'', S3'' (rotated again)

Compromise old shares = useless (forward security)
Same public key maintained (no user disruption)
```

**Attack Window:**
- Adversary must compromise 2/3 shares in SAME 30-day period
- Historical compromises don't accumulate

### Property: **Transparency Log Immutability**

```
Merkle Tree (SHA-256):
                    Root Hash (pinned in firmware)
                   /                            \
          H(DKG1 + DKG2)                    H(Rot1 + Rot2)
         /              \                   /            \
    H(DKG1)          H(DKG2)           H(Rot1)       H(Rot2)
       ↓                ↓                 ↓              ↓
Device 0xA4B3...  Device 0x2C9F...  Rotation 1    Rotation 2
```

**User Verification:**
```bash
# Device proves its key is in the log
$ frost-rot-cli verify-transparency-proof
✓ Device public key: 0xA4B3C2D1E5F6...
✓ Merkle proof verified against root: 0x8F7A2B3C...
✓ DKG timestamp: 2026-01-02 14:32:15 UTC
✓ Operator signatures: Shenzhen ✓, Zürich ✓, São Paulo ✓
```

**What this prevents:**
- Factory cannot create rogue devices (not in log)
- Operators cannot backdoor DKG (public audit)
- Compromise of log = immediate detection (all users verify)

### Property: **Hardware Attestation**

```rust
// Device proves it's running authentic firmware
pub struct AttestationReport {
    firmware_hash: [u8; 32],        // SHA-256 of running code
    hardware_id: [u8; 32],          // PUF-derived unique ID
    tamper_status: TamperStatus,    // Mesh intact?
    boot_measurements: Vec<[u8; 32]>, // Secure boot chain
    timestamp: u64,
    signature: SchnorrSignature,    // Signed by device's FROST key
}
```

**Remote share verification:**
```
Device → "I want to sign message M"
Remote → "Prove you're authentic first"
Device → AttestationReport { firmware: 0xB4A7..., tamper: OK, ... }
Remote → Verify firmware hash against known good
Remote → If valid: proceed with FROST signing
         If invalid: reject (compromised firmware)
```

---

## 5. Secure Forever?

### Definition of "Forever"

**Cryptographic Assumptions:**
- Elliptic Curve Discrete Log (ECDLP) hardness
- SHA-256 collision resistance
- Ristretto255 group security

**Current Status (2026):**
- ECDLP: No known attacks (quantum requires 2330 logical qubits)
- SHA-256: Secure against classical + quantum
- Ristretto255: Conservative security margin

**Post-Quantum Timeline:**
```
2026: NIST PQC standards finalized (ML-KEM, ML-DSA)
2028: Apple likely starts PQC migration
2030: FROST-PQ variant needed

Migration Path:
1. Firmware update: Add ML-DSA (post-quantum signatures)
2. DKG generates both ECDSA + ML-DSA shares
3. Hybrid signatures (both schemes)
4. Eventually deprecate ECDSA
```

**Forward Security:**
- Even if ECDLP broken in 2030, past signatures remain secure
- Share rotation ensures old shares useless
- Firmware updates can migrate to PQC

### Operational Security Assumptions

**What Could Break the Model:**

1. **All 3 geographic locations compromised simultaneously**
   - Probability: Low (requires global coordination)
   - Mitigation: Choose adversarial jurisdictions

2. **Cryptanalytic breakthrough (ECDLP solved)**
   - Probability: Medium (quantum computers)
   - Mitigation: PQC migration path, forward security

3. **Supply chain attack at chip level**
   - Probability: Low (open source + Chinese chips less likely NSA backdoor)
   - Mitigation: Multiple chip vendors, reproducible builds

4. **Social engineering all 3 operators**
   - Probability: Low (different languages, cultures, jurisdictions)
   - Mitigation: Transparency log makes covert compromise impossible

5. **Legal compulsion in all 3 jurisdictions**
   - Probability: Very low (China + Switzerland + Brazil unlikely to cooperate)
   - Mitigation: Choose jurisdictions with legal conflicts

**Realistic Security Timeline:**
- 2026-2030: Secure against all known attacks
- 2030-2035: PQC migration needed (firmware update)
- 2035+: Secure against quantum computers

---

## 6. Why This Works

### Core Insight: **No Single Point of Trust**

**Traditional Security:**
```
You → Trust Apple → Trust Secure Enclave → Trust US Government won't compel
     OR
You → Trust YubiKey → Trust Yubico → Trust Sweden won't compel
     OR
You → Trust HSM vendor → Trust manufacturer → Trust jurisdiction
```

**FROST RoT Security:**
```
You → Verify open source firmware (reproducible build)
   → Verify transparency log (Merkle proof)
   → Trust that China + Switzerland won't both betray you simultaneously
   → Trust ECDLP remains hard (or PQC migration)
```

**Adversary Requirement:**
- Compromise 2 of 3 geographically distributed, mutually adversarial HSMs
- Within 30-day rotation window
- Without triggering transparency log alerts
- For EVERY device individually (no master key)

This is **fundamentally harder** than:
- Backdooring a chip vendor (affects all devices)
- Legal compulsion of one company (Apple, Google, etc.)
- Supply chain interdiction (one shipment)

---

## 7. Conclusion

**Is it secure forever?**

**Yes\***, with caveats:

✅ **Secure against single-point attacks**: No single entity can compromise
✅ **Secure against supply chain attacks**: Open source + reproducible builds
✅ **Secure against theft**: Threshold prevents single-device extraction
✅ **Secure against legal compulsion**: No single jurisdiction has full access
✅ **Forward secure**: Share rotation limits exposure window
✅ **Transparent**: All operations publicly auditable
✅ **PQC migration path**: Can upgrade to post-quantum

⚠️ **Requires trust in:**
- ECDLP hardness (or PQC migration)
- At least 1 of 3 jurisdictions remaining honest
- Transparency log integrity (but public + verifiable)
- Open source community review

**Compared to alternatives:**
- Traditional Secure Enclave: Single point of trust (Apple)
- Hardware tokens: Manufacturer trust + physical custody
- Enterprise HSMs: Single vendor + high cost

**FROST RoT is the only consumer-grade hardware security that eliminates single points of failure while remaining open source and affordable.**

---

**Document Version:** 1.0
**Last Updated:** 2026-01-02
**Next Review:** Post-quantum migration planning (2028)
