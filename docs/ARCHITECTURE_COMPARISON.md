# Architecture Comparison: Three FROST Modes

## TL;DR - Which Mode Should You Use?

```
┌─────────────────────────────────────────────────────────────────┐
│                     DECISION TREE                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Do you need to work offline for days/weeks?                    │
│         │                                                        │
│         ├─ YES ──────────────────────────► DERIVED KEY MODE     │
│         │                                   (fully offline)      │
│         │                                                        │
│         └─ NO ─┐                                                 │
│                │                                                 │
│                │  Is 350ms latency acceptable?                   │
│                │      │                                          │
│                │      ├─ YES ───────────► PURE FROST MODE       │
│                │      │                   (highest security)     │
│                │      │                                          │
│                │      └─ NO ──────────► HYBRID + SESSION TOKENS │
│                │                        (50ms, balanced)         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Mode 1: Derived Key (Fully Offline)

### Architecture

```
Manufacturing (One-Time):
    ┌──────────────┐
    │ Device + PUF │
    └───────┬──────┘
            │ Device ID
            │
            ▼
    ╔═══════════════════╗
    ║  FROST DKG        ║  ◄── 2-of-3 Threshold Ceremony
    ║  (3 locations)    ║      (Shenzhen, Zürich, Brazil)
    ╚═════════┬═════════╝
              │
              │ KDF(group_secret, device_id)
              ▼
    ┌──────────────────────┐
    │ Device Master Key    │  ◄── Stored in PUF-encrypted flash
    │ (unique per device)  │
    └──────────────────────┘

Daily Use (Offline):
    User → Device → Sign with master key → Done
    (No network, no remote parties)
```

### Code Example

```rust
use frost_core::derived_key::*;

// Manufacturing (factory)
let provisioner = ManufacturingProvisioner {
    device_id: puf_derived_id,
    remote_endpoints: vec![
        "https://frost-cn.example.com".to_string(),
        "https://frost-ch.example.com".to_string(),
        "https://frost-br.example.com".to_string(),
    ],
};

// One-time DKG ceremony
let device_key = provisioner.provision_device().await?;

// Encrypt to PUF, store in flash
let encrypted_key = device_key.encrypt_to_puf(&puf_key);
write_flash(0x08010000, &encrypted_key);

// Daily use (fully offline)
let message = b"Unlock device";
let signature = device_key.sign(message)?;  // < 10ms, no network
```

### Specifications

| Property | Value |
|----------|-------|
| **Latency** | < 10ms (all local) |
| **Offline Duration** | Indefinite (until re-key needed) |
| **Network Required** | Only during DKG (manufacturing) + re-key |
| **Security (Daily)** | ★★★☆☆ (single device key) |
| **Security (Manufacturing)** | ★★★★★ (2-of-3 threshold) |
| **Complexity** | Low (simple Schnorr signatures) |
| **User Experience** | Identical to Secure Enclave |

### Security Trade-offs

**Strengths:**
- ✓ Fully offline operation (airplane mode, no network)
- ✓ Low latency (< 10ms)
- ✓ Manufacturing security (FROST DKG prevents backdoors)
- ✓ Unique key per device (no master key exists)
- ✓ Open source + verifiable (transparency log)
- ✓ Re-keyable if compromised

**Weaknesses:**
- ✗ Device compromise = full key exposure (can't revoke immediately)
- ✗ No ongoing threshold protection (daily signatures are single-device)
- ✗ Relies on physical security (tamper mesh, PUF encryption)

**Compared to Apple Secure Enclave:**
| Property | Secure Enclave | Derived Key |
|----------|----------------|-------------|
| Manufacturing Trust | Trust Apple | 2-of-3 Threshold |
| Daily Security | Single device key | Single device key |
| Offline | ✓ Yes | ✓ Yes |
| Open Source | ✗ No | ✓ Yes |
| Re-keyable | ✗ No | ✓ Yes |

**Verdict:** Same daily security as Secure Enclave, but **provably no manufacturer backdoor**.

---

## Mode 2: Pure FROST (Highest Security)

### Architecture

```
Every Signature:
    User → Device (share 1)
              │
              ├──────────► Remote Share 2 (Shenzhen)
              │                │
              ├──────────► Remote Share 3 (Zürich)
              │                │
              │            ╔═══════════════╗
              │            ║ FROST Signing ║  2-of-3 Threshold
              │            ║  (Round 1+2)  ║  Required for EVERY signature
              │            ╚═══════════════╝
              │                │
              ◄────────────────┘
              │
    Signature (after 350ms network round-trip)
```

### Code Example

```rust
use frost_core::signing::*;

// Device has local share
let local_share = load_puf_encrypted_share();

// Round 1: Generate commitments
let mut rng = rand::thread_rng();
let round1 = SigningRound1::new(
    local_share.participant_id,
    &local_share,
    &mut rng,
);

let local_commitment = round1.commitment();

// Request remote commitments (network call)
let remote_commitments = request_remote_commitments(message).await?;

let all_commitments = vec![
    local_commitment,
    remote_commitments[0],  // Shenzhen
    remote_commitments[1],  // Zürich
];

// Round 2: Generate partial signatures
let round2 = round1.into_round2(message, &all_commitments)?;
let local_partial = round2.partial_signature();

// Request remote partial signatures
let remote_partials = request_remote_partials(message, &all_commitments).await?;

// Aggregate
let signature = aggregate_signatures(
    message,
    &round2.group_commitment(),
    &[local_partial, remote_partials[0], remote_partials[1]],
)?;
```

### Specifications

| Property | Value |
|----------|-------|
| **Latency** | 350-500ms (network RTT) |
| **Offline Duration** | None (always requires network) |
| **Network Required** | Every signature |
| **Security (Daily)** | ★★★★★ (2-of-3 threshold always) |
| **Security (Manufacturing)** | ★★★★★ (2-of-3 threshold) |
| **Complexity** | High (coordination protocol) |
| **User Experience** | Noticeable delay |

### Security Trade-offs

**Strengths:**
- ✓ Maximum security (2-of-3 threshold for every operation)
- ✓ Device compromise ≠ key compromise (1 share useless)
- ✓ No single point of failure
- ✓ Revocable (can rotate shares)
- ✓ Transparent (all operations logged)

**Weaknesses:**
- ✗ Requires network for every signature
- ✗ Higher latency (350-500ms)
- ✗ Availability dependent on remote shares
- ✗ More complex protocol (2 network rounds)

**Use Cases:**
- High-value transactions (> $10,000)
- Code signing (firmware updates)
- Enterprise key management
- When maximum security > convenience

---

## Mode 3: Hybrid + Session Tokens (Balanced)

### Architecture

```
Background Refresh (When Online):
    Device ──────► FROST (2-of-3)
              │         │
              │    Pre-sign tokens
              │         │
              ◄─────────┘
              │
    Store 20 tokens (80 hours offline)

Daily Use (Offline):
    User → Device → Validate token → Sign with token → Done
    (50ms latency, works offline for 80 hours)

Fallback Chain:
    1. Try hybrid (1 local + 1 remote) ─── 350ms
    2. Try session token ────────────────── 50ms
    3. Try degraded local (with warning) ─ 10ms
```

### Code Example

```rust
use frost_core::hybrid::*;

// Setup hybrid device
let mut hybrid_device = HybridFROSTDevice::new(
    Some(local_share),
    group_public_key,
    vec![
        RemoteShareEndpoint {
            participant_id: ParticipantId::new(2)?,
            location: "Shenzhen, CN".to_string(),
            endpoint_url: "https://frost-cn.example.com".to_string(),
            available: true,
            avg_response_time: 200,
            ..Default::default()
        },
        RemoteShareEndpoint {
            participant_id: ParticipantId::new(3)?,
            location: "Zürich, CH".to_string(),
            endpoint_url: "https://frost-ch.example.com".to_string(),
            available: true,
            avg_response_time: 180,
            ..Default::default()
        },
    ],
);

// Refresh tokens when online (background task)
hybrid_device.refresh_tokens().await?;

// Daily use: automatic fallback
let message = b"Unlock keychain";
let signature = hybrid_device.sign(message).await?;  // 50ms (uses token)
```

### Specifications

| Property | Value |
|----------|-------|
| **Latency** | 50ms (token), 350ms (hybrid), 10ms (degraded) |
| **Offline Duration** | ~80 hours (20 tokens × 4 hours each) |
| **Network Required** | Background refresh every 4 hours |
| **Security (Token)** | ★★★★☆ (FROST-signed token) |
| **Security (Hybrid)** | ★★★★☆ (2-of-3 threshold) |
| **Security (Degraded)** | ★★☆☆☆ (single device, emergency) |
| **Complexity** | Medium (tiered fallback) |
| **User Experience** | Excellent (feels offline) |

### Security Trade-offs

**Strengths:**
- ✓ Best of both worlds (security + convenience)
- ✓ 99% of signatures use tokens (50ms, offline)
- ✓ Graceful degradation (hybrid → token → local)
- ✓ Long offline duration (80 hours typical)
- ✓ Transparent mode switching

**Weaknesses:**
- ~ Token compromise allows limited operations (4-hour window)
- ~ Requires periodic online connectivity (every few days)
- ~ More complex state management

**Use Cases:**
- Consumer devices (MacBooks, iPhones)
- Frequent offline use (flights, remote areas)
- When UX critical (< 100ms latency required)
- General-purpose RoT

---

## Side-by-Side Comparison

### Security Levels

```
Manufacturing Phase (Key Generation):
┌──────────────┬─────────────┬─────────────┬─────────────┐
│              │ Derived Key │ Pure FROST  │ Hybrid      │
├──────────────┼─────────────┼─────────────┼─────────────┤
│ DKG Security │ ★★★★★       │ ★★★★★       │ ★★★★★       │
│ (2-of-3)     │ Threshold   │ Threshold   │ Threshold   │
└──────────────┴─────────────┴─────────────┴─────────────┘

Daily Operation (Signing):
┌──────────────┬─────────────┬─────────────┬─────────────┐
│              │ Derived Key │ Pure FROST  │ Hybrid      │
├──────────────┼─────────────┼─────────────┼─────────────┤
│ Signing Sec. │ ★★★☆☆       │ ★★★★★       │ ★★★★☆       │
│              │ Single key  │ Threshold   │ Token/Hybrid│
└──────────────┴─────────────┴─────────────┴─────────────┘
```

### Performance

```
Latency (ms):
    0        100       200       300       400       500
    ├─────────┼─────────┼─────────┼─────────┼─────────┤
Derived:  ▓▓▓ 10ms (local)
Hybrid:   ▓▓▓▓▓ 50ms (token)
          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ 350ms (hybrid)
FROST:    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ 500ms (full threshold)
```

### Offline Capability

```
Offline Duration:
    Hours:  1    4    8    16   32   64   ∞
    ├───────┼────┼────┼────┼────┼────┼────┤
Derived:  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━► Unlimited
Hybrid:   ━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ ~80 hours
FROST:    ✗ (requires network for every operation)
```

### Use Case Matrix

| Use Case | Derived Key | Pure FROST | Hybrid |
|----------|-------------|------------|--------|
| **Consumer Device (MacBook/iPhone)** | ✓ Best | ✗ Too slow | ✓ Good |
| **Enterprise HSM** | ✓ Good | ✓ Best | ✓ Good |
| **High-Value Transactions** | ~ OK | ✓ Best | ✓ Good |
| **Code Signing** | ~ OK | ✓ Best | ✓ Good |
| **Frequent Offline** | ✓ Best | ✗ Unusable | ~ OK (80h) |
| **Maximum Security** | ✗ Single point | ✓ Best | ~ Good |
| **Low Latency** | ✓ Best | ✗ 500ms | ✓ Good |
| **Open Source Manufacturing** | ✓ Yes | ✓ Yes | ✓ Yes |

---

## Implementation Recommendations

### For Apple Hardware (MacBook, iPhone)

**Recommendation: Derived Key Mode**

**Rationale:**
- User expectation: Instant response (< 50ms)
- Offline requirement: Frequent (flights, low coverage)
- Security: Manufacturing backdoor resistance (main threat)
- UX: Identical to Secure Enclave (seamless migration)

**Configuration:**
```rust
// During manufacturing (Shenzhen factory)
let device_key = ManufacturingProvisioner::provision_device().await?;
device_key.encrypt_to_puf(&puf_key);

// Store in Secure Enclave flash
write_secure_storage(device_key);

// Daily use
let sig = device_key.sign(biometric_challenge)?;  // 8ms
```

**Re-key Policy:**
- Automatic: Every 365 days (annual service)
- Manual: On security event (device repair, etc.)
- Emergency: If transparency log shows anomaly

### For Server/Enterprise HSM

**Recommendation: Pure FROST Mode**

**Rationale:**
- Network always available (data center)
- Maximum security required (signing $M+ transactions)
- Latency acceptable (500ms fine for batch signing)
- Auditability critical (threshold prevents insider threats)

**Configuration:**
```rust
// 3 geographically distributed HSMs
let frost_coordinator = FrostCoordinator::new(2, 3)?;

// Every signature requires 2-of-3
let sig = frost_coordinator.sign(transaction).await?;  // 350ms
```

### For IoT/Edge Devices

**Recommendation: Hybrid + Session Tokens**

**Rationale:**
- Intermittent connectivity (WiFi, cellular)
- Battery efficient (minimize network calls)
- Graceful degradation (works offline temporarily)
- Security > consumer, < enterprise

**Configuration:**
```rust
let mut hybrid = HybridFROSTDevice::new(local_share, group_pk, remotes);

// Background refresh (when WiFi available)
tokio::spawn(async move {
    loop {
        if is_online() {
            hybrid.refresh_tokens().await.ok();
        }
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
});

// Daily use
let sig = hybrid.sign(sensor_data).await?;  // 50ms (token)
```

---

## Migration Path Between Modes

### Derived Key → Pure FROST

**When:** Security requirements increase (e.g., device now handles payments)

**Process:**
1. Initiate DKG with 3 remote participants
2. Derive shares from existing derived key (optional: for backward compat)
3. Update firmware to use FROST signing
4. Zeroize old derived key

### Pure FROST → Hybrid

**When:** User complaints about latency

**Process:**
1. Keep FROST shares
2. Add session token refresh
3. Firmware update to support token signing
4. Gradual rollout (A/B test latency impact)

### Hybrid → Derived Key

**When:** Offline requirement becomes critical

**Process:**
1. Run DKG to derive permanent device key
2. Zeroize FROST shares + session tokens
3. Firmware update to derived key mode
4. Notify user of security model change

---

## Security Model Comparison

### Threat Model: Malicious Factory

| Threat | Derived Key | Pure FROST | Hybrid |
|--------|-------------|------------|--------|
| **Factory pre-generates keys** | ✗ Prevented (threshold DKG) | ✗ Prevented | ✗ Prevented |
| **Factory leaks keys** | ✗ Prevented (unique per device) | ✗ Prevented | ✗ Prevented |
| **Factory creates backdoor** | ✗ Detected (reproducible builds) | ✗ Detected | ✗ Detected |
| **Factory ships rogue device** | ✗ Detected (transparency log) | ✗ Detected | ✗ Detected |

**All modes achieve same manufacturing security.** ✓

### Threat Model: Device Theft

| Threat | Derived Key | Pure FROST | Hybrid |
|--------|-------------|------------|--------|
| **Thief extracts key** | ~ Possible (physical attack) | ✗ Prevented (1/3 useless) | ~ Possible (1/3 + tokens) |
| **Thief uses stolen device** | ~ Possible (if no biometric) | ✗ Prevented (needs remote) | ~ Limited (token expire) |
| **Thief clones device** | ~ Possible (if key extracted) | ✗ Prevented (threshold) | ~ Limited (token expire) |

**Pure FROST strongest against theft.** ✓

### Threat Model: Government Compulsion

| Threat | Derived Key | Pure FROST | Hybrid |
|--------|-------------|------------|--------|
| **China orders backdoor** | ✗ Prevented (1/3 share) | ✗ Prevented (1/3 share) | ✗ Prevented (1/3 share) |
| **Switzerland court order** | ✗ Prevented (1/3 share) | ✗ Prevented (1/3 share) | ✗ Prevented (1/3 share) |
| **All 3 jurisdictions collude** | ~ Possible (DKG only) | ~ Possible (always) | ~ Possible (DKG + tokens) |

**All modes resist single-jurisdiction compulsion.** ✓

---

## Conclusion: Which Mode?

### Quick Decision Matrix

```
┌─────────────────────────────────────────────────────────────┐
│ Your Priority                    │ Recommended Mode          │
├──────────────────────────────────┼───────────────────────────┤
│ ⚡ Lowest latency (<10ms)        │ DERIVED KEY               │
│ 🔒 Maximum security (threshold)  │ PURE FROST                │
│ ✈️  Works offline (days)         │ DERIVED KEY               │
│ 📱 Consumer UX (invisible)       │ HYBRID + TOKENS           │
│ 🏢 Enterprise HSM                │ PURE FROST                │
│ 🏭 No manufacturer trust         │ ALL (threshold DKG)       │
│ 🌐 Good connectivity             │ PURE FROST or HYBRID      │
│ 🔋 Battery constrained           │ DERIVED KEY or HYBRID     │
│ 💰 High-value operations         │ PURE FROST                │
│ 📝 Code signing                  │ PURE FROST                │
│ 🔓 Device unlock                 │ DERIVED KEY or HYBRID     │
└──────────────────────────────────┴───────────────────────────┘
```

### Default Recommendations

**For most users: Derived Key Mode**
- Satisfies: Open source ✓, unique per device ✓, secure manufacturing ✓
- Fully offline, low latency, simple UX
- Trade-off: Daily security = Secure Enclave (but manufacturing is threshold)

**For maximum security: Pure FROST**
- Every operation requires 2-of-3 threshold
- No single point of failure
- Trade-off: Requires network, higher latency

**For balanced approach: Hybrid + Session Tokens**
- 99% of operations offline (tokens)
- Graceful degradation
- Trade-off: More complex state machine

---

**All three modes achieve the core goal: provably secure manufacturing with no single point of trust.**

The difference is **daily operation security vs. convenience trade-off**.

**Document Version:** 1.0
**Last Updated:** 2026-01-02
