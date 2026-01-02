# Bill of Materials (BOM) - FROST Root of Trust Module

## Overview
This document specifies the complete BOM for manufacturing the FROST RoT security module in Shenzhen, China.

## Target Form Factors
- **Variant A**: M.2 2242 module (for MacBook/iPhone integration)
- **Variant B**: USB-C security key (standalone)
- **Variant C**: Bare chip for OEM integration

---

## Core Components

### Option 1: GigaDevice GD32W515 (Recommended for Cost)

| Component | Part Number | Manufacturer | Qty | Unit Price (USD) | Source |
|-----------|-------------|--------------|-----|------------------|--------|
| MCU       | GD32W515P0Q6 | GigaDevice | 1 | $2.50 | Shenzhen markets, LCSC |
| Secure Flash | GD25Q64E | GigaDevice | 1 | $0.35 | LCSC, Taobao |
| EEPROM (Secure Storage) | 24LC256 | Microchip | 1 | $0.15 | Taobao |
| Oscillator | X322516MLB4SI | Epson | 1 | $0.12 | LCSC |
| LDO Regulator | AMS1117-3.3 | AMS | 1 | $0.08 | Taobao, LCSC |
| USB-C Connector | TYPE-C-31-M-12 | Korean Hroparts | 1 | $0.25 | Taobao |
| ESD Protection | USBLC6-2SC6 | STMicro | 1 | $0.12 | LCSC |
| Tamper Mesh PCB | Custom 4-layer | - | 1 | $0.50 | Shenzhen PCB fab |
| Encapsulation Resin | EP-21TCHT | Master Bond | 10g | $0.30 | Alibaba |

**Subtotal (Option 1):** ~$4.40 per unit

### Option 2: Nations Technologies N32S032 (Higher Security)

| Component | Part Number | Manufacturer | Qty | Unit Price (USD) | Source |
|-----------|-------------|--------------|-----|------------------|--------|
| Secure MCU | N32S032R8L7 | Nations Tech | 1 | $4.20 | Direct from Nations Tech Shenzhen |
| Secure Flash | Built-in | - | - | - | - |
| External EEPROM | AT24C256C | Atmel | 1 | $0.18 | LCSC |
| Oscillator | X322516MLB4SI | Epson | 1 | $0.12 | LCSC |
| LDO Regulator | AMS1117-3.3 | AMS | 1 | $0.08 | Taobao |
| USB-C Connector | TYPE-C-31-M-12 | Korean Hroparts | 1 | $0.25 | Taobao |
| ESD Protection | USBLC6-2SC6 | STMicro | 1 | $0.12 | LCSC |
| Tamper Mesh PCB | Custom 4-layer | - | 1 | $0.50 | Shenzhen PCB fab |

**Subtotal (Option 2):** ~$5.45 per unit

### Option 3: Feitian HSM Chip (Premium)

| Component | Part Number | Manufacturer | Qty | Unit Price (USD) | Source |
|-----------|-------------|--------------|-----|------------------|--------|
| HSM Module | FT-SE-A22 | Feitian | 1 | $8.50 | Feitian Beijing (MOQ: 1000) |
| Interface MCU | STM32F103C8T6 | ST | 1 | $1.20 | LCSC, Taobao |
| USB-C Connector | TYPE-C-31-M-12 | Korean Hroparts | 1 | $0.25 | Taobao |
| Supporting passives | - | - | - | $0.30 | - |

**Subtotal (Option 3):** ~$10.25 per unit

---

## Passive Components (All Options)

| Type | Value | Package | Qty | Unit Price | Total |
|------|-------|---------|-----|------------|-------|
| Capacitor | 10µF | 0805 | 4 | $0.01 | $0.04 |
| Capacitor | 100nF | 0603 | 8 | $0.005 | $0.04 |
| Capacitor | 22pF | 0603 | 2 | $0.005 | $0.01 |
| Resistor | 5.1kΩ | 0603 | 2 | $0.002 | $0.004 |
| Resistor | 10kΩ | 0603 | 4 | $0.002 | $0.008 |
| LED | Green | 0805 | 1 | $0.02 | $0.02 |
| LED | Red | 0805 | 1 | $0.02 | $0.02 |

**Subtotal:** ~$0.15

---

## PCB Specifications

### 4-Layer PCB with Tamper Detection

| Parameter | Specification |
|-----------|--------------|
| Layers | 4 (Signal / Ground / Power / Tamper Mesh) |
| Material | FR-4 TG170 |
| Thickness | 1.0mm |
| Copper Weight | 1oz (35µm) |
| Min Track/Space | 0.1mm/0.1mm |
| Min Hole Size | 0.2mm |
| Surface Finish | ENIG (Electroless Nickel Immersion Gold) |
| Solder Mask | Black (to obscure traces) |
| Silkscreen | White |
| Impedance Control | 50Ω single-ended, 100Ω differential |
| Tamper Mesh | Layer 4: serpentine trace covering all components |

**PCB Cost:** $0.50/unit @ 10K quantity (Shenzhen JLCPCB, PCBWay)

---

## Enclosure (M.2 Variant)

| Component | Specification | Source | Price |
|-----------|--------------|--------|-------|
| M.2 Shell | Aluminum, anodized black | Taobao/Alibaba | $0.60 |
| Thermal Pad | 0.5mm silicone | 3M equivalent | $0.05 |
| M.2 Connector | M.2 Key B+M, 2242 | Amphenol | $0.40 |

**Subtotal:** $1.05

---

## Manufacturing Costs (10K Units, Shenzhen)

| Item | Cost per Unit (USD) |
|------|---------------------|
| Components (Option 1) | $4.40 |
| Passives | $0.15 |
| PCB | $0.50 |
| Enclosure | $1.05 |
| SMT Assembly | $0.80 |
| Testing & Programming | $0.30 |
| Epoxy Encapsulation | $0.30 |
| Quality Control | $0.20 |
| Packaging | $0.15 |

**Total Manufacturing Cost:** ~$7.85/unit

**Suggested Retail Price:** $29.99 (3.8x margin)

---

## Recommended Suppliers (Shenzhen/China)

### Components
- **LCSC Electronics** (立创商城): Online ordering, English interface
  - Website: lcsc.com
  - Address: Shenzhen, Guangdong

- **Szlcsc/JLCPCB**: Integrated PCB + assembly
  - Website: jlcpcb.com
  - One-stop shop for prototyping

### Contract Manufacturers
1. **Shenzhen Wonderful** (中诺通讯)
   - Minimum order: 1K units
   - Capabilities: SMT, through-hole, encapsulation
   - Certifications: ISO9001, ISO14001

2. **Shenzhen Grande**
   - Minimum order: 500 units
   - Turnkey PCB assembly
   - Website: grandpcb.com

3. **Seeed Studio**
   - Prototype-friendly (MOQ: 5 units)
   - Open-source hardware focus
   - Website: seeedstudio.com

### Direct Manufacturer Contact
- **GigaDevice**: Shenzhen office, sales@gigadevice.com
- **Nations Technologies**: Shenzhen office, 0755-8860-6888
- **Feitian Technologies**: Beijing/Shenzhen, requires NDA for volume pricing

---

## Quality Standards

### Testing Requirements
1. **Electrical Testing**
   - Continuity test
   - Power consumption < 200mW
   - USB enumeration test

2. **Cryptographic Testing**
   - TRNG entropy test (NIST SP 800-22)
   - FROST DKG simulation
   - Signing operation test

3. **Security Testing**
   - Tamper mesh continuity
   - Side-channel analysis (basic)
   - Secure boot verification

4. **Environmental Testing**
   - Operating temp: -20°C to +70°C
   - Storage temp: -40°C to +85°C
   - Humidity: 5% to 95% RH

### Certifications (Optional)
- **CE**: Required for EU export
- **FCC**: Required for US export
- **RoHS**: Lead-free compliance
- **FIPS 140-2**: For US government use (requires validation lab)

---

## Lead Time Estimates (Shenzhen)

| Phase | Duration |
|-------|----------|
| PCB fabrication | 5-7 days |
| Component sourcing | 3-5 days |
| SMT assembly | 2-3 days |
| Programming/testing | 1-2 days |
| Encapsulation/packaging | 1-2 days |

**Total:** 12-19 days from order to shipping

---

## Minimum Order Quantities

| Component | MOQ | Lead Time |
|-----------|-----|-----------|
| GD32W515 | 1 reel (3000 pcs) | 4-6 weeks |
| N32S032 | 500 pcs | 6-8 weeks |
| Feitian FT-SE-A22 | 1000 pcs | 8-12 weeks |
| Custom PCB | 5 pcs (prototype) | 2-3 days |
| Custom PCB | 100 pcs (production) | 5-7 days |

---

## Notes for Procurement

1. **Avoid Counterfeits**: Purchase MCUs from authorized distributors (LCSC, Arrow, Mouser China)
2. **Customs/Export**: Cryptographic hardware may require export licenses depending on destination
3. **IP Protection**: Use NDA with CM, consider contract terms for design ownership
4. **Backup Suppliers**: Maintain 2-3 sources for critical components
5. **Revision Control**: Mark PCBs with revision number and date code

---

**Document Version:** 1.0
**Last Updated:** 2026-01-02
**Contact:** frost-rot-project@example.com
