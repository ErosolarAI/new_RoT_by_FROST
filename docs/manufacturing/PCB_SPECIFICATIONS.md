# PCB Design Specifications - FROST RoT Module

## PCB Stack-Up (4-Layer)

```
┌─────────────────────────────────────┐
│ Layer 1: Top Signal (Components)    │ ← 35µm copper
├─────────────────────────────────────┤
│ Prepreg PP1210 (0.21mm)            │
├─────────────────────────────────────┤
│ Layer 2: Ground Plane               │ ← 35µm copper
├─────────────────────────────────────┤
│ Core FR-4 TG170 (0.46mm)           │
├─────────────────────────────────────┤
│ Layer 3: Power Plane (+3.3V)       │ ← 35µm copper
├─────────────────────────────────────┤
│ Prepreg PP1210 (0.21mm)            │
├─────────────────────────────────────┤
│ Layer 4: Tamper Detection Mesh      │ ← 35µm copper
└─────────────────────────────────────┘
         Total: 1.0mm ±10%
```

## Design Files Format

### Required Deliverables to Factory
- Gerber RS-274X format (extended)
- Excellon drill files
- IPC-2581 (preferred) or ODB++
- BOM in Excel (.xlsx) or CSV
- Assembly drawing (PDF)
- Pick-and-place file (.pos or .csv)
- Test point locations

### CAD Tool Compatibility
- KiCad 7.0+ (recommended - open source)
- Altium Designer
- Eagle
- EasyEDA (Chinese, integrated with JLCPCB)

---

## Detailed Layer Specifications

### Layer 1: Top Signal Layer

**Purpose:** Component placement and signal routing

**Design Rules:**
- Minimum trace width: 0.15mm (6 mil)
- Minimum trace spacing: 0.15mm (6 mil)
- Differential pairs (USB): 0.2mm traces, 0.15mm gap (90Ω impedance)
- Sensitive signals: Guard traces on both sides
- Crystal traces: < 10mm length, direct to MCU pins

**Component Placement:**
- MCU: Center of board
- USB connector: Edge, with proper strain relief
- Decoupling caps: < 3mm from power pins
- Keep-out zone: 2mm from board edge

### Layer 2: Ground Plane

**Purpose:** Signal return path, EMI shielding

**Design Rules:**
- Solid pour (no splits)
- Vias to Layer 2: minimum 12 per IC (thermal and electrical)
- Ground vias under USB connector: 4 minimum
- Stitching vias around perimeter: every 5mm

### Layer 3: Power Plane (+3.3V)

**Purpose:** Power distribution

**Design Rules:**
- Solid pour for 3.3V
- Split for analog/digital sections if needed
- Minimum 20 vias to Layer 1 for power delivery
- Star grounding for LDO regulator

### Layer 4: Tamper Detection Mesh

**Purpose:** Physical security - detect PCB drilling/milling attacks

**Design:**
```
┌─────────────────────────────────────────┐
│  ╔════════════════════════════════════╗ │
│  ║ ┌─────────────────────────────┐   ║ │
│  ║ │ ┌──────────────────────┐ │  │   ║ │
│  ║ │ │  Components Here     │ │  │   ║ │
│  ║ │ └──────────────────────┘ │  │   ║ │
│  ║ └─────────────────────────────┘   ║ │
│  ╚════════════════════════════════════╝ │
└─────────────────────────────────────────┘
    ↑                                  ↑
    Serpentine trace (0.15mm width)
    covers entire board area
```

**Mesh Specifications:**
- Trace width: 0.15mm
- Spacing between traces: 0.3mm
- Total resistance: 500Ω - 1kΩ
- Connected to: MCU GPIO with pull-up resistor
- Monitoring: Continuous resistance measurement by firmware

**Detection Method:**
1. MCU applies constant current through mesh
2. Measures voltage drop (R = V/I)
3. If resistance changes > 10%: trigger tamper alert
4. Alert action: Zeroize all secrets, halt operation

---

## M.2 2242 Form Factor

### Mechanical Dimensions

```
                 22mm
        ┌─────────────────┐
        │                 │
        │    ┌─────┐      │
        │    │ MCU │      │  42mm
        │    └─────┘      │
        │                 │
        │  [M.2 Connector]│
        └─────────────────┘

Key: B+M (supports both SATA and PCIe)
Mounting hole: 2.0mm diameter at position per M.2 spec
```

### Connector Pinout (M.2 Key B)

| Pin | Signal | Usage |
|-----|--------|-------|
| 1 | GND | Ground |
| 2 | 3.3V | Power input |
| 4-5 | Reserved | - |
| 11-12 | USB 2.0 D+/D- | Communication |
| 22-23 | GND | Ground |
| 58 | 3.3V | Power input |

**Note:** For MacBook integration, USB pins are mapped to internal USB hub.

---

## PCB Manufacturing Specifications (Gerber Notes)

### File Naming Convention (for Chinese fabs)
```
FROST-RoT-v1.0-Top.gtl         (Top copper)
FROST-RoT-v1.0-L2.g2           (Inner layer 2)
FROST-RoT-v1.0-L3.g3           (Inner layer 3)
FROST-RoT-v1.0-Bottom.gbl      (Bottom copper)
FROST-RoT-v1.0-TopMask.gts     (Top solder mask)
FROST-RoT-v1.0-BottomMask.gbs  (Bottom solder mask)
FROST-RoT-v1.0-TopSilk.gto     (Top silkscreen)
FROST-RoT-v1.0-BottomSilk.gbo  (Bottom silkscreen)
FROST-RoT-v1.0-EdgeCuts.gm1    (Board outline)
FROST-RoT-v1.0-PTH.drl         (Plated through holes)
FROST-RoT-v1.0-NPTH.drl        (Non-plated holes)
```

### Drill File Specifications
- Format: Excellon
- Units: Millimeters
- Zero suppression: Leading
- Coordinates: Absolute
- Min drill: 0.2mm
- Max drill: 3.0mm

### Fabrication Notes for Factory
```
Board Name: FROST-RoT-Module-v1.0
Dimensions: 22mm x 42mm
Quantity: [specify]
Material: FR-4 TG170
Thickness: 1.0mm ±0.1mm
Layers: 4
Copper Weight: 1oz (35µm) all layers
Surface Finish: ENIG (1-2µm)
Min Track/Space: 0.15mm/0.15mm
Min Hole: 0.2mm
Solder Mask: Black, both sides
Silkscreen: White, top only
Impedance Control: Yes (see impedance table)
Gold Fingers: No
Castellated Holes: No
Special Requirements: Layer 4 tamper mesh must be continuous
```

### Impedance Requirements

| Net | Type | Target Z | Tolerance |
|-----|------|----------|-----------|
| USB_DP/DN | Differential | 90Ω | ±10% |
| CRYSTAL | Single-ended | 50Ω | ±15% |

**Test Coupon:** Include on panel, 50mm length

---

## SMT Assembly Specifications

### Stencil Design
- Thickness: 0.12mm (5 mil)
- Material: Stainless steel, laser-cut
- Aperture: 1:1 ratio for most pads
- Fine-pitch ICs: 0.9:1 ratio (reduce solder paste)

### Solder Paste
- Type: Lead-free SAC305 (96.5% Sn, 3% Ag, 0.5% Cu)
- Particle size: Type 3 or 4
- Brand: Senju M705 or equivalent

### Reflow Profile
```
Temperature (°C)
250 ─          ┌───┐ Peak: 245°C ±5°C
    │         ╱     ╲
200 ─    ┌───┘       └───┐ TAL: 217°C
    │   ╱                 ╲
150 ─  ╱  Preheat          ╲ Cooling
    │ ╱                     ╲
 25 ┴──────────────────────────▶ Time (sec)
    0   60  120 180 240 300

    Preheat: 150-180°C, 90-120 sec
    TAL: 217-230°C, 60-90 sec
    Peak: 240-250°C, 20-30 sec
    Cooling: < 6°C/sec
```

---

## Testing and Programming

### Test Points (0.5mm pads, top layer)

| Label | Signal | Purpose |
|-------|--------|---------|
| TP1 | 3.3V | Power check |
| TP2 | GND | Ground reference |
| TP3 | USB_DP | USB signal test |
| TP4 | MCU_TX | UART debug |
| TP5 | TAMPER | Mesh resistance |
| TP6 | SWDIO | Programming/debug |
| TP7 | SWCLK | Programming/debug |

### Programming Interface
- **Protocol:** SWD (Serial Wire Debug) for ARM
- **Connector:** Tag-Connect TC2050 footprint (no connector populated)
- **Programmer:** ST-Link V3, J-Link, or DAPLink
- **Firmware:** Load via factory programming fixture

### Factory Test Procedure
1. Visual inspection (AOI - Automated Optical Inspection)
2. Power-on test (measure current: 20-50mA idle)
3. USB enumeration test
4. TRNG test (collect 1KB, verify entropy)
5. Tamper mesh resistance test (500-1000Ω)
6. Crypto self-test (FROST signing simulation)
7. Program unique serial number to OTP
8. Epoxy encapsulation
9. Final QC inspection

---

## Design for Manufacturing (DFM) Checklist

- [ ] All components available from LCSC or Taobao
- [ ] No BGAs (use QFP/QFN for ease of assembly)
- [ ] Minimum 0.5mm pitch (no 0.4mm fine-pitch)
- [ ] Test points accessible from top side
- [ ] Fiducials: 3 minimum (1mm copper, 3mm clearance)
- [ ] Tooling holes: 3mm diameter if panelized
- [ ] Panel rails: 5mm if panelized
- [ ] Solder mask clearance: 0.05mm minimum
- [ ] Silkscreen: 0.15mm line width, 1.0mm text height
- [ ] Barcode/QR code area: 5mm x 5mm (for traceability)

---

## Panelization (for volume production)

```
┌─────────────────────────────────────────────┐
│  Rail (5mm)                                 │
│  ┌────┐  ┌────┐  ┌────┐  ┌────┐  ┌────┐   │
│  │PCB1│  │PCB2│  │PCB3│  │PCB4│  │PCB5│   │
│  └────┘  └────┘  └────┘  └────┘  └────┘   │
│  ┌────┐  ┌────┐  ┌────┐  ┌────┐  ┌────┐   │
│  │PCB6│  │PCB7│  │PCB8│  │PCB9│  │PCB10│  │
│  └────┘  └────┘  └────┘  └────┘  └────┘   │
│  Rail (5mm)                                 │
└─────────────────────────────────────────────┘

Panel: 10 boards (2x5 array)
Break-out: V-groove or mouse bites
```

---

**Revision:** 1.0
**Date:** 2026-01-02
**Approved by:** Engineering Team
