# Assembly and Manufacturing Guide

## Factory Assembly Instructions - Shenzhen Contract Manufacturer

This document provides step-by-step instructions for Chinese contract manufacturers to assemble the FROST RoT security module.

---

## Pre-Production Checklist

### Materials Verification
- [ ] All components per BOM received and inspected
- [ ] PCBs inspected (visual + electrical test)
- [ ] Stencil fabricated and cleaned
- [ ] Solder paste fresh (< 30 days old)
- [ ] Programming fixture ready
- [ ] Test software installed

### Equipment Setup
- [ ] SMT pick-and-place machine calibrated
- [ ] Reflow oven profile validated
- [ ] AOI (Automated Optical Inspection) programmed
- [ ] ICT (In-Circuit Test) fixture ready
- [ ] Humidity < 60% RH in assembly area

---

## Assembly Process Flow

```
Raw PCB → Solder Paste → Pick & Place → Reflow → Inspection →
Programming → Testing → Encapsulation → Final QC → Packaging
```

**Total Time per Unit:** ~8 minutes (automated line)
**Daily Capacity:** ~3000 units (8-hour shift)

---

## Step 1: Solder Paste Application

### Equipment
- Semi-automatic stencil printer or manual alignment jig
- Stencil: 0.12mm stainless steel, laser-cut

### Procedure
1. Clean PCB with isopropyl alcohol (IPA), dry completely
2. Align stencil over PCB using fiducial marks
3. Apply solder paste:
   - Paste: SAC305 lead-free, Type 3
   - Squeegee angle: 45-60°
   - Squeegee speed: 10-20 mm/sec
   - Pressure: Medium (adjust for complete fill)
4. Carefully remove stencil (vertical lift)
5. Inspect paste deposits:
   - **PASS:** Clean edges, no bridges, complete fill
   - **FAIL:** Clean PCB and repeat

### Quality Check
- Use microscope to check fine-pitch IC pads (GD32: 0.5mm pitch)
- No solder balls or excess paste

---

## Step 2: Component Placement (SMT)

### Pick and Place Sequence

**Order of placement (bottom to top height):**

1. **Resistors & Small Capacitors** (0603 package)
   - Place first (shortest components)
   - Use vacuum nozzle: 0.5mm diameter

2. **Larger Capacitors** (0805, 1206)
   - 10µF decoupling caps near power pins

3. **LEDs** (0805)
   - Verify polarity: Cathode marking

4. **Crystal Oscillator**
   - Handle with care (ESD sensitive)
   - Orientation: Pin 1 mark to PCB silkscreen

5. **USB-C Connector**
   - Large thermal mass - may need preheat
   - Ensure flush mounting

6. **ESD Protection IC** (SOT-23-6)
   - Check pin 1 orientation

7. **LDO Regulator** (SOT-223)
   - Verify polarity (tab is usually GND or output)

8. **Main MCU** (LQFP-64 or QFN-48)
   - **CRITICAL:** Pin 1 alignment
   - Use vision system for centering
   - MCU options:
     - GigaDevice GD32W515: LQFP-64 (0.5mm pitch)
     - Nations Tech N32S032: LQFP-48 (0.5mm pitch)

9. **Flash Memory** (SOP-8)
   - Pin 1 to dot marking

10. **EEPROM** (SOP-8)
    - Pin 1 to dot marking

### Placement Tolerances
- Resistors/capacitors: ±0.5mm
- ICs: ±0.2mm (use vision alignment)
- Rotation: ±5°

---

## Step 3: Reflow Soldering

### Oven Settings (Lead-Free SAC305 Profile)

**Zone Configuration (8-zone oven):**

| Zone | Temperature | Time | Purpose |
|------|-------------|------|---------|
| 1-2 | 150°C | 60s | Preheat |
| 3-4 | 180°C | 60s | Soak |
| 5-6 | 217°C | 30s | TAL (Time Above Liquidus) |
| 7 | 245°C | 20s | Peak |
| 8 | Cool | - | Cooling (fan on) |

**Belt Speed:** 50 cm/min
**Peak Temperature:** 245°C ±5°C
**Time Above 217°C:** 60-90 seconds
**Cooling Rate:** < 6°C/sec

### Monitoring
- Place thermocouples on test PCB
- Monitor with data logger
- Adjust weekly or after maintenance

### Post-Reflow Inspection
- Visual check for:
  - No cold solder joints (dull appearance)
  - No bridges between pins
  - No tombstoning (component standing up)
  - No missing components

---

## Step 4: Automated Optical Inspection (AOI)

### AOI Programming
- Import Gerber + centroid files
- Train on golden sample
- Set defect thresholds:
  - Missing component: 100% check
  - Polarity: 100% check
  - Solder bridges: 0.1mm min gap
  - Insufficient solder: < 50% pad coverage

### Common Defects to Catch
1. MCU pin bridges (most critical)
2. Wrong component values
3. Reversed polarity (LEDs, electrolytic caps if any)
4. Insufficient solder on USB connector
5. Missing solder on thermal pads

---

## Step 5: Programming and Provisioning

### Programming Fixture
- Pogo-pin fixture contacting test points TP6 (SWDIO) and TP7 (SWCLK)
- Connection to ST-Link V3 or gang programmer
- DUT (Device Under Test) powered via USB or fixture

### Programming Steps

1. **Connect to MCU via SWD**
   ```
   openocd -f interface/stlink.cfg -f target/stm32f1x.cfg
   ```

2. **Flash Bootloader**
   - File: `frost-rot-bootloader-v1.0.bin`
   - Address: 0x08000000
   - Verify: Read back and compare

3. **Flash Firmware**
   - File: `frost-rot-firmware-v1.0.bin`
   - Address: 0x08008000
   - Includes: FROST crypto, HAL, USB stack

4. **Provision Unique ID**
   - Generate random 128-bit UUID
   - Write to OTP (One-Time Programmable) memory
   - Format: `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
   - Log to database for traceability

5. **Lock Debug Interface** (optional, for production only)
   - Set RDP (Read Protection) to Level 1
   - **WARNING:** Cannot be reversed without full erase

### Programming Time
- Per unit: ~30 seconds
- Parallel programming: 8 units simultaneously with gang programmer

---

## Step 6: Functional Testing

### Test Fixture
- Bed-of-nails fixture OR
- Pogo-pin jig with test points

### Test Sequence (Automated)

```python
# Pseudocode for test script
def test_frost_module(dut):
    # 1. Power test
    assert dut.measure_voltage("3V3") in range(3.2, 3.4)
    assert dut.measure_current() < 100  # mA

    # 2. USB enumeration
    assert dut.usb_enumerate() == "FROST RoT Module"

    # 3. TRNG test
    random_bytes = dut.get_random(1024)
    assert entropy_test(random_bytes) > 0.98  # NIST threshold

    # 4. Tamper mesh test
    resistance = dut.measure_resistance("TAMPER", "GND")
    assert 500 < resistance < 1000  # Ohms

    # 5. Crypto self-test
    assert dut.run_self_test() == PASS

    # 6. Sign test message
    test_msg = b"Factory test message"
    sig = dut.frost_sign_test(test_msg)
    assert len(sig) == 64

    print("✓ ALL TESTS PASSED")
    return PASS
```

### Test Coverage
- **Electrical:** 100%
- **Functional:** 100%
- **Crypto:** 100%

### Failure Handling
- **FAIL:** Mark with red dot, separate for rework or scrap
- **PASS:** Proceed to encapsulation

---

## Step 7: Tamper-Evident Encapsulation

### Purpose
- Protect against physical attacks
- Prevent reverse engineering
- Detect tampering attempts

### Materials
- **Epoxy Resin:** EP-21TCHT (Master Bond) or equivalent
  - Two-part epoxy
  - Black color (opaque to hide PCB traces)
  - Thermal conductivity: 0.8 W/m·K
  - Hardness: Shore D 80

### Encapsulation Process

1. **Prepare PCB**
   - Clean with IPA, dry
   - Mask connectors (M.2 connector must remain exposed)

2. **Mix Epoxy**
   - Part A : Part B = 100:28 (by weight)
   - Mix thoroughly for 2-3 minutes
   - Vacuum degass (optional, reduces bubbles)

3. **Apply Epoxy**
   - Dispense over component side
   - Use dam/barrier around edges
   - Thickness: 1-2mm layer
   - Ensure complete coverage of MCU and critical components

4. **Cure**
   - Room temperature: 24 hours
   - OR
   - Oven cure: 80°C for 2 hours

5. **Inspect**
   - No voids or bubbles over MCU
   - Connectors still accessible
   - Tamper mesh still testable

### Alternative: Potting Compound
- For full encapsulation: pot entire module in M.2 shell
- Use polyurethane PU or silicone for easier removal (for RMA)

---

## Step 8: Final Assembly (M.2 Variant)

### Components
- Encapsulated PCB
- Aluminum M.2 shell (22mm x 42mm)
- Thermal pad (optional)
- Label sticker

### Assembly Steps

1. **Apply Thermal Pad**
   - Cut to size: 20mm x 10mm
   - Place over MCU area (on epoxy)

2. **Insert PCB into Shell**
   - Slide PCB into shell
   - Ensure M.2 connector protrudes correctly
   - Align mounting hole

3. **Close Shell**
   - Press-fit or snap-fit (depending on shell design)
   - OR use 2 small screws

4. **Apply Label**
   - Label includes:
     - Product name: "FROST RoT Module"
     - Serial number: `FRT-XXXXXX-XXXX`
     - QR code (links to cert/documentation)
     - Regulatory marks: CE, FCC, RoHS
     - "Made in China"

---

## Step 9: Quality Control (QC)

### Final Inspection Checklist

- [ ] Encapsulation complete, no defects
- [ ] Shell assembly correct
- [ ] Label applied, QR code scannable
- [ ] Re-test USB enumeration (final check)
- [ ] Measure tamper mesh resistance (should be unchanged)
- [ ] Visual: No scratches, dents, or damage

### Sampling Plan (AQL 1.0)
- Sample size: Per ISO 2859 tables
- Example: For lot of 1000, inspect 80 units
- Defects allowed: 1 major, 2 minor

### Documentation
- Log serial number to production database
- Record:
  - Date/time of manufacture
  - Operator ID
  - Test results
  - Firmware version
  - QC pass/fail

---

## Step 10: Packaging

### Packaging Materials

**Individual Unit:**
- Anti-static bag (pink poly, moisture barrier)
- Desiccant pack (2g silica gel)
- Seal bag with heat sealer

**Retail Packaging (if applicable):**
- Cardboard box: 100mm x 70mm x 20mm
- Includes:
  - Module in anti-static bag
  - Quick start guide (printed card)
  - Warranty card
  - Sticker set (optional)

**Bulk Packaging (for OEM):**
- Tray: ESD-safe plastic tray, 50 units per tray
- Box: Corrugated cardboard, 10 trays (500 units) per box
- Label: Lot number, quantity, production date

### Shipping Preparation
- Seal boxes with tape
- Apply shipping labels
- Include packing list and certificate of conformity

---

## Rework Procedures

### Common Rework Scenarios

#### 1. Solder Bridge on MCU
- **Tool:** Hot air rework station + fine-tip tweezers
- **Temperature:** 320°C, airflow low
- **Method:** Heat area, use solder wick to remove excess
- **Verification:** Continuity test between adjacent pins

#### 2. Missing Component
- **Apply solder paste manually (syringe)**
- **Place component with tweezers**
- **Reflow with hot air**

#### 3. Wrong Component Value
- **Remove:** Hot air or soldering iron
- **Clean pads:** Solder wick
- **Replace:** Correct component

#### 4. Failed Programming
- **Check SWD connections**
- **Retry with fresh firmware**
- **If persistent:** Mark as scrap (likely MCU fault)

### Rework Limit
- **Maximum 2 reworks per board**
- After 2nd rework failure: Scrap board

---

## Environmental and Safety Notes

### ESD Protection
- Wrist straps required: 1MΩ resistor to ground
- ESD mats on all work surfaces
- Ionizers for airflow (optional)
- Humidity: 30-70% RH

### Chemical Safety
- Solder paste: Contains flux (respiratory irritant)
  - Use fume extraction
- Epoxy resin: Skin sensitizer
  - Wear gloves (nitrile)
  - Use in ventilated area
- IPA: Flammable
  - Store away from heat sources

### Waste Disposal
- Lead-free solder: Recyclable
- Failed PCBs: E-waste recycling
- Epoxy waste: Hazardous waste (check local regulations)

---

## Production Capacity Estimates

### Automated Line (High Volume)
- Setup time: 2 hours
- Units per hour: 400
- Daily capacity (8h): 3,200 units
- Monthly capacity: 70,000 units

### Semi-Automated (Medium Volume)
- Units per hour: 80
- Daily capacity: 640 units
- Monthly capacity: 14,000 units

### Manual Assembly (Prototypes)
- Units per hour: 10
- Suitable for: < 100 units

---

## Contact for Manufacturing Support

**Technical Support:**
- Email: manufacturing@frost-rot-project.example.com
- WeChat: FrostRoT-Support (for Chinese manufacturers)

**Firmware Updates:**
- Check GitHub: github.com/frost-rot/firmware (hypothetical)

**Quality Issues:**
- RMA process: contact support with serial number and photos

---

**Document Version:** 1.0
**Language:** English (中文翻译可提供 - Chinese translation available upon request)
**Last Updated:** 2026-01-02
