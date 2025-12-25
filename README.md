# MBR Analyzer (Python)

A lightweight **Master Boot Record (MBR) analyzer** written in Python.  
This tool parses and validates the first 512 bytes of a disk image or block device to determine whether the MBR is **valid, misconfigured, or broken**.

Designed for **learning, DFIR, and low-level disk forensics**.

---

## 🔍 What This Tool Does

- Reads the first **512 bytes** of a disk image or device
- Validates the **MBR signature (0x55AA)**
- Parses all **4 partition table entries**
- Identifies:
  - Active (bootable) partitions
  - Partition types and sizes
  - LBA start and sector count
  - CHS values (legacy)
- Detects common MBR issues:
  - Invalid or missing signature
  - Multiple active partitions
  - Overlapping partitions
  - Suspicious partition alignment
- Classifies the MBR as:
  - **OK**
  - **WARN** (misconfiguration or suspicious layout)
  - **BROKEN** (corruption or invalid structure)

---

## 📦 Features

- Simple CLI interface
- Human-readable output
- Safe to run on disk images
- No external dependencies (stdlib only)
- DFIR-friendly heuristics (non-destructive)

---

## 🧠 MBR Layout Reference

