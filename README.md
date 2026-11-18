# Offline OSINT Document & Entity Link Intelligence Suite (v1.0)

100% air-gapped Windows desktop GUI for bulk OCR, Indian KYC/ID entity extraction (English, Hindi, and Tamil), multi-core drive triage, and interactive network link visualization.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows 10/11](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg)](#)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](#)
[![Privacy: 100% Offline](https://img.shields.io/badge/Privacy-100%25%20Air--Gapped-success.svg)](#)

## Legal & Ethical Use Disclaimer

Read this disclaimer carefully before running the software. This tool is intended strictly for educational purposes, authorized digital forensics (DFIR), legitimate OSINT research, KYC/AML compliance auditing, and journalistic investigations.

1. **Authorized Use Only:** Only scan, process, or analyze documents and storage media that you own or have explicit legal authorization to inspect.
2. **Data Privacy & Statutory Compliance:** When handling Indian Personally Identifiable Information (PII), including Aadhaar cards, PAN cards, and financial records, you are solely responsible for complying with the Digital Personal Data Protection (DPDP) Act, the Aadhaar Act (2016), the Information Technology Act (2000), and all applicable local privacy laws.
3. **Zero Cloud Transmission:** While this application runs 100% locally offline and transmits zero data over the internet, you are responsible for securing the generated `_OSINT_OUTPUT` files (`CSV`, `JSON`, and `HTML` graphs) against unauthorized access.
4. **No Liability:** The author(s) and contributors assume no liability and are not responsible for any misuse, unlawful data processing, or damages caused by this program.

## Overview

Investigators, compliance teams, and forensic analysts often need to sort through unorganized folders containing thousands of mixed files across multiple individuals. Uploading sensitive identity or banking records to cloud OCR APIs violates privacy laws and operational security, while running local Vision LLMs requires expensive GPUs and overheats standard laptops.

This Python desktop application processes raw document dumps locally on CPU without cloud dependencies:

1. **Bulk-scans folders or entire drive partitions** across images (`JPG`, `PNG`, `WEBP`, `BMP`, `TIFF`, `GIF`) and documents (`PDF`, `DOCX`, `DOC`, `TXT`, `MD`).
2. **Rotates and sharpens** vertical, sideways, upside-down, or low-quality phone camera photos before running OCR.
3. **Extracts structured Indian and global PII** in English, Hindi (Devanagari), and Tamil (`Name`, `Father's Name`, `Husband/Spouse Name`, `DOB`, `Aadhaar`, `PAN`, `Phone`, `Address`, `PIN Code`, `Bank Account`, `IFSC`).
4. **Cross-links matching entities** into an offline, dark-mode PyVis network graph (`connections_graph.html`) to reveal shared addresses, family relationships (`S/O`, `W/O`, `D/O`, `पिता`, `पति`), shared phone numbers, and linked bank accounts.
5. **Scales from low-power laptops to 80-thread servers** via a built-in hardware profile selector.

## Features (v1.0)

* **Hardware Profile Selector:**
  * **Laptop Mode (1 Thread):** Runs with `BELOW_NORMAL` CPU priority, single-thread throttling (`OMP_THREAD_LIMIT=1`), and an adjustable cooldown timer (`1.5s` default) to prevent thermal throttling on older laptops.
  * **Balanced Desktop Mode (4 Threads):** Standard multi-core processing for workstations.
  * **Server / Multi-Core Turbo Mode (Up to 64+ Parallel Workers):** Uses Python's `ProcessPoolExecutor` to saturate 40-core / 80-thread servers for full-drive partition triage. Automatically skips Windows system directories (`Windows`, `Program Files`, `AppData`, `$RECYCLE.BIN`, `node_modules`).
* **Auto-Orientation for Camera Scans:** Combines Tesseract OSD (`--psm 0`) with `90° / 180° / 270°` rotation probing and `UnsharpMask` contrast enhancement so unedited vertical phone photos extract without manual cropping or rotation.
* **Live Pause, Stop, and Partial Exports:** Pause or stop a scan at any point to inspect the live extracted records table, open the partial `CSV`/`JSON` files, or view the network graph generated so far.
* **Multi-Format Filtering:** Scan **Both (Images + Docs)**, **Images Only**, or **Documents Only** (`PDF`, `DOCX`, `DOC`, `TXT`, `MD`).
* **Custom Field Extraction & Skip Rules:** Toggle individual PII fields on or off (`Name`, `Father's Name`, `Husband's Name`, `DOB`, `Aadhaar`, `PAN`, `Phone`, `Address`, `PIN Code`, `Bank Account`, `IFSC`). Built-in filters automatically skip signature crops (`sig`, `seg`, `sign`, `thumb`, `photo`) and small icon files (`< 5 KB`).
* **UIDAI Verhoeff Checksum & OCR Confusion Repair:** Validates 12-digit Aadhaar candidates against the official Verhoeff Checksum Algorithm and corrects common OCR character mix-ups (`O/0`, `I/1`, `S/5`, `B/8`, `Z/2`, `G/6`) in PAN, Aadhaar, and IFSC strings.

## Use Cases

* **OSINT & Investigative Journalism:** Map relationships, shell-company directors, shared family guardians, and overlapping residential PIN codes across public or leaked document dumps.
* **KYC / AML & Financial Fraud Compliance:** Audit customer onboarding folders to catch synthetic identities, shared phone numbers, or duplicate bank accounts across separate applicant profiles.
* **Digital Forensics & Incident Response (DFIR):** Run offline triage across seized drives or partitions on high-core forensic workstations to index identity documents and financial statements.
* **Legal & Case File Organization:** Convert disorganized client folders containing WhatsApp images, phone photos, Word files, and PDF statements into a single searchable spreadsheet (`extracted_records.csv`).

## Installation & Setup (Windows 10 / 11 / Server)

### 1. Install Tesseract OCR
Open Command Prompt (`cmd`) and run:

```cmd
winget install --id UB-Mannheim.TesseractOCR
```

Download [`hin.traineddata`](https://github.com/tesseract-ocr/tessdata_best/raw/main/hin.traineddata) (Hindi) and optionally [`tam.traineddata`](https://github.com/tesseract-ocr/tessdata_best/raw/main/tam.traineddata) (Tamil), then copy them into:

```text
C:\Program Files\Tesseract-OCR\tessdata\
```

### 2. Install Python 3.10+
Install Python with **"Add python.exe to PATH"** enabled:

```cmd
winget install --id Python.Python.3.12
```

### 3. Launch the Application
Double-click `install_and_run.bat`. On first launch, the script installs `pytesseract`, `pillow`, `pdfplumber`, and `pyvis`, then opens the v1.0 GUI.

## Output Structure

All results are written to an `_OSINT_OUTPUT` directory inside your target folder:

```text
Target_Dataset_or_Drive/
├── Person_01_Ramesh/
│   ├── aadhaar_scan.jpg
│   ├── pan_card.png
│   └── bank_statement.pdf
├── Person_02_Suresh/
│   ├── cheque.jpg
│   └── case_notes.docx
└── _OSINT_OUTPUT/
    ├── extracted_records.csv    <-- UTF-8-SIG Excel-ready spreadsheet
    ├── extracted_records.json   <-- Structured JSON array
    └── connections_graph.html   <-- Offline interactive PyVis link map
```

## OpSec & Security Practices

* **100% Local Execution:** Uses no telemetry, external APIs, or cloud LLMs.
* **Encrypted Storage:** Keep sensitive datasets and `_OSINT_OUTPUT` directories inside an encrypted [VeraCrypt](https://www.veracrypt.fr/) volume when at rest.
* **Redaction Compliance:** Mask or redact government IDs before sharing screenshots or `CSV` exports externally.

## License

Released under the **MIT License** — Free for personal, compliance, journalistic, and authorized investigative use.
