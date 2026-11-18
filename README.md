# 🛡️ Offline OSINT Document & Entity Link Intelligence Suite (v1.0)

> **100% Air-Gapped Windows Desktop GUI for Bulk OCR, Indian KYC/ID Entity Extraction (English, Hindi & Tamil), Multi-Core Drive Triage, and Interactive Network Link Visualization.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows 10/11](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg)](#)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](#)
[![Privacy: 100% Offline](https://img.shields.io/badge/Privacy-100%25%20Air--Gapped-success.svg)](#)

## ⚠️ Legal & Ethical Use Disclaimer

**PLEASE READ CAREFULLY BEFORE USING THIS SOFTWARE:**

This tool is developed strictly for **educational purposes, authorized digital forensics (DFIR), legitimate Open-Source Intelligence (OSINT) research, KYC/AML compliance auditing, and journalistic investigations**.

1. **Authorized Use Only:** Users must only scan, process, or analyze documents and storage media that they own or have explicit legal authorization to inspect.
2. **Data Privacy & Statutory Compliance:** When handling Indian Personally Identifiable Information (PII)—including Aadhaar cards, PAN cards, and financial records—users are solely responsible for complying with the **Digital Personal Data Protection (DPDP) Act**, the **Aadhaar Act (2016)**, the **Information Technology Act (2000)**, and all applicable local privacy laws.
3. **Zero Cloud Transmission:** While this software operates 100% locally offline and transmits zero data over the internet, the user is solely responsible for securing the generated `_OSINT_OUTPUT` files (`CSV`, `JSON`, and `HTML` graphs) against unauthorized access.
4. **No Liability:** The author(s) and contributors assume no liability and are not responsible for any misuse, unlawful data processing, or damages caused by this program.

## 🔍 Overview (What Problem Does This Solve?)

Investigators, compliance teams, and forensic analysts frequently deal with unorganized folders containing hundreds or thousands of mixed documents—**mobile camera photos, vertical/sideways scans, PDFs, Word documents (`.docx`/`.doc`), and text files**—spanning multiple individuals.

Uploading sensitive identity and banking documents to cloud OCR APIs violates privacy laws and OpSec. Running heavy local Vision LLMs requires expensive GPUs and overheats standard laptops.

**Offline OSINT Document & Entity Link Intelligence Suite v1.0** solves this with a zero-cloud Python desktop application that:

1. **Bulk-scans folders or entire drive partitions** across **Images** (`JPG`, `PNG`, `WEBP`, `BMP`, `TIFF`, `GIF`) and **Documents** (`PDF`, `DOCX`, `DOC`, `TXT`, `MD`).
2. **Automatically rotates and enhances** vertical, sideways, upside-down, or low-quality phone camera photos before OCR.
3. **Extracts structured Indian & global PII** in **English, Hindi (Devanagari), and Tamil** (`Name`, `Father's Name`, `Husband/Spouse Name`, `DOB`, `Aadhaar`, `PAN`, `Phone`, `Address`, `PIN Code`, `Bank Account`, `IFSC`).
4. **Cross-links entities automatically** into an interactive, offline dark-mode **PyVis Network Graph (`connections_graph.html`)** to expose shared addresses, family relationships (`S/O`, `W/O`, `D/O`, `पिता`, `पति`), shared phone numbers, and linked bank accounts.
5. **Scales from low-power laptops to 80-thread servers** with a built-in **Hardware Profile Selector**.

## ✨ Key Features in v1.0

* **🖥️ Hardware Profile Selector (Laptop Thermal-Safe vs. Multi-Core Server Turbo):**
  * **Laptop Mode (1 Thread):** Uses `BELOW_NORMAL` CPU priority, single-thread throttling (`OMP_THREAD_LIMIT=1`), and an adjustable cooldown timer (`1.5s` default) so older laptops never overheat.
  * **Balanced Desktop Mode (4 Threads):** Multi-core processing for standard workstations.
  * **Server / Multi-Core Turbo Mode (Up to 64+ Parallel Workers):** Uses Python's `ProcessPoolExecutor` to saturate 40-core / 80-thread servers for full-drive partition triage, automatically skipping Windows system folders (`Windows`, `Program Files`, `AppData`, `$RECYCLE.BIN`, `node_modules`).
* **🔄 Auto-Orientation for Unedited Vertical & Camera Scans:**
  * Combines Tesseract OSD (`--psm 0`) with intelligent `90° / 180° / 270°` rotation probing and `UnsharpMask` contrast enhancement so raw vertical phone photos extract accurately without manual cropping or rotation.
* **⏸️ Live Pause, Stop & Instant Partial Output:**
  * Pause or stop a scan at any moment and immediately inspect the **Live Extracted Records Table**, open the **CSV/JSON**, or launch the **Connection Map** generated so far.
* **📄 Multi-Format Document & Image Support:**
  * Choose between **Both (Images + Docs)**, **Images Only**, or **Documents Only** (`PDF`, `DOCX`, `DOC`, `TXT`, `MD`).
* **🎯 Custom Field Extraction & Skip Filters:**
  * Select/deselect individual fields to extract (`Name`, `Father's Name`, `Husband's Name`, `DOB`, `Aadhaar`, `PAN`, `Phone`, `Address`, `PIN Code`, `Bank Account`, `IFSC`).
  * Custom skip rules automatically bypass signature crops (`sig`, `seg`, `sign`, `thumb`, `photo`) and tiny icon files (`< 5 KB`).
* **✅ UIDAI Verhoeff Checksum & OCR Confusion Repair:**
  * Validates 12-digit Aadhaar candidates against the official **Verhoeff Checksum Algorithm** and repairs common OCR character mix-ups (`O/0`, `I/1`, `S/5`, `B/8`, `Z/2`, `G/6`) in PAN, Aadhaar, and IFSC strings.

## 🎯 Primary Use Cases

* **OSINT & Investigative Journalism:** Uncover hidden relationships, shell-company directors, shared family guardians, and overlapping residential PIN codes across leaked or public document dumps.
* **KYC / AML & Financial Fraud Compliance:** Audit customer onboarding folders to detect synthetic identity fraud, shared phone numbers, or duplicate bank accounts across different applicant profiles.
* **Digital Forensics & Incident Response (DFIR):** Run rapid offline triage across seized drives or partitions on high-core forensic workstations to index identity records and financial statements.
* **Legal & Case File Organization:** Convert messy client folders containing mixed WhatsApp images, vertical phone photos, Word documents, and PDF statements into a single searchable Excel spreadsheet (`extracted_records.csv`).

## 🚀 Installation & Setup (Windows 10 / 11 / Server)

### 1. Install Tesseract OCR
Open Command Prompt (`cmd`) and run:

    winget install --id UB-Mannheim.TesseractOCR

Download [`hin.traineddata`](https://github.com/tesseract-ocr/tessdata_best/raw/main/hin.traineddata) (Hindi) and optionally [`tam.traineddata`](https://github.com/tesseract-ocr/tessdata_best/raw/main/tam.traineddata) (Tamil) and copy them into:

    C:\Program Files\Tesseract-OCR\tessdata\

### 2. Install Python 3.10+
Ensure Python is installed with **"Add python.exe to PATH"** checked:

    winget install --id Python.Python.3.12

### 3. Launch the Suite
Double-click **`install_and_run.bat`**. On first launch, it automatically installs `pytesseract`, `pillow`, `pdfplumber`, and `pyvis` and opens the v1.0 GUI.

## 📂 Output Structure

All extracted results are saved inside your selected folder under `_OSINT_OUTPUT`:

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

## 🔒 OpSec & Security Best Practices

* **100% Local Execution:** No telemetry, external APIs, or cloud LLMs are used.
* **Encrypted Storage:** Store sensitive datasets and `_OSINT_OUTPUT` inside an encrypted [VeraCrypt](https://www.veracrypt.fr/) container when at rest.
* **Redaction Compliance:** Redact or mask sensitive government IDs before sharing screenshots or CSV exports externally.

## 📜 License

Released under the **MIT License** — Free for personal, compliance, journalistic, and authorized investigative use.