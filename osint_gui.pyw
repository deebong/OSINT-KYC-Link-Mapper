import os
import re
import csv
import json
import time
import zipfile
import xml.etree.ElementTree as ET
import threading
import webbrowser
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageOps, ImageEnhance, ImageFilter
import pytesseract
import pdfplumber
from pyvis.network import Network

# Default Windows Tesseract path
TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if os.path.exists(TESSERACT_PATH):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

# Keep each Tesseract invocation single-threaded; Server mode scales via multi-process workers
os.environ["OMP_THREAD_LIMIT"] = "1"

IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff", ".gif")
DOC_EXTS = (".pdf", ".docx", ".doc", ".txt", ".md")

# System/Junk folders automatically skipped when scanning a full partition/drive
SYSTEM_SKIP_DIRS = {
    "_osint_output", "$recycle.bin", "system volume information", "windows",
    "program files", "program files (x86)", "programdata", "appdata",
    "node_modules", ".git", ".venv", "venv", "__pycache__", "recovery", "perflogs"
}

# Official UIDAI Verhoeff Checksum Tables for 12-digit Aadhaar Validation
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def set_process_priority(low_priority=True):
    """Adjusts Windows process priority for thermal safety vs server speed."""
    try:
        import ctypes
        # 0x00004000 = BELOW_NORMAL_PRIORITY_CLASS, 0x00000020 = NORMAL_PRIORITY_CLASS
        prio = 0x00004000 if low_priority else 0x00000020
        ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), prio)
    except Exception:
        pass


def is_valid_verhoeff(num_str):
    if not num_str or len(num_str) != 12 or not num_str.isdigit() or num_str[0] in ("0", "1"):
        return False
    c = 0
    for i, item in enumerate(reversed(num_str)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(item)]]
    return c == 0


def repair_pan_candidate(raw):
    """Repairs common OCR confusions in 10-char PAN strings (AAAAA9999A)."""
    s = re.sub(r"[^A-Z0-9]", "", raw.upper())
    if len(s) != 10:
        return None
    to_alpha = {"0": "O", "1": "I", "2": "Z", "5": "S", "8": "B", "6": "G"}
    to_digit = {"O": "0", "Q": "0", "D": "0", "I": "1", "L": "1", "Z": "2", "S": "5", "B": "8", "G": "6"}
    chars = list(s)
    for i in (0, 1, 2, 3, 4, 9):
        if chars[i] in to_alpha:
            chars[i] = to_alpha[chars[i]]
    for i in (5, 6, 7, 8):
        if chars[i] in to_digit:
            chars[i] = to_digit[chars[i]]
    fixed = "".join(chars)
    if re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", fixed) and fixed[3] in "PCHFATBLJG":
        return fixed
    return None


def repair_ifsc_candidate(raw):
    """Repairs common OCR confusions in 11-char Indian IFSC strings (AAAA0XXXXXX)."""
    s = re.sub(r"[^A-Z0-9]", "", raw.upper())
    if len(s) != 11:
        return None
    to_alpha = {"0": "O", "1": "I", "2": "Z", "5": "S", "8": "B", "6": "G"}
    chars = list(s)
    for i in (0, 1, 2, 3):
        if chars[i] in to_alpha:
            chars[i] = to_alpha[chars[i]]
    if chars[4] in ("O", "Q", "D"):
        chars[4] = "0"
    fixed = "".join(chars)
    if re.match(r"^[A-Z]{4}0[A-Z0-9]{6}$", fixed):
        return fixed
    return None


def _score_ocr_quality(text):
    """Scores an OCR pass based on valid Indian ID hits and meaningful document keywords."""
    if not text:
        return 0
    score = 0
    upper = text.upper()

    # High reward for verified PAN or Aadhaar
    for token in re.findall(r"\b[A-Z0-9]{10}\b", upper):
        if repair_pan_candidate(token):
            score += 60
    digit_map = str.maketrans({"O": "0", "o": "0", "Q": "0", "I": "1", "l": "1", "S": "5", "B": "8", "Z": "2", "G": "6"})
    for cand in re.findall(r"(?<!\d)[0-9OolISBZ]{4}[\s\-\.]?[0-9OolISBZ]{4}[\s\-\.]?[0-9OolISBZ]{4}(?!\d)", text):
        norm = re.sub(r"[\s\-\.]", "", cand).translate(digit_map)
        if is_valid_verhoeff(norm):
            score += 75
        elif len(norm) == 12 and norm.isdigit():
            score += 25

    # Reward document keywords (English + Hindi)
    cues = (
        "INCOME TAX", "GOVT OF INDIA", "GOVERNMENT OF INDIA", "UNIQUE IDENTIFICATION",
        "PERMANENT ACCOUNT", "FATHER", "ADDRESS", "DOB", "YEAR OF BIRTH", "MALE", "FEMALE",
        "S/O", "W/O", "D/O", "ACCOUNT", "CHEQUE", "IFSC", "BRANCH", "STATEMENT",
        "आयकर", "भारत सरकार", "आधार", "मेरा आधार", "पिता", "पति", "पत्नी", "पता", "जन्म"
    )
    for c in cues:
        if c in upper or c in text:
            score += 18

    # Reward 6-digit PIN or 10-digit Phone
    if re.search(r"\b[1-9]\d{5}\b", text):
        score += 12
    if re.search(r"\b[6-9]\d{9}\b", text):
        score += 12

    return score


def enhance_low_quality_image(pil_img):
    """Prepares unedited/low-quality phone camera images with denoise, contrast stretch, and sharpening."""
    gray = ImageOps.grayscale(pil_img)
    w, h = gray.size
    max_dim = max(w, h)
    # Normalize resolution for optimal OCR recognition without memory bloat
    if max_dim < 1600:
        scale = min(2.0, 1600 / max(1, max_dim))
        gray = gray.resize((int(w * scale), int(h * scale)), Image.Resampling.BILINEAR)
    elif max_dim > 2300:
        scale = 1900 / max_dim
        gray = gray.resize((int(w * scale), int(h * scale)), Image.Resampling.BILINEAR)

    # Median filter cleans camera sensor noise/shadows before contrast enhancement
    v1 = ImageOps.autocontrast(gray, cutoff=1)
    v1 = v1.filter(ImageFilter.SHARPEN)
    return v1


def detect_and_orient_image(img, auto_rotate=True):
    """Uses EXIF transpose + Tesseract OSD (with fallback rotation probing) to fix vertical/sideways photos."""
    img = ImageOps.exif_transpose(img)
    if not auto_rotate:
        return img, 0

    # Step 1: Try fast Tesseract OSD (Orientation and Script Detection)
    try:
        osd = pytesseract.image_to_osd(img, config="--psm 0")
        m = re.search(r"Rotate:\s*(\d+)", osd)
        if m:
            angle = int(m.group(1))
            if angle in (90, 180, 270):
                # PIL rotate is counter-clockwise; Rotate: 90 in OSD means rotate 90° clockwise (270° CCW)
                return img.rotate(360 - angle, expand=True), angle
    except Exception:
        pass

    return img, 0


def extract_text_from_docx_or_doc(filepath):
    """Extracts text from .docx (XML + embedded images OCR) and legacy binary .doc files."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".docx":
        chunks = []
        try:
            with zipfile.ZipFile(filepath, "r") as z:
                # Extract XML paragraphs and tables
                for name in z.namelist():
                    if name.startswith("word/") and name.endswith(".xml"):
                        xml_bytes = z.read(name)
                        root = ET.fromstring(xml_bytes)
                        texts = [elem.text for elem in root.iter() if elem.text and elem.tag.endswith("}t")]
                        if texts:
                            chunks.append(" ".join(texts))
        except Exception as e:
            chunks.append(f"[DOCX Read Warning: {e}]")
        return "\n".join(chunks)

    elif ext == ".doc":
        # Lightweight native string extraction from legacy binary .doc without requiring MS Word installed
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            ascii_runs = [m.decode("ascii", errors="ignore") for m in re.findall(b"[\\x20-\\x7E\\r\\n\\t]{5,}", data)]
            utf16_runs = [m.decode("utf-16le", errors="ignore") for m in re.findall(b"(?:[\\x20-\\x7E]\\x00){5,}", data)]
            return "\n".join(ascii_runs + utf16_runs)
        except Exception as e:
            return f"[DOC Read Warning: {e}]"
    return ""


def extract_text_from_file(filepath, lang_code, adaptive_multipass=True, auto_rotate=True):
    """Extracts text from Images, PDFs, DOCX/DOC, TXT, and MD with auto-rotation for vertical scans."""
    if os.path.exists(TESSERACT_PATH):
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

    ext = os.path.splitext(filepath)[1].lower()

    if ext in (".txt", ".md"):
        for enc in ("utf-8", "utf-8-sig", "utf-16", "cp1252", "latin-1"):
            try:
                with open(filepath, "r", encoding=enc) as f:
                    return f.read()
            except Exception:
                continue
        return ""

    if ext in (".docx", ".doc"):
        return extract_text_from_docx_or_doc(filepath)

    if ext in IMAGE_EXTS:
        raw_img = Image.open(filepath)
        oriented_img, used_angle = detect_and_orient_image(raw_img, auto_rotate=auto_rotate)
        v1 = enhance_low_quality_image(oriented_img)

        txt_sparse = pytesseract.image_to_string(v1, lang=lang_code, config="--psm 11")
        base_score = _score_ocr_quality(txt_sparse)

        # Fallback Orientation Probing: If OSD missed a vertical/sideways phone photo and score is very low,
        # test 90° and 270° rotations automatically so unedited vertical camera photos still extract cleanly!
        if auto_rotate and base_score < 35:
            best_txt = txt_sparse
            best_v1 = v1
            best_score = base_score

            for test_angle in (90, 270, 180):
                if test_angle == used_angle:
                    continue
                rot_img = raw_img.rotate(360 - test_angle, expand=True)
                rot_v1 = enhance_low_quality_image(rot_img)
                rot_txt = pytesseract.image_to_string(rot_v1, lang=lang_code, config="--psm 11")
                rot_score = _score_ocr_quality(rot_txt)
                if rot_score > best_score + 15:
                    best_score = rot_score
                    best_txt = rot_txt
                    best_v1 = rot_v1
                    if best_score >= 60:
                        break

            txt_sparse = best_txt
            v1 = best_v1
            base_score = best_score

        if adaptive_multipass and base_score >= 65:
            return txt_sparse

        # Pass 2: High-contrast adaptive threshold / contrast boost for faint/blurry digits
        v2 = ImageEnhance.Contrast(v1).enhance(1.75).filter(ImageFilter.SHARPEN)
        txt_block = pytesseract.image_to_string(v2, lang="eng", config="--psm 6")
        return txt_sparse + "\n---DIGIT_PASS---\n" + txt_block

    if ext == ".pdf":
        text_chunks = []
        with pdfplumber.open(filepath) as pdf:
            for page in pdf.pages:
                txt = page.extract_text()
                if txt and len(txt.strip()) > 30:
                    text_chunks.append(txt)
                else:
                    pil_img = page.to_image(resolution=180).original
                    oriented_img, _ = detect_and_orient_image(pil_img, auto_rotate=auto_rotate)
                    v1 = enhance_low_quality_image(oriented_img)
                    text_chunks.append(pytesseract.image_to_string(v1, lang=lang_code, config="--psm 6"))
        return "\n".join(text_chunks)

    return ""


def parse_indian_entities(text, folder_name, filename, enabled_fields=None):
    """Parses Indian PII and splits Father's Name, Husband's Name, Guardian, and Address."""
    if enabled_fields is None:
        enabled_fields = {
            "Extracted_Name", "Father_Name", "Husband_Name", "Other_Guardian",
            "DOB", "PAN", "Aadhaar", "Bank_Account", "IFSC", "Phone", "PIN_Code", "Address"
        }

    if text.startswith("[SKIPPED_"):
        return {
            "Person_Folder": folder_name,
            "File_Name": filename,
            "Detected_Doc_Type": "Skipped / Filtered File",
            "Extracted_Name": "",
            "Father_Name": "",
            "Husband_Name": "",
            "Other_Guardian": "",
            "DOB": "",
            "PAN": "",
            "Aadhaar": "",
            "Aadhaar_Checksum_Verified": "",
            "Bank_Account": "",
            "IFSC": "",
            "Phone": "",
            "PIN_Code": "",
            "Address": "",
            "Father_Spouse_Guardian": "",
            "Raw_OCR_Text": text,
        }

    clean_lines = [line.strip() for line in text.splitlines() if line.strip()]
    full_text = "\n".join(clean_lines)
    upper_text = full_text.upper()

    # 1. PAN extraction
    pan_set = set()
    if "PAN" in enabled_fields:
        for token in re.findall(r"\b[A-Z0-9]{10}\b", upper_text):
            repaired = repair_pan_candidate(token)
            if repaired:
                pan_set.add(repaired)

    # 2. Aadhaar extraction with Verhoeff Checksum Validation
    aadhaar_valid = set()
    aadhaar_unverified = set()
    if "Aadhaar" in enabled_fields:
        digit_map = str.maketrans({
            "O": "0", "o": "0", "Q": "0", "D": "0",
            "I": "1", "l": "1", "|": "1",
            "Z": "2", "S": "5", "G": "6", "B": "8"
        })
        candidates = re.findall(
            r"(?<!\d)[0-9OolQD|ZSBG]{4}[\s\-\.]?[0-9OolQD|ZSBG]{4}[\s\-\.]?[0-9OolQD|ZSBG]{4}(?!\d)",
            full_text
        )
        for cand in candidates:
            norm = re.sub(r"[\s\-\.]", "", cand).translate(digit_map)
            if len(norm) == 12 and norm.isdigit() and norm[0] not in ("0", "1"):
                formatted = f"{norm[:4]} {norm[4:8]} {norm[8:]}"
                if is_valid_verhoeff(norm):
                    aadhaar_valid.add(formatted)
                else:
                    aadhaar_unverified.add(formatted)
    aadhaar_final = sorted(aadhaar_valid) if aadhaar_valid else sorted(aadhaar_unverified)

    # 3. IFSC & Bank Account Numbers
    ifsc_matches = []
    if "IFSC" in enabled_fields:
        ifsc_set = set()
        for token in re.findall(r"\b[A-Z0-9]{11}\b", upper_text):
            fixed_ifsc = repair_ifsc_candidate(token)
            if fixed_ifsc:
                ifsc_set.add(fixed_ifsc)
        ifsc_matches = sorted(ifsc_set)

    acct_matches = set()
    if "Bank_Account" in enabled_fields:
        acct_patterns = [
            r"(?:A/C|AC|ACCOUNT|ACC|ACCT|खाता|क्र)[\s\.\-:NO#Numberसंख्या]*([0-9]{9,18})\b",
            r"\b([0-9]{11,16})\b(?=.*(?:IFSC|BRANCH|CHEQUE|SAVINGS|CURRENT|PASSBOOK))",
        ]
        for pat in acct_patterns:
            for m in re.findall(pat, upper_text):
                if len(m) != 12 or not is_valid_verhoeff(m):
                    acct_matches.add(m)

    # 4. Phone, PIN Code & DOB
    phone_matches = sorted(set(re.findall(r"(?:\+91[\s\-]?)?\b[6-9]\d{9}\b", full_text))) if "Phone" in enabled_fields else []
    pin_matches = sorted(set(re.findall(r"\b[1-9]\d{5}\b", full_text))) if "PIN_Code" in enabled_fields else []
    dob_matches = []
    if "DOB" in enabled_fields:
        dob_matches = sorted(set(re.findall(
            r"\b(?:0[1-9]|[12][0-9]|3[01])[/\-\.](?:0[1-9]|1[0-2])[/\-\.](?:19\d\d|20[0-2]\d)\b",
            full_text
        )))

    # 5. Father's Name, Husband's Name, Other Guardian & Subject Name
    noise_words = {
        "INDIA", "GOVT", "GOVERNMENT", "INCOME", "TAX", "DEPARTMENT", "ADDRESS",
        "UNIQUE", "MALE", "FEMALE", "DOB", "YEAR", "BIRTH", "SIGNATURE", "CARD"
    }

    def clean_person_name(raw_str):
        cleaned = re.sub(r"[ \t]+", " ", raw_str).strip(" .,-:|/")
        words = [w for w in cleaned.split() if w.upper() not in noise_words]
        return " ".join(words)

    father_set = set()
    husband_set = set()
    guardian_set = set()

    father_patterns = [
        r"(?:S/O|D/O|F/N|Father(?:'s)?[ \t]*Name)[ \t:\.\-]+([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t\.]{2,38})",
        r"(?:पिता|पुत्र|आत्मज|आत्मजा)(?:[ \t]*का[ \t]*नाम)?[ \t:\.\-]+([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t\.]{2,38})",
    ]
    husband_patterns = [
        r"(?:W/O|H/O|Husband(?:'s)?[ \t]*Name|Spouse(?:'s)?[ \t]*Name)[ \t:\.\-]+([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t\.]{2,38})",
        r"(?:पति|पत्नी)(?:[ \t]*का[ \t]*नाम)?[ \t:\.\-]+([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t\.]{2,38})",
    ]
    guardian_patterns = [
        r"(?:C/O|G/O|Care[ \t]*Of)[ \t:\.\-]+([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t\.]{2,38})",
    ]

    for idx_line, line in enumerate(clean_lines):
        if "---DIGIT_PASS---" in line:
            break
        if "Father_Name" in enabled_fields:
            for pat in father_patterns:
                for m in re.findall(pat, line, re.IGNORECASE):
                    cn = clean_person_name(m)
                    if 3 <= len(cn) <= 38:
                        father_set.add(cn)
            # PAN card positional Father's Name (line right below "Father's Name")
            if re.search(r"Father(?:'s)?\s*Name", line, re.IGNORECASE) and idx_line + 1 < len(clean_lines):
                next_l = clean_person_name(clean_lines[idx_line + 1])
                if re.match(r"^[A-Z][A-Z \t\.]{3,35}$", next_l):
                    father_set.add(next_l)

        if "Husband_Name" in enabled_fields:
            for pat in husband_patterns:
                for m in re.findall(pat, line, re.IGNORECASE):
                    cn = clean_person_name(m)
                    if 3 <= len(cn) <= 38:
                        husband_set.add(cn)

        if "Other_Guardian" in enabled_fields:
            for pat in guardian_patterns:
                for m in re.findall(pat, line, re.IGNORECASE):
                    cn = clean_person_name(m)
                    if 3 <= len(cn) <= 38:
                        guardian_set.add(cn)

    name_candidates = set()
    if "Extracted_Name" in enabled_fields:
        for idx_line, line in enumerate(clean_lines):
            if "---DIGIT_PASS---" in line:
                break
            for m in re.findall(r"^(?:NAME|नाम|Account\s*Holder)[ \t:\.\-]+([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F \t\.]{2,36})$", line, re.IGNORECASE):
                cn = clean_person_name(m)
                if 3 <= len(cn) <= 36:
                    name_candidates.add(cn)
            if "FATHER" in line.upper() and idx_line > 0:
                prev_line = clean_person_name(clean_lines[idx_line - 1])
                if re.match(r"^[A-Z][A-Z \t\.]{3,34}$", prev_line):
                    name_candidates.add(prev_line)

    # 6. Address Extraction
    address_candidates = []
    if "Address" in enabled_fields:
        for idx_line, line in enumerate(clean_lines):
            if "---DIGIT_PASS---" in line:
                break
            m = re.search(r"(?:Address|पता)[ \t:\.\-]+(.+)", line, re.IGNORECASE)
            if m:
                addr_chunk = [m.group(1).strip()]
                for extra in clean_lines[idx_line + 1: idx_line + 3]:
                    if "---DIGIT_PASS---" in extra or len(extra) < 4:
                        break
                    addr_chunk.append(extra.strip())
                combined_addr = re.sub(r"\s+", " ", ", ".join(addr_chunk)).strip(" ,.-:")
                if len(combined_addr) >= 8:
                    address_candidates.append(combined_addr)

    # 7. Document Classification
    doc_type = "Other Document"
    if pan_set or "INCOME TAX" in upper_text or "आयकर विभाग" in full_text or "PERMANENT ACCOUNT" in upper_text:
        doc_type = "PAN Card"
    elif aadhaar_final or "UNIQUE IDENTIFICATION" in upper_text or "आधार" in full_text or "मेरा आधार" in full_text:
        doc_type = "Aadhaar Card"
    elif ifsc_matches or "CHEQUE" in upper_text or "PAY" in upper_text or "IFS" in upper_text or "RUPEES" in upper_text:
        doc_type = "Bank Cheque / Passbook"
    elif "STATEMENT" in upper_text or "OPENING BALANCE" in upper_text or "CLOSING BALANCE" in upper_text or acct_matches:
        doc_type = "Bank Statement"

    all_relations = sorted(father_set | husband_set | guardian_set)

    return {
        "Person_Folder": folder_name,
        "File_Name": filename,
        "Detected_Doc_Type": doc_type,
        "Extracted_Name": " | ".join(sorted(name_candidates)),
        "Father_Name": " | ".join(sorted(father_set)),
        "Husband_Name": " | ".join(sorted(husband_set)),
        "Other_Guardian": " | ".join(sorted(guardian_set)),
        "DOB": ", ".join(dob_matches),
        "PAN": ", ".join(sorted(pan_set)),
        "Aadhaar": ", ".join(aadhaar_final),
        "Aadhaar_Checksum_Verified": "Yes" if aadhaar_valid else ("Unverified" if aadhaar_unverified else ""),
        "Bank_Account": ", ".join(sorted(acct_matches)),
        "IFSC": ", ".join(ifsc_matches),
        "Phone": ", ".join(phone_matches),
        "PIN_Code": ", ".join(pin_matches),
        "Address": " | ".join(address_candidates[:2]),
        "Father_Spouse_Guardian": " | ".join(all_relations),
        "Raw_OCR_Text": full_text,
    }


def process_single_file_worker(task_tuple):
    """Top-level multiprocessing worker function for Dell Server / Multi-Core mode."""
    fpath, folder_name, fname, lang, adaptive_ocr, auto_rotate, enabled_fields, low_prio = task_tuple
    set_process_priority(low_priority=low_prio)
    raw_text = extract_text_from_file(fpath, lang, adaptive_multipass=adaptive_ocr, auto_rotate=auto_rotate)
    parsed = parse_indian_entities(raw_text, folder_name, fname, enabled_fields=enabled_fields)
    return parsed


def _norm_person_tokens(name_str):
    cleaned = re.sub(r"[^a-z\u0900-\u097F\s]", " ", name_str.lower())
    stop = {"mr", "mrs", "ms", "shri", "smt", "kumari", "late", "dr", "folder", "person", "doc", "docs", "root"}
    return [t for t in cleaned.split() if len(t) >= 3 and t not in stop and not t.isdigit()]


def build_connection_graph(records, output_html, only_connected=False):
    net = Network(height="800px", width="100%", bgcolor="#0d1117", font_color="#e6edf3", directed=False)
    net.barnes_hut(gravity=-3200, central_gravity=0.3, spring_length=145)
    added_nodes = set()
    added_edges = set()

    def add_node_safe(node_id, label, group, color, shape="dot", size=22):
        if node_id not in added_nodes:
            net.add_node(node_id, label=label, title=f"{group}: {label}", color=color, shape=shape, size=size)
            added_nodes.add(node_id)

    def add_edge_safe(u, v, label="", color=None, width=1.5, dashes=False):
        if u == v:
            return
        key = tuple(sorted((u, v))) + (label,)
        if key not in added_edges:
            kwargs = {"label": label, "width": width, "dashes": dashes}
            if color:
                kwargs["color"] = color
            net.add_edge(u, v, **kwargs)
            added_edges.add(key)

    folder_tokens_map = {}
    for rec in records:
        folder = rec["Person_Folder"]
        tokens = set(_norm_person_tokens(folder))
        for ext_name in rec.get("Extracted_Name", "").split("|"):
            tokens.update(_norm_person_tokens(ext_name))
        if folder not in folder_tokens_map:
            folder_tokens_map[folder] = set()
        folder_tokens_map[folder].update(tokens)

    for rec in records:
        folder = rec["Person_Folder"]
        person_key = f"FOLDER::{folder}"

        has_any_entity = any(
            rec.get(k) for k in ("PAN", "Aadhaar", "Bank_Account", "IFSC", "Phone", "PIN_Code", "Father_Spouse_Guardian")
        )
        if only_connected and not has_any_entity:
            continue

        add_node_safe(person_key, folder, "Subject Folder", "#58a6ff", shape="box", size=28)

        for field, color, prefix in [
            ("PAN", "#f78166", "PAN"),
            ("Aadhaar", "#d2a8ff", "Aadhaar"),
            ("Bank_Account", "#56d364", "Account"),
            ("IFSC", "#7ee787", "IFSC"),
            ("Phone", "#ffa657", "Phone"),
            ("PIN_Code", "#79c0ff", "PIN"),
        ]:
            values = [v.strip() for v in rec.get(field, "").split(",") if v.strip()]
            for val in values:
                val_norm = re.sub(r"\s+", "", val)
                node_id = f"{prefix}::{val_norm}"
                add_node_safe(node_id, f"{prefix}: {val}", prefix, color, size=18)
                add_edge_safe(person_key, node_id, label=prefix)

        for rel_field, rel_label in [
            ("Father_Name", "Father"),
            ("Husband_Name", "Husband"),
            ("Other_Guardian", "Guardian"),
        ]:
            rels = [r.strip() for r in rec.get(rel_field, "").split("|") if r.strip()]
            for rel in rels:
                rel_norm = re.sub(r"\s+", " ", rel.lower())
                rel_node_id = f"REL::{rel_norm}"
                add_node_safe(rel_node_id, f"{rel_label}: {rel}", rel_label, "#ff7b72", size=20)
                add_edge_safe(person_key, rel_node_id, label=rel_label)

                rel_tokens = set(_norm_person_tokens(rel))
                if rel_tokens:
                    for other_folder, other_tokens in folder_tokens_map.items():
                        if other_folder != folder and other_tokens:
                            overlap = rel_tokens.intersection(other_tokens)
                            if len(overlap) >= 2 or (len(rel_tokens) == 1 and len(overlap) == 1):
                                other_key = f"FOLDER::{other_folder}"
                                add_node_safe(other_key, other_folder, "Subject Folder", "#58a6ff", shape="box", size=28)
                                add_edge_safe(rel_node_id, other_key, label="Matched Subject", color="#ffa657", width=2.5, dashes=True)

    net.write_html(output_html)


class OSINTExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT KYC Link Mapper - v1")
        self.root.geometry("980x760")
        self.root.minsize(900, 680)
        self.root.configure(bg="#0f172a")

        self.cpu_count = os.cpu_count() or 2

        # State Variables
        self.selected_folder = tk.StringVar()
        self.hw_profile = tk.StringVar(value="Laptop (Thermal Safe - 1 Worker)")
        self.worker_threads = tk.IntVar(value=1)
        self.lang_choice = tk.StringVar(value="eng+hin")
        self.cooldown_sec = tk.DoubleVar(value=1.5)
        self.filetype_mode = tk.StringVar(value="Both (Images + Documents)")
        self.skip_patterns = tk.StringVar(value="sig, sign, seg, signature, thumb, photo, logo, icon")

        self.adaptive_ocr = tk.BooleanVar(value=True)
        self.auto_rotate = tk.BooleanVar(value=True)
        self.force_rescan = tk.BooleanVar(value=False)
        self.only_connected_graph = tk.BooleanVar(value=False)

        # Custom Field Selection Checkboxes
        self.field_vars = {
            "Extracted_Name": tk.BooleanVar(value=True),
            "Father_Name": tk.BooleanVar(value=True),
            "Husband_Name": tk.BooleanVar(value=True),
            "Other_Guardian": tk.BooleanVar(value=True),
            "DOB": tk.BooleanVar(value=True),
            "PAN": tk.BooleanVar(value=True),
            "Aadhaar": tk.BooleanVar(value=True),
            "Bank_Account": tk.BooleanVar(value=True),
            "IFSC": tk.BooleanVar(value=True),
            "Phone": tk.BooleanVar(value=True),
            "PIN_Code": tk.BooleanVar(value=True),
            "Address": tk.BooleanVar(value=True),
        }

        self.is_running = False
        self.stop_requested = False
        self.pause_event = threading.Event()
        self.pause_event.set()

        self.current_records = []
        self.last_graph_path = None
        self.last_output_dir = None
        self.last_csv_path = None
        self.last_json_path = None

        self._apply_modern_theme()
        self._build_ui()

    def _apply_modern_theme(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TProgressbar", thickness=14, troughcolor="#1e293b", background="#10b981", bordercolor="#334155")
        style.configure("TCombobox", fieldbackground="#1e293b", background="#334155", foreground="#f8fafc")

    def _build_ui(self):
        # Top Banner
        banner = tk.Frame(self.root, bg="#1e293b", padx=18, pady=10, highlightthickness=1, highlightbackground="#334155")
        banner.pack(fill="x", padx=14, pady=(12, 6))

        title_row = tk.Frame(banner, bg="#1e293b")
        title_row.pack(fill="x")
        tk.Label(
            title_row,
            text="🛡️ OSINT KYC Link Mapper (v1)",
            font=("Segoe UI", 14, "bold"),
            bg="#1e293b",
            fg="#38bdf8"
        ).pack(side="left")
        tk.Label(
            title_row,
            text=f"Detected CPU Threads: {self.cpu_count} • 100% Air-Gapped Local Engine",
            font=("Segoe UI", 9, "bold"),
            bg="#1e293b",
            fg="#94a3b8"
        ).pack(side="right", pady=4)

        tk.Label(
            banner,
            text="Auto-Rotating Vertical Photo OCR • Verhoeff Aadhaar Checksum • Images + PDF/DOCX/TXT/MD • Laptop & 80-Thread Server Profiles",
            font=("Segoe UI", 9),
            bg="#1e293b",
            fg="#cbd5e1"
        ).pack(anchor="w", pady=(2, 0))

        # Section 1: Target Directory & Filetype Filter
        sec1 = tk.LabelFrame(
            self.root, text=" 1. Target Dataset / Drive Partition & File Types ",
            font=("Segoe UI", 9, "bold"), bg="#0f172a", fg="#38bdf8", padx=12, pady=8
        )
        sec1.pack(fill="x", padx=14, pady=4)

        r1 = tk.Frame(sec1, bg="#0f172a")
        r1.pack(fill="x", pady=(0, 6))
        tk.Label(r1, text="Target Folder / Drive:", bg="#0f172a", fg="#e2e8f0", font=("Segoe UI", 9)).pack(side="left")
        tk.Entry(
            r1, textvariable=self.selected_folder, state="readonly",
            readonlybackground="#1e293b", fg="#f8fafc", font=("Segoe UI", 9), relief="flat"
        ).pack(side="left", fill="x", expand=True, padx=8, ipady=4)
        tk.Button(
            r1, text="📂 Browse Folder / Drive...", command=self.pick_folder,
            bg="#0284c7", fg="white", activebackground="#0369a1", font=("Segoe UI", 9, "bold"),
            relief="flat", padx=12, pady=3, cursor="hand2"
        ).pack(side="left")

        r2 = tk.Frame(sec1, bg="#0f172a")
        r2.pack(fill="x")
        tk.Label(r2, text="Include File Types:", bg="#0f172a", fg="#e2e8f0", font=("Segoe UI", 9)).pack(side="left")
        ttk.Combobox(
            r2, textvariable=self.filetype_mode,
            values=[
                "Both (Images + Documents)",
                "Images Only (JPG, PNG, WEBP, GIF, TIFF, BMP)",
                "Documents Only (PDF, DOCX, DOC, TXT, MD)"
            ],
            width=40, state="readonly"
        ).pack(side="left", padx=(6, 18))

        tk.Label(r2, text="Skip Filename/Ext Cues (comma-separated):", bg="#0f172a", fg="#e2e8f0", font=("Segoe UI", 9)).pack(side="left")
        tk.Entry(
            r2, textvariable=self.skip_patterns, bg="#1e293b", fg="#f8fafc",
            insertbackground="white", font=("Segoe UI", 9), relief="flat"
        ).pack(side="left", fill="x", expand=True, padx=(6, 0), ipady=3)

        # Section 2: Hardware Profile, Orientation & Thermal Controls
        sec2 = tk.LabelFrame(
            self.root, text=" 2. Hardware Profile, Vertical Photo Auto-Rotation & Thermal Controls ",
            font=("Segoe UI", 9, "bold"), bg="#0f172a", fg="#38bdf8", padx=12, pady=8
        )
        sec2.pack(fill="x", padx=14, pady=4)

        hw_row1 = tk.Frame(sec2, bg="#0f172a")
        hw_row1.pack(fill="x", pady=(0, 6))

        tk.Label(hw_row1, text="Hardware Profile:", bg="#0f172a", fg="#e2e8f0", font=("Segoe UI", 9)).pack(side="left")
        cb_hw = ttk.Combobox(
            hw_row1, textvariable=self.hw_profile,
            values=[
                "Laptop (Thermal Safe - 1 Worker)",
                "Desktop / Workstation (Balanced - 4 Workers)",
                f"Dell Server / Multi-Core Turbo ({max(2, int(self.cpu_count * 0.8))} Workers)"
            ],
            width=42, state="readonly"
        )
        cb_hw.pack(side="left", padx=(6, 14))
        cb_hw.bind("<<ComboboxSelected>>", self._on_hw_profile_change)

        tk.Label(hw_row1, text="Parallel Workers:", bg="#0f172a", fg="#e2e8f0", font=("Segoe UI", 9)).pack(side="left")
        tk.Spinbox(
            hw_row1, from_=1, to=128, textvariable=self.worker_threads,
            width=5, bg="#1e293b", fg="#f8fafc", buttonbackground="#334155", relief="flat"
        ).pack(side="left", padx=(4, 14))

        tk.Label(hw_row1, text="Cooldown (sec):", bg="#0f172a", fg="#e2e8f0", font=("Segoe UI", 9)).pack(side="left")
        tk.Spinbox(
            hw_row1, from_=0.0, to=60.0, increment=0.5, textvariable=self.cooldown_sec,
            width=5, bg="#1e293b", fg="#f8fafc", buttonbackground="#334155", relief="flat"
        ).pack(side="left", padx=(4, 14))

        tk.Label(hw_row1, text="OCR Lang:", bg="#0f172a", fg="#e2e8f0", font=("Segoe UI", 9)).pack(side="left")
        ttk.Combobox(
            hw_row1, textvariable=self.lang_choice,
            values=["eng+hin", "eng+hin+tam", "eng", "hin", "tam"],
            width=12, state="readonly"
        ).pack(side="left", padx=(4, 0))

        hw_row2 = tk.Frame(sec2, bg="#0f172a")
        hw_row2.pack(fill="x")

        for text_lbl, var in [
            ("Auto-Rotate Vertical/Sideways Camera Photos (90°/180°/270°)", self.auto_rotate),
            ("Smart Fast Mode", self.adaptive_ocr),
            ("Force Full Rescan", self.force_rescan),
            ("Graph: Connected Only", self.only_connected_graph),
        ]:
            tk.Checkbutton(
                hw_row2, text=text_lbl, variable=var,
                bg="#0f172a", fg="#cbd5e1", selectcolor="#1e293b",
                activebackground="#0f172a", activeforeground="#38bdf8", font=("Segoe UI", 9)
            ).pack(side="left", padx=(0, 14))

        # Section 3: Custom Entity Extraction Selector
        sec3 = tk.LabelFrame(
            self.root, text=" 3. Custom Entity Extraction Filter (Choose Which Fields to Extract) ",
            font=("Segoe UI", 9, "bold"), bg="#0f172a", fg="#38bdf8", padx=12, pady=6
        )
        sec3.pack(fill="x", padx=14, pady=4)

        f_top = tk.Frame(sec3, bg="#0f172a")
        f_top.pack(fill="x")

        field_labels = [
            ("Extracted_Name", "Person Name"),
            ("Father_Name", "Father's Name"),
            ("Husband_Name", "Husband's Name"),
            ("Other_Guardian", "Guardian (C/O)"),
            ("DOB", "DOB"),
            ("PAN", "PAN Number"),
            ("Aadhaar", "Aadhaar (Verhoeff)"),
            ("Bank_Account", "Bank Account"),
            ("IFSC", "IFSC Code"),
            ("Phone", "Phone No"),
            ("PIN_Code", "PIN Code"),
            ("Address", "Full Address"),
        ]

        grid_frame = tk.Frame(sec3, bg="#0f172a")
        grid_frame.pack(fill="x")
        for idx, (f_key, f_title) in enumerate(field_labels):
            r_idx = idx // 6
            c_idx = idx % 6
            tk.Checkbutton(
                grid_frame, text=f_title, variable=self.field_vars[f_key],
                bg="#0f172a", fg="#e2e8f0", selectcolor="#1e293b",
                activebackground="#0f172a", activeforeground="#38bdf8", font=("Segoe UI", 9)
            ).grid(row=r_idx, column=c_idx, sticky="w", padx=(0, 16), pady=2)

        btn_sel_frame = tk.Frame(grid_frame, bg="#0f172a")
        btn_sel_frame.grid(row=0, column=6, rowspan=2, padx=(12, 0))
        tk.Button(
            btn_sel_frame, text="Select All", command=lambda: self._set_all_fields(True),
            bg="#334155", fg="#f8fafc", relief="flat", font=("Segoe UI", 8), padx=6
        ).pack(side="top", pady=1, fill="x")
        tk.Button(
            btn_sel_frame, text="Clear All", command=lambda: self._set_all_fields(False),
            bg="#334155", fg="#f8fafc", relief="flat", font=("Segoe UI", 8), padx=6
        ).pack(side="top", pady=1, fill="x")

        # Section 4: Action Controls Bar
        ctrl_frame = tk.Frame(self.root, bg="#0f172a")
        ctrl_frame.pack(fill="x", padx=14, pady=6)

        self.btn_start = tk.Button(
            ctrl_frame, text="▶ Start Extraction", command=self.start_processing,
            bg="#10b981", fg="white", activebackground="#059669",
            font=("Segoe UI", 10, "bold"), relief="flat", padx=16, pady=6, cursor="hand2"
        )
        self.btn_start.pack(side="left")

        self.btn_pause = tk.Button(
            ctrl_frame, text="⏸ Pause & View Partial", command=self.toggle_pause,
            bg="#f59e0b", fg="white", activebackground="#d97706",
            font=("Segoe UI", 10, "bold"), relief="flat", padx=14, pady=6, state="disabled", cursor="hand2"
        )
        self.btn_pause.pack(side="left", padx=(8, 0))

        self.btn_stop = tk.Button(
            ctrl_frame, text="⏹ Stop & Save Now", command=self.stop_processing,
            bg="#ef4444", fg="white", activebackground="#dc2626",
            font=("Segoe UI", 10, "bold"), relief="flat", padx=14, pady=6, state="disabled", cursor="hand2"
        )
        self.btn_stop.pack(side="left", padx=(8, 0))

        self.btn_graph = tk.Button(
            ctrl_frame, text="🕸 Open Connection Map (So Far)", command=self.open_graph,
            bg="#6366f1", fg="white", activebackground="#4f46e5",
            font=("Segoe UI", 9, "bold"), relief="flat", padx=14, pady=6, state="disabled", cursor="hand2"
        )
        self.btn_graph.pack(side="right")

        self.btn_folder = tk.Button(
            ctrl_frame, text="📊 Open CSV / JSON Folder (So Far)", command=self.open_output_folder,
            bg="#334155", fg="white", activebackground="#475569",
            font=("Segoe UI", 9, "bold"), relief="flat", padx=14, pady=6, state="disabled", cursor="hand2"
        )
        self.btn_folder.pack(side="right", padx=8)

        # Status & Progress Bar
        status_row = tk.Frame(self.root, bg="#0f172a")
        status_row.pack(fill="x", padx=14)
        self.lbl_status = tk.Label(
            status_row, text="Ready. Select a folder or drive partition to begin.",
            bg="#0f172a", fg="#38bdf8", font=("Segoe UI", 9, "bold")
        )
        self.lbl_status.pack(side="left")
        self.lbl_counter = tk.Label(
            status_row, text="Extracted Records: 0",
            bg="#0f172a", fg="#10b981", font=("Segoe UI", 9, "bold")
        )
        self.lbl_counter.pack(side="right")

        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=14, pady=(4, 6))

        # Section 5: Scrollable Live Activity Console
        log_frame = tk.LabelFrame(
            self.root, text=" Live Scanning & Extraction Log (Scrollable) ",
            font=("Segoe UI", 9, "bold"), bg="#0f172a", fg="#38bdf8", padx=8, pady=6
        )
        log_frame.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        self.log_scroll = tk.Scrollbar(log_frame, orient="vertical")
        self.log_scroll.pack(side="right", fill="y")

        self.log_box = tk.Text(
            log_frame, height=12, font=("Consolas", 9),
            bg="#090d16", fg="#e2e8f0", insertbackground="white",
            yscrollcommand=self.log_scroll.set, relief="flat", padx=8, pady=6
        )
        self.log_box.pack(side="left", fill="both", expand=True)
        self.log_scroll.config(command=self.log_box.yview)

    def _set_all_fields(self, state):
        for var in self.field_vars.values():
            var.set(state)

    def _on_hw_profile_change(self, _event=None):
        prof = self.hw_profile.get()
        if "Laptop" in prof:
            self.worker_threads.set(1)
            self.cooldown_sec.set(1.5)
            set_process_priority(low_priority=True)
        elif "Desktop" in prof:
            self.worker_threads.set(min(4, max(2, self.cpu_count // 2)))
            self.cooldown_sec.set(0.2)
            set_process_priority(low_priority=False)
        else:
            # Dell Server / Multi-Core Turbo Profile
            recommended = max(2, int(self.cpu_count * 0.8))
            self.worker_threads.set(recommended)
            self.cooldown_sec.set(0.0)
            set_process_priority(low_priority=False)

    def log(self, msg):
        self.log_box.insert(tk.END, msg + "\n")
        self.log_box.see(tk.END)

    def pick_folder(self):
        folder = filedialog.askdirectory(title="Select Dataset Folder or Drive Partition")
        if folder:
            self.selected_folder.set(folder)

    def _flush_partial_snapshot(self, action_label="Snapshot"):
        """Immediately writes CSV, JSON, and interactive HTML Connection Map for all records extracted so far."""
        if not self.last_output_dir:
            return
        try:
            self._save_outputs(
                self.current_records,
                self.last_csv_path,
                self.last_json_path,
                self.last_graph_path,
                rebuild_graph=True
            )
            self.btn_graph.config(state="normal")
            self.btn_folder.config(state="normal")
            self.log(f"💾 [{action_label}] Exported {len(self.current_records)} records so far to CSV, JSON & Connection Map!")
        except Exception as e:
            self.log(f"⚠️ Snapshot export warning: {e}")

    def toggle_pause(self):
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.btn_pause.config(text="▶ Resume Scan", bg="#0284c7")
            self.lbl_status.config(
                text="⏸ PAUSED — CPU idle. CSV, JSON & Connection Map updated with results so far!",
                fg="#f59e0b"
            )
            self.log("⏸ Scan paused. Building partial CSV/JSON & Connection Map for immediate viewing...")
            threading.Thread(target=self._flush_partial_snapshot, args=("Paused",), daemon=True).start()
        else:
            self.pause_event.set()
            self.btn_pause.config(text="⏸ Pause & View Partial", bg="#f59e0b")
            self.lbl_status.config(text="▶ Resuming scan...", fg="#10b981")
            self.log("▶ Resuming scan...")

    def stop_processing(self):
        if not self.is_running:
            return
        self.stop_requested = True
        self.pause_event.set()  # Unblock if paused so loop can exit cleanly
        self.lbl_status.config(text="⏹ Stopping scan and saving all extracted results so far...", fg="#ef4444")
        self.log("⏹ Stop requested by user. Finalizing partial CSV, JSON & Connection Map...")

    def start_processing(self):
        base_dir = self.selected_folder.get()
        if not base_dir or not os.path.isdir(base_dir):
            messagebox.showwarning("Select Folder", "Please select your dataset folder or drive partition first.")
            return

        ft_mode = self.filetype_mode.get()
        if "Documents Only" not in ft_mode and not os.path.exists(pytesseract.pytesseract.tesseract_cmd):
            messagebox.showerror(
                "Tesseract Missing",
                "Tesseract OCR was not found at C:\\Program Files\\Tesseract-OCR\\tesseract.exe."
            )
            return

        enabled_fields = {k for k, v in self.field_vars.items() if v.get()}
        if not enabled_fields:
            messagebox.showwarning("No Fields Selected", "Please select at least one entity field to extract in Section 3.")
            return

        self.is_running = True
        self.stop_requested = False
        self.pause_event.set()

        self.btn_start.config(state="disabled")
        self.btn_pause.config(state="normal", text="⏸ Pause & View Partial", bg="#f59e0b")
        self.btn_stop.config(state="normal")
        self.log_box.delete("1.0", tk.END)

        threading.Thread(target=self._worker, args=(base_dir, enabled_fields), daemon=True).start()

    def _save_outputs(self, records, csv_path, json_path, graph_path, rebuild_graph=False):
        fieldnames = [
            "Person_Folder", "File_Name", "Detected_Doc_Type",
            "Extracted_Name", "Father_Name", "Husband_Name", "Other_Guardian",
            "DOB", "PAN", "Aadhaar", "Aadhaar_Checksum_Verified",
            "Bank_Account", "IFSC", "Phone", "PIN_Code", "Address",
            "Father_Spouse_Guardian", "Raw_OCR_Text"
        ]
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)

        if rebuild_graph:
            build_connection_graph(records, graph_path, only_connected=self.only_connected_graph.get())

    def _get_allowed_extensions(self):
        mode = self.filetype_mode.get()
        if "Images Only" in mode:
            return IMAGE_EXTS
        elif "Documents Only" in mode:
            return DOC_EXTS
        return IMAGE_EXTS + DOC_EXTS

    def _should_skip_file(self, filepath, user_skip_tokens):
        fname = os.path.basename(filepath).lower()
        stem, ext = os.path.splitext(fname)
        for tok in user_skip_tokens:
            if not tok:
                continue
            if tok.startswith(".") and ext == tok:
                return True
            if stem == tok or stem.startswith(tok + "_") or stem.endswith("_" + tok) or tok in fname:
                return True
        return False

    def _worker(self, base_dir, enabled_fields):
        out_dir = os.path.join(base_dir, "_OSINT_OUTPUT")
        os.makedirs(out_dir, exist_ok=True)
        csv_path = os.path.join(out_dir, "extracted_records.csv")
        json_path = os.path.join(out_dir, "extracted_records.json")
        graph_path = os.path.join(out_dir, "connections_graph.html")

        self.last_output_dir = out_dir
        self.last_csv_path = csv_path
        self.last_json_path = json_path
        self.last_graph_path = graph_path

        self.current_records = []
        processed_keys = set()

        if not self.force_rescan.get() and os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    self.current_records = json.load(f)
                for r in self.current_records:
                    processed_keys.add((r.get("Person_Folder"), r.get("File_Name")))
                if self.current_records:
                    self.root.after(0, lambda c=len(self.current_records): self.log(f"♻ Loaded {c} previously extracted records."))
                    self.root.after(0, lambda c=len(self.current_records): self.lbl_counter.config(text=f"Extracted Records: {c}"))
                    self.root.after(0, lambda: self.btn_graph.config(state="normal"))
                    self.root.after(0, lambda: self.btn_folder.config(state="normal"))
            except Exception:
                self.current_records = []

        allowed_exts = self._get_allowed_extensions()
        user_skip_tokens = [t.strip().lower() for t in self.skip_patterns.get().split(",") if t.strip()]

        files_to_scan = []
        skipped_count = 0

        for root_dir, dirs, files in os.walk(base_dir):
            # Prune system/junk directories in-place so full-drive scans stay fast
            dirs[:] = [d for d in dirs if d.lower() not in SYSTEM_SKIP_DIRS]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in allowed_exts:
                    full_p = os.path.join(root_dir, f)
                    if self._should_skip_file(full_p, user_skip_tokens):
                        skipped_count += 1
                        continue
                    files_to_scan.append(full_p)

        if not files_to_scan:
            self.root.after(0, lambda: messagebox.showinfo("No Matching Files", "No matching files found for the selected filter."))
            self.root.after(0, self._reset_buttons)
            return

        total_files = len(files_to_scan)
        self.root.after(0, lambda: self.progress.config(maximum=total_files, value=0))
        self.root.after(0, lambda: self.log(
            f"🔍 Found {total_files} files to scan (Skipped {skipped_count} filtered files). Starting extraction..."
        ))

        lang = self.lang_choice.get()
        workers = max(1, int(self.worker_threads.get()))
        low_prio = "Laptop" in self.hw_profile.get()
        set_process_priority(low_priority=low_prio)

        # Helper to derive meaningful Person/Subject folder name even on deep partition paths
        def get_subject_folder(fpath):
            rel_path = os.path.relpath(fpath, base_dir)
            parts = rel_path.split(os.sep)
            if len(parts) == 2:
                return parts[0]
            elif len(parts) > 2:
                return parts[-2]
            return "Root_Folder"

        # MODE A: Single-Worker Sequential Mode (Ideal for Toshiba Laptop Thermal Control)
        if workers == 1:
            for idx, fpath in enumerate(files_to_scan, 1):
                if self.stop_requested:
                    break
                self.pause_event.wait()
                if self.stop_requested:
                    break

                folder_name = get_subject_folder(fpath)
                fname = os.path.basename(fpath)

                if (folder_name, fname) in processed_keys:
                    self.root.after(0, lambda m=f"[{idx}/{total_files}] Skipping (already done): {folder_name} / {fname}": self.log(m))
                    self.root.after(0, lambda v=idx: self.progress.config(value=v))
                    continue

                self.root.after(0, lambda m=f"Scanning [{idx}/{total_files}]: {folder_name} / {fname}": self.lbl_status.config(text=m, fg="#38bdf8"))
                self.root.after(0, lambda m=f"[{idx}/{total_files}] Scanning: {folder_name} / {fname}": self.log(m))

                try:
                    raw_text = extract_text_from_file(
                        fpath, lang,
                        adaptive_multipass=self.adaptive_ocr.get(),
                        auto_rotate=self.auto_rotate.get()
                    )
                    parsed = parse_indian_entities(raw_text, folder_name, fname, enabled_fields=enabled_fields)
                    self.current_records.append(parsed)
                    processed_keys.add((folder_name, fname))

                    # Enable partial viewing buttons as soon as the very first record is extracted
                    rebuild_now = (len(self.current_records) == 1) or (idx % 10 == 0) or (idx == total_files)
                    self._save_outputs(self.current_records, csv_path, json_path, graph_path, rebuild_graph=rebuild_now)

                    self.root.after(0, lambda c=len(self.current_records): self.lbl_counter.config(text=f"Extracted Records: {c}"))
                    self.root.after(0, lambda: self.btn_graph.config(state="normal"))
                    self.root.after(0, lambda: self.btn_folder.config(state="normal"))

                    summary_hits = [
                        k for k in ("Extracted_Name", "PAN", "Aadhaar", "Bank_Account", "IFSC", "Phone", "Father_Name", "Husband_Name")
                        if parsed.get(k)
                    ]
                    if summary_hits:
                        self.root.after(0, lambda h=", ".join(summary_hits): self.log(f"   ✓ Extracted: {h}"))
                except Exception as e:
                    self.root.after(0, lambda err=str(e): self.log(f"   ! Error: {err}"))

                self.root.after(0, lambda v=idx: self.progress.config(value=v))

                try:
                    delay = float(self.cooldown_sec.get())
                except Exception:
                    delay = 1.5

                if delay > 0 and idx < total_files and not self.stop_requested:
                    self.root.after(0, lambda d=delay: self.lbl_status.config(text=f"Cooling CPU for {d}s before next file...", fg="#94a3b8"))
                    end_time = time.time() + delay
                    while time.time() < end_time:
                        if self.stop_requested:
                            break
                        self.pause_event.wait()
                        time.sleep(0.2)

        # MODE B: Multi-Process Turbo Pool (For Desktop / 80-Thread Dell Server Partition Scans)
        else:
            self.root.after(0, lambda w=workers: self.log(f"🚀 Launching Multi-Core Server Pool with {w} parallel worker processes..."))
            pending_tasks = []
            completed_count = 0

            for fpath in files_to_scan:
                folder_name = get_subject_folder(fpath)
                fname = os.path.basename(fpath)
                if (folder_name, fname) in processed_keys:
                    completed_count += 1
                    continue
                pending_tasks.append((
                    fpath, folder_name, fname, lang,
                    self.adaptive_ocr.get(), self.auto_rotate.get(),
                    enabled_fields, low_prio
                ))

            self.root.after(0, lambda v=completed_count: self.progress.config(value=v))

            with ProcessPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(process_single_file_worker, t): t for t in pending_tasks}
                for fut in as_completed(futures):
                    if self.stop_requested:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    self.pause_event.wait()

                    task_info = futures[fut]
                    folder_name, fname = task_info[1], task_info[2]
                    completed_count += 1

                    try:
                        parsed = fut.result()
                        self.current_records.append(parsed)
                        processed_keys.add((folder_name, fname))

                        # Batch checkpoint every 20 files in server mode to avoid disk lock contention
                        if len(self.current_records) == 1 or completed_count % 20 == 0 or completed_count == total_files:
                            self._save_outputs(self.current_records, csv_path, json_path, graph_path, rebuild_graph=True)
                            self.root.after(0, lambda: self.btn_graph.config(state="normal"))
                            self.root.after(0, lambda: self.btn_folder.config(state="normal"))

                        self.root.after(0, lambda c=len(self.current_records): self.lbl_counter.config(text=f"Extracted Records: {c}"))
                        self.root.after(0, lambda m=f"[{completed_count}/{total_files}] Completed: {folder_name} / {fname}": self.log(m))
                        self.root.after(0, lambda m=f"Turbo Scanning [{completed_count}/{total_files}]: {folder_name} / {fname}": self.lbl_status.config(text=m, fg="#38bdf8"))
                    except Exception as e:
                        self.root.after(0, lambda err=str(e), fn=fname: self.log(f"   ! Error on {fn}: {err}"))

                    self.root.after(0, lambda v=completed_count: self.progress.config(value=v))

        # Final Save Guarantee (whether completed normally or stopped early by user)
        try:
            self._save_outputs(self.current_records, csv_path, json_path, graph_path, rebuild_graph=True)
            self.root.after(0, lambda: self.btn_graph.config(state="normal"))
            self.root.after(0, lambda: self.btn_folder.config(state="normal"))
        except Exception as e:
            self.root.after(0, lambda err=str(e): self.log(f"Final save warning: {err}"))

        if self.stop_requested:
            self.root.after(0, lambda c=len(self.current_records): self.lbl_status.config(
                text=f"⏹ Scan stopped by user. Saved {c} extracted records to CSV, JSON & Connection Map!",
                fg="#f59e0b"
            ))
            self.root.after(0, lambda c=len(self.current_records): self.log(
                f"\n⏹ Scan stopped. All {c} records extracted so far are saved and ready in _OSINT_OUTPUT."
            ))
        else:
            self.root.after(0, lambda c=len(self.current_records): self.lbl_status.config(
                text=f"✅ Completed! {c} records saved to CSV, JSON & Interactive Connection Map.",
                fg="#10b981"
            ))
            self.root.after(0, lambda: self.log("\n✅ Done! Saved CSV, JSON, and Interactive Connection Map in _OSINT_OUTPUT."))

        self.root.after(0, self._reset_buttons)

    def _reset_buttons(self):
        self.is_running = False
        self.btn_start.config(state="normal")
        self.btn_pause.config(state="disabled", text="⏸ Pause & View Partial", bg="#f59e0b")
        self.btn_stop.config(state="disabled")

    def open_graph(self):
        if self.last_graph_path:
            if not os.path.exists(self.last_graph_path) and self.current_records:
                build_connection_graph(self.current_records, self.last_graph_path, only_connected=self.only_connected_graph.get())
            if os.path.exists(self.last_graph_path):
                webbrowser.open(f"file:///{self.last_graph_path.replace(os.sep, '/')}")

    def open_output_folder(self):
        if self.last_output_dir and os.path.exists(self.last_output_dir):
            os.startfile(self.last_output_dir)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = OSINTExtractorApp(root)
    root.mainloop()
