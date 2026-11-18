@echo off
title OSINT KYC Link Mapper (v1)
echo Checking lightweight dependencies...
python -m pip install --quiet --upgrade pytesseract pillow pdfplumber pyvis
echo Launching v1 GUI...
start "" pythonw "%~dp0osint_gui.pyw"
exit
