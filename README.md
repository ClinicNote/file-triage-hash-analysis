# File Triage & Hash Analysis

## Project Overview
This project is a Python program that examines files for basic digital forensic analysis.

## Features
- Calculates SHA-256 hashes for files.
- Displays file names, extensions, sizes and modification dates.
- Compares file hashes against a reference list.
- Labels files as Known or Unknown.
- Detects duplicate files.
- Saves the results in `triage_report.txt`.

## Requirements
- Python 3 installed.
- No additional Python packages required.

## How to Run
1. Open Command Prompt in the project folder.
2. Enter `py main.py`.
3. When asked for a folder path, enter `samples`.
4. Read the results displayed in Command Prompt.
5. Open `triage_report.txt` to view the saved report.

## Project Files
- `main.py` — the Python program.
- `samples/` — sample files used for testing.
- `hashes_reference.csv` — reference hashes used for comparison.
- `triage_report.txt` — generated analysis report.

## Testing
The program was tested using sample text and binary files. It identified known and unknown hashes, detected duplicate files and generated a text report.