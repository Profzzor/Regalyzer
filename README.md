# Regalyzer - Python Registry Forensics Toolkit

Regalyzer is a powerful, script-based toolkit for performing forensic analysis on Windows Registry hives. It is designed to be accurate, user-friendly, and extensible.

The tool automatically detects available registry hives in a target image and runs all relevant parsers.

## Features

- **Automatic Hive Detection**: Simply point Regalyzer at a Windows filesystem root, and it does the rest.
- **SAM Hive Analysis**: Detailed user account reporting from SAM hives.
- **Hybrid Parsing Engine**: Leverages `impacket` for accurate NTLM hash decryption and `python-registry-lib` for deep metadata extraction.
- **Comprehensive Reporting**: Generates detailed reports including timestamps, login counts, account status, and password hashes.

---

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/Profzzor/Regalyzer.git
    cd Regalyzer
    ```

2.  (Recommended) Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage

Provide the path to the root directory of a mounted forensic image or a copy of a Windows filesystem.

```bash
# General syntax
python regalyzer.py <path_to_image_root>

# Example
python regalyzer.py "C:\forensic_mount\C_DRIVE"
