 # Web Server Log Threat Detector

A custom Python script built to parse HTTP access logs and automate threat detection for basic web attack vectors.

## Key Features

- **Regex-Based Payload Detection**: Scans log paths for SQL injection characters and keywords.
- **IP Frequency Tracking**: Identifies IP addresses exceeding specified brute-force attempt limits.
- **Structured Output**: Generates an immediate terminal display and exports a `report.json` file.

## Setup & Usage

Requires Python 3.10 or higher. No external dependencies needed.

1. **Clone this repository:**
   ```bash
   git clone [https://github.com/tealnon/py-access-log-analyzer.git](https://github.com/tealnon/py-access-log-analyzer.git)
   cd py-access-log-analyzer
   ```

2. **Initialize and activate a local virtual environment:**
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Place your target `access.log` in the root directory and run:**
   ```bash
   python log_analysis.py
   ```