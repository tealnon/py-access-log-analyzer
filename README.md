Web Server Log Threat Detector
​A custom Python script built to parse HTTP access logs and automate threat detection for basic web attack vectors.

​Key Functionality
​Regex-Based Payload Detection: Analyzes log paths for SQL injection characters and keywords.

​IP Frequency Tracking: Identifies IP addresses exceeding specified brute-force attempt limits.
​Structured Output: Generates both an immediate terminal display and a clean report.json file for downstream log processing.

​Setup & Usage
​Requires Python 3.10 or higher. No external dependencies needed.

​Clone this repository to your local machine.

​Initialize and activate a local .venv environment.

​Place your target access.log in the project root directory.
​Execute python log_analysis.py in your terminal.