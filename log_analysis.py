import json
import re
from collections import defaultdict
from typing import Any, Dict, List
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\['
    r'(?P<timestamp>[^\]]+)\]\s+"(?P<method>\w+)\s+'
    r'(?P<path>\S+)\s+HTTP/[0-9\.]+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)'
)

# Common SQL Injection signature patterns (URL-encoded and decoded)
SQLI_PATTERNS = [
    re.compile(r"(%27|')", re.IGNORECASE),
    re.compile(r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bDROP\b)", re.IGNORECASE),
    re.compile(r"(%20OR%20|\bOR\b\s+[\d\w]+=[\d\w]+|1=1)", re.IGNORECASE),
    re.compile(r"(--|%23|\/\*|\*\/)", re.IGNORECASE),
]


def parse_and_analyze(log_file_path: str, brute_force_threshold: int = 5) -> Dict[str, Any]:
    """Parses raw web server logs to detect SQLi attempts and brute-force logins."""
    sqli_alerts: List[Dict[str, str]] = []
    failed_login_counts: Dict[str, int] = defaultdict(int)
    total_parsed = 0

    with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            match = LOG_PATTERN.search(line)
            if not match:
                continue

            total_parsed += 1
            log_data = match.groupdict()
            ip = log_data["ip"]
            path = log_data["path"]
            status = int(log_data["status"])

            # 1. Detect SQL Injection in request paths / query strings
            for pattern in SQLI_PATTERNS:
                if pattern.search(path):
                    sqli_alerts.append({
                        "ip": ip,
                        "timestamp": log_data["timestamp"],
                        "method": log_data["method"],
                        "path": path,
                    })
                    break

            # 2. Track failed login attempts for brute-force detection
            if status == 401 or ("/login" in path and status in (401, 403)):
                failed_login_counts[ip] += 1

    # Filter IPs exceeding brute force threshold
    brute_force_suspects = {
        ip: count for ip, count in failed_login_counts.items() if count >= brute_force_threshold
    }

    return {
        "summary": {
            "total_logs_analyzed": total_parsed,
            "sqli_incidents_found": len(sqli_alerts),
            "brute_force_ips_flagged": len(brute_force_suspects),
        },
        "brute_force_suspects": brute_force_suspects,
        "sqli_alerts": sqli_alerts,
    }


def print_report(results: Dict[str, Any]) -> None:
    """Prints a structured summary report to the terminal."""
    summary = results["summary"]
    print("=" * 60)
    print(" SECURITY LOG ANALYSIS SUMMARY REPORT ")
    print("=" * 60)
    print(f"Total Log Entries Processed: {summary['total_logs_analyzed']}")
    print(f"SQL Injection Attempts Detected: {summary['sqli_incidents_found']}")
    print(f"Brute-Force Attackers Flagged: {summary['brute_force_ips_flagged']}")
    print("-" * 60)

    if results["brute_force_suspects"]:
        print("\n[!] SUSPECTED BRUTE-FORCE ATTACKS:")
        for ip, count in results["brute_force_suspects"].items():
            print(f" - IP: {ip:<15} Failed Attempts: {count}")

    if results["sqli_alerts"]:
        print("\n[!] SQL INJECTION ATTEMPTS DETECTED:")
        for alert in results["sqli_alerts"]:
            print(f" - [{alert['timestamp']}] IP: {alert['ip']}")
            print(f" Payload: {alert['path']}")

    print("\n" + "=" * 60)
    
if __name__ == "__main__":
    #Example usage:
    results = parse_and_analyze("access.log", brute_force_threshold=5)
    print_report(results)

    # To export as JSON report for SIEM integration:
    with open("report.json", "w") as out:
        json.dump(results, out, indent=4)
    pass