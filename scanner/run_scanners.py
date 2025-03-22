import json
import time
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

print("🔍 Updated sys.path:", sys.path)

from scanner import http_scanner, sql_injection, xss_injection, csrf_scanner, broken_authentication

SECURITY_SCAN_RESULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_scan_results.json")

def read_security_results():
    """Reads and returns the security scan results from JSON file."""
    if not os.path.exists(SECURITY_SCAN_RESULTS_FILE):
        print("\n❌ Security results file not found.")
        return {}

    try:
        with open(SECURITY_SCAN_RESULTS_FILE, "r") as file:
            return json.load(file)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"\n❌ Error reading {SECURITY_SCAN_RESULTS_FILE}: {e}")
        return {}

def check_sql_injection_results():
    """Checks if SQL Injection was detected in the security scan results."""
    results = read_security_results()

    if not isinstance(results, dict):
        return False  # Avoids crashing if file is empty

    for scan_data in results.values():
        if isinstance(scan_data, dict):  
            for url, vulnerabilities in scan_data.items():
                if isinstance(vulnerabilities, list):
                    if any(isinstance(entry, dict) and entry.get("vulnerable", False) for entry in vulnerabilities):
                        print(f"\n⚠️ SQL Injection detected on {url}! Skipping XSS Scanner.")
                        return True

    return False

def run_all_scanners():
    print("\n🚀 Running Security Scanners...\n")

    print("\n🔹 Running HTTP Scanner...")
    http_scanner.run()

    print("\n🔹 Running SQL Injection Scanner...")
    sql_injection.run()

    # Allow some time for results to be updated before checking
    time.sleep(3)  

    sql_injection_detected = check_sql_injection_results()

    if not sql_injection_detected:
        print("\n🔹 Running XSS Scanner...")
        xss_injection.run()
    else:
        print("\n⏭️ Skipping XSS Scanner due to SQL Injection detection.")

    print("\n🔹 Running CSRF Scanner...")
    csrf_scanner.run()

    print("\n🔹 Running Broken Authentication Scanner...")
    broken_authentication.run()

    print("\n✅ Security Scan Completed! Results saved in", SECURITY_SCAN_RESULTS_FILE)

if __name__ == "__main__":
    run_all_scanners()
