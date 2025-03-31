import json
import time
import os
import sys
from scanner.network.http_scanner import URLSecurityScanner
from scanner.injections.sql_injection import SQLInjectionScanner
from scanner.injections.xss_injection import XSSScanner
from scanner.authentication.broken_authentication import BrokenAuthScanner
from scanner.authentication.csrf_scanner import CSRFScanner

class SecurityScanner:
    """Class to manage and run multiple security scanners and store summary results."""

    SCAN_SUMMARY_FILE = "scan_results_json/scan_summary.json"

    def __init__(self):
        self.scan_summary = {
            "total_vulnerabilities": 0,
            "critical": 0,
            "low": 0,
            "safe": 0,
            "execution_times": {},
            "target_urls": [],
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def update_severity_counts(self, results_file):
        """Updates severity counts based on scan results."""
        if not os.path.exists(results_file):
            print(f"⚠️ {results_file} not found, skipping update.")
            return

        try:
            with open(results_file, "r") as file:
                results = json.load(file)

            if not isinstance(results, dict) or "scans" not in results:
                print(f"⚠️ Skipping {results_file}: Unexpected format.")
                return

            scanner_results = results["scans"]
            for scanner, urls in scanner_results.items():
                for url, vulnerabilities in urls.items():
                    if isinstance(url, str) and url not in self.scan_summary["target_urls"]:
                        self.scan_summary["target_urls"].append(url)

                    if not isinstance(vulnerabilities, list):
                        continue

                    for entry in vulnerabilities:
                        severity = entry.get("severity", "").strip().lower()
                        if severity == "high":
                            self.scan_summary["critical"] += 1
                        elif severity == "low":
                            self.scan_summary["low"] += 1
                        elif severity == "safe":
                            self.scan_summary["safe"] += 1

                        if severity in ["high", "low"]:
                            self.scan_summary["total_vulnerabilities"] += 1

        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"⚠️ Error processing {results_file}: {e}")

    def save_scan_summary(self):
        """Saves the scan summary to a JSON file."""
        try:
            os.makedirs(os.path.dirname(self.SCAN_SUMMARY_FILE), exist_ok=True)

            with open(self.SCAN_SUMMARY_FILE, "w") as file:
                json.dump(self.scan_summary, file, indent=4)

            print(f"\n✅ Scan summary saved to {self.SCAN_SUMMARY_FILE}")

        except Exception as e:
            print(f"\n❌ Error saving scan summary: {e}")

    def run_all_scanners(self):
        """Runs all security scanners in sequence and updates scan summary."""
        print("\n🚀 Running Security Scanners...\n")

        total_start_time = time.time()

        # Run scanners and track execution time
        scanners = {
            "HTTP Scanner": URLSecurityScanner(),
            "Broken Authentication Scanner": BrokenAuthScanner(),
            "CSRF Scanner": CSRFScanner(),
            "SQL Injection Scanner": SQLInjectionScanner(),
            "XSS Scanner": XSSScanner()
        }

        for scanner_name, scanner_instance in scanners.items():
            start_time = time.time()
            print(f"\n🔹 Running {scanner_name}...")
            scanner_instance.run()
            self.scan_summary["execution_times"][scanner_name] = time.time() - start_time

        # Update severity counts after all scans
        scan_result_files = [
            "scan_results_json/sql_injection.json",
            "scan_results_json/xss_injection.json",
            "scan_results_json/csrf.json",
            "scan_results_json/broken_authentication.json",
            "scan_results_json/http.json"
        ]

        for result_file in scan_result_files:
            self.update_severity_counts(result_file)

        # Calculate total scan time
        total_scan_time = time.time() - total_start_time
        self.scan_summary["execution_times"]["Total Scan Time"] = total_scan_time

        # Display execution times
        print("\n⏱️ **Execution Time Summary:**")
        for scanner, exec_time in self.scan_summary["execution_times"].items():
            print(f"   - {scanner}: {exec_time:.2f} seconds")

        print(f"\n🚀 **Total Scan Time:** {total_scan_time:.2f} seconds")

        # Save final scan summary
        self.save_scan_summary()


if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run_all_scanners()
