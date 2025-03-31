import json
import time
import os
import sys
from scan_engine.scanner.network.http_scanner import URLSecurityScanner
from scan_engine.scanner.injections.sql_injection import SQLInjectionScanner
from scan_engine.scanner.injections.xss_injection import XSSScanner
from scan_engine.scanner.authentication.broken_authentication import BrokenAuthScanner
from scan_engine.scanner.authentication.csrf_scanner import CSRFScanner

class SecurityScanner:
    """Class to manage and run multiple security scanners and store summary results."""

    SCAN_SUMMARY_FILE = "scan_engine/reports/final_report/scan_summary.json"

    def __init__(self, results_file):
        self.results_file = results_file
        self.scan_summary = {
            "execution_times": {},
            "target_urls": [],
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def update_severity_counts(self, results_file):
        """Updates the list of target URLs from scan results."""
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
                for url in urls.keys():
                    if isinstance(url, str) and url not in self.scan_summary["target_urls"]:
                        self.scan_summary["target_urls"].append(url)

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

        # Track execution times
        execution_times = {}

        # Run HTTP Scanner
        start_time = time.time()
        print("\n🔹 Running HTTP Scanner...")
        http_scanner = URLSecurityScanner()
        http_scanner.run()
        execution_times["HTTP Scanner"] = time.time() - start_time

        # Run Broken Authentication Scanner
        start_time = time.time()
        print("\n🔹 Running Broken Authentication Scanner...")
        auth_scanner = BrokenAuthScanner()
        auth_scanner.run()
        execution_times["Broken Authentication Scanner"] = time.time() - start_time

        # Run CSRF Scanner
        start_time = time.time()
        print("\n🔹 Running CSRF Scanner...")
        csrf_scanner = CSRFScanner()
        csrf_scanner.run()
        execution_times["CSRF Scanner"] = time.time() - start_time

        # ✅ Run SQL Injection Scanner and check if SQL Injection is detected
        start_time = time.time()
        print("\n🔹 Running SQL Injection Scanner...")
        sql_scanner = SQLInjectionScanner()
        sql_injection_detected = sql_scanner.run()  # ✅ Check if SQLi is found
        execution_times["SQL Injection Scanner"] = time.time() - start_time

        # ✅ If SQL Injection is found, exit immediately
        if sql_injection_detected:
            print("\n⏹️ **SQL Injection Detected! Exiting process to prevent further risks.**")
            sys.exit(1)

        # Run XSS Scanner only if SQL Injection was NOT detected
        start_time = time.time()
        print("\n🔹 Running XSS Scanner...")
        xss_scanner = XSSScanner()
        xss_scanner.run()
        execution_times["XSS Scanner"] = time.time() - start_time

        # Update target URLs after all scans
        scan_result_files = [
            "scan_engine/reports/scan_results_json/sql_injection.json",
            "scan_engine/reports/scan_results_json/xss_injection.json",
            "scan_engine/reports/scan_results_json/csrf.json",
            "scan_engine/reports/scan_results_json/broken_authentication.json",
            "scan_engine/reports/scan_results_json/http.json"
        ]

        for result_file in scan_result_files:
            self.update_severity_counts(self.result_file)

        # Calculate total scan time
        total_scan_time = time.time() - total_start_time
        execution_times["Total Scan Time"] = total_scan_time

        # Store execution times in scan summary
        self.scan_summary["execution_times"] = execution_times

        # ✅ Display execution times
        print("\n⏱️ **Execution Time Summary:**")
        for scanner, exec_time in execution_times.items():
            print(f"   - {scanner}: {exec_time:.2f} seconds")

        print(f"\n🚀 **Total Scan Time:** {total_scan_time:.2f} seconds")

        # Save final scan summary
        print("Execution times stored:", execution_times)

        self.save_scan_summary()


if __name__ == "__main__":
    results_file = "scan_engine/reports/scan_results.json" 
    scanner = SecurityScanner(results_file) 
    scanner.run_all_scanners()
