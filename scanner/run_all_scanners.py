import json
import time
import os
import sys
from scanner.http_scanner import URLSecurityScanner
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss_injection import XSSScanner
from scanner.broken_authentication import BrokenAuthScanner
from scanner.csrf_scanner import CSRFScanner

class SecurityScanner:
    """Class to manage and run multiple security scanners."""

    SECURITY_SCAN_RESULTS_FILE = "security_scan_results.json"

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.venv_python = os.path.join(self.project_root, ".venv", "Scripts", "python.exe")
        self._ensure_virtual_env()
        self._update_sys_path()

    def _ensure_virtual_env(self):
        """Ensure the script runs inside the virtual environment."""
        if sys.executable.lower() != self.venv_python.lower():
            print(f"⚠️ Warning: Not using virtual environment! Restarting with: {self.venv_python}")
            os.execl(self.venv_python, self.venv_python, *sys.argv)  # Restart script in venv

    def _update_sys_path(self):
        """Add project root to sys.path if not already included."""
        if self.project_root not in sys.path:
            sys.path.append(self.project_root)
        print("🔍 Updated sys.path:", sys.path)

    def read_security_results(self):
        """Reads and returns the security scan results from the JSON file."""
        if not os.path.exists(self.SECURITY_SCAN_RESULTS_FILE):
            print("\n❌ Security results file not found.")
            return {}

        try:
            with open(self.SECURITY_SCAN_RESULTS_FILE, "r") as file:
                return json.load(file)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"\n❌ Error reading {self.SECURITY_SCAN_RESULTS_FILE}: {e}")
            return {}

    def store_scan_results(self, scan_results):
        """Store the scan results into the JSON file."""
        if not scan_results:
            print("❌ No scan results to store.")
            return

        try:
            with open(self.SECURITY_SCAN_RESULTS_FILE, "w") as file:
                json.dump(scan_results, file, indent=4)
            print("✅ Scan results saved successfully.")
        except Exception as e:
            print(f"❌ Error saving scan results: {e}")

    def check_sql_injection_results(self):
        """Checks if SQL Injection was detected in the security scan results."""
        results = self.read_security_results()

        if not isinstance(results, dict):
            return False  # Avoids crashing if file is empty

        sql_injection_results = results.get("scans", {}).get("SQLInjectionScanner", {})

        for url, vulnerabilities in sql_injection_results.items():
            if isinstance(vulnerabilities, list):
                if any(entry.get("vulnerable", False) for entry in vulnerabilities):
                    print(f"\n⚠️ SQL Injection detected on {url}! Skipping XSS Scanner.")
                    return True

        return False

    def run_all_scanners(self):
        """Runs all security scanners in sequence."""
        print("\n🚀 Running Security Scanners...\n")

        total_start_time = time.time()  # Start time for the entire scanning process
        execution_times = {}
        scans_results = {"scans": {}}

        # Run HTTP Scanner
        start_time = time.time()
        print("\n🔹 Running HTTP Scanner...")
        http_scanner = URLSecurityScanner()
        http_scanner.run()
        execution_times["HTTP Scanner"] = time.time() - start_time
        scans_results["scans"]["HTTP Scanner"] = http_scanner.scan_results

        # Run SQL Injection Scanner
        start_time = time.time()
        print("\n🔹 Running SQL Injection Scanner...")
        sql_scanner = SQLInjectionScanner()
        sql_scanner.run()
        execution_times["SQL Injection Scanner"] = time.time() - start_time
        scans_results["scans"]["SQLInjectionScanner"] = sql_scanner.scan_results

        # Allow time for results to be updated before checking
        time.sleep(3)

        # Check SQL Injection results and conditionally run XSS scanner
        sql_injection_detected = self.check_sql_injection_results()

        if not sql_injection_detected:
            start_time = time.time()
            print("\n🔹 Running XSS Scanner...")
            xss_scanner = XSSScanner()
            xss_scanner.run()
            execution_times["XSS Scanner"] = time.time() - start_time
            scans_results["scans"]["XSSScanner"] = xss_scanner.scan_results
        else:
            print("\n⏭️ Skipping XSS Scanner due to SQL Injection detection.")

        # Run CSRF Scanner
        start_time = time.time()
        print("\n🔹 Running CSRF Scanner...")
        csrf_scanner = CSRFScanner()
        csrf_scanner.run()
        execution_times["CSRF Scanner"] = time.time() - start_time
        scans_results["scans"]["CSRFScanner"] = csrf_scanner.scan_results

        # Run Broken Authentication Scanner
        start_time = time.time()
        print("\n🔹 Running Broken Authentication Scanner...")
        auth_scanner = BrokenAuthScanner()
        auth_scanner.run()
        execution_times["Broken Authentication Scanner"] = time.time() - start_time
        scans_results["scans"]["BrokenAuthScanner"] = auth_scanner.scan_results

        # Calculate total scan time (the total execution time of all scanners)
        total_scan_time = time.time() - total_start_time

        # ✅ Display execution times for each scanner
        print("\n⏱️ **Execution Time Summary:**")
        for scanner, exec_time in execution_times.items():
            print(f"   - {scanner}: {exec_time:.2f} seconds")

        # Save the execution_times to a JSON file (includes the total scan time)
        scan_results = {"execution_times": {"total_scan_time": total_scan_time}, **scans_results}
        
        # Store the results in the JSON file
        self.store_scan_results(scan_results)

        # Display total scan time once at the end
        print(f"\n🚀 **Total Scan Time:** {total_scan_time:.2f} seconds")

    @staticmethod
    def count_vulnerabilities(scan_results):
        """Count the number of vulnerabilities and categorize them by risk level."""
        vulnerability_count = {
            "vulnerabilities_found": 0,
            "high_risk_vulnerabilities": 0,
            "medium_risk_vulnerabilities": 0,
            "low_risk_vulnerabilities": 0
        }

        # Loop through the scan results and count vulnerabilities
        for scanner_name, scanner_results in scan_results.get("scans", {}).items():
            for url, vulnerabilities in scanner_results.items():
                if isinstance(vulnerabilities, list):
                    for entry in vulnerabilities:
                        if entry.get("vulnerable", False):
                            vulnerability_count["vulnerabilities_found"] += 1
                            
                            # Check for 'severity'
                            severity = entry.get("severity", "").lower()
                            if severity == "high":
                                vulnerability_count["high_risk_vulnerabilities"] += 1
                            elif severity == "medium":
                                vulnerability_count["medium_risk_vulnerabilities"] += 1
                            elif severity == "low":
                                vulnerability_count["low_risk_vulnerabilities"] += 1
                            
                elif isinstance(vulnerabilities, dict):  # For BrokenAuthScanner, where vulnerabilities are not in a list
                    for vuln_type, severity in vulnerabilities.items():
                        if isinstance(severity, str) and severity.lower() == "high":
                            vulnerability_count["vulnerabilities_found"] += 1
                            vulnerability_count["high_risk_vulnerabilities"] += 1

        return vulnerability_count



if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run_all_scanners()
