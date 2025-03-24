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

    def check_sql_injection_results(self):
        """Checks if SQL Injection was detected in the security scan results."""
        results = self.read_security_results()

        if not isinstance(results, dict):
            return False  # Avoids crashing if file is empty

        # ✅ Ensure we're checking the correct scanner results
        sql_injection_results = results.get("scans", {}).get("SQLInjectionScanner", {})

        for url, vulnerabilities in sql_injection_results.items():
            if isinstance(vulnerabilities, list):
                if any(entry.get("vulnerable", False) for entry in vulnerabilities):
                    print(f"\n⚠️ SQL Injection detected on {url}! Skipping XSS Scanner.")
                    return True

        return False


        return False
    def run_all_scanners(self):
        """Runs all security scanners in sequence."""
        print("\n🚀 Running Security Scanners...\n")

        total_start_time = time.time()
        execution_times = {}

        start_time = time.time()
        print("\n🔹 Running HTTP Scanner...")
        http_scanner = URLSecurityScanner()  # ✅ Create an instance
        http_scanner.run()  # ✅ Call run() on the instance
        execution_times["HTTP Scanner"] = time.time() - start_time

        start_time = time.time()
        print("\n🔹 Running SQL Injection Scanner...")
        sql_scanner = SQLInjectionScanner()  # ✅ Create an instance
        sql_scanner.run()  # ✅ Call run() on the instance
        execution_times["SQL Injection Scanner"] = time.time() - start_time

        # Allow time for results to be updated before checking
        time.sleep(3)

        sql_injection_detected = self.check_sql_injection_results()

        if not sql_injection_detected:
            start_time = time.time()
            print("\n🔹 Running XSS Scanner...")
            xss_scanner = XSSScanner()  # ✅ Create an instance
            xss_scanner.run()  # ✅ Call run() on the instance
            execution_times["XSS Scanner"] = time.time() - start_time
        else:
            print("\n⏭️ Skipping XSS Scanner due to SQL Injection detection.")

        start_time = time.time()
        print("\n🔹 Running CSRF Scanner...")
        csrf_scanner = CSRFScanner()  # ✅ Create an instance
        csrf_scanner.run()  # ✅ Call run() on the instance
        execution_times["CSRF Scanner"] = time.time() - start_time

        start_time = time.time()
        print("\n🔹 Running Broken Authentication Scanner...")
        auth_scanner = BrokenAuthScanner()  # ✅ Create an instance
        auth_scanner.run()  # ✅ Call run() on the instance
        execution_times["Broken Authentication Scanner"] = time.time() - start_time

        total_time = time.time() - total_start_time

        # ✅ Display execution times for each scanner
        print("\n⏱️ **Execution Time Summary:**")
        for scanner, exec_time in execution_times.items():
            print(f"   - {scanner}: {exec_time:.2f} seconds")

if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run_all_scanners()
