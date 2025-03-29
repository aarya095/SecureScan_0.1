import json
import time
import os
import sys
from scanner.http_scanner import URLSecurityScanner
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss_injection import XSSScanner
from scanner.broken_authentication import BrokenAuthScanner
from scanner.csrf_scanner import CSRFScanner

class CustomSecurityScanner:
    """Class to manage and run custom-selected security scanners."""

    SECURITY_SCAN_RESULTS_FILE = "security_scan_results.json"

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self._update_sys_path()

    def _update_sys_path(self):
        """Ensure the project root is in sys.path."""
        if self.project_root not in sys.path:
            sys.path.append(self.project_root)

    def store_scan_results(self, scan_results):
        """Store the scan results into the JSON file."""
        try:
            with open(self.SECURITY_SCAN_RESULTS_FILE, "w") as file:
                json.dump(scan_results, file, indent=4)
        except Exception as e:
            print(f"❌ Error saving scan results: {e}")

    def run_custom_scan(self, selected_scanners, url):
        """Runs only the selected security scanners."""
        scans_results = {"scans": {}}
        scanner_mapping = {
            "Http Scanner": URLSecurityScanner,
            "SQL-Injection": SQLInjectionScanner,
            "XSS-Injection": XSSScanner,
            "Broken Authentication": BrokenAuthScanner,
            "CSRF Scanner": CSRFScanner
        }

        for scanner_name in selected_scanners:
            if scanner_name in scanner_mapping:
                scanner_instance = scanner_mapping[scanner_name]()
                scanner_instance.run()
                scans_results["scans"][scanner_name] = scanner_instance.scan_results

        self.store_scan_results(scans_results)
        return scans_results
    
    
