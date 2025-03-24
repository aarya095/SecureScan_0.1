import json
import os
from scanner.crawler import WebCrawler
from scanner.run_scanners import SecurityScanner
from scan_report.store_scan import ScanResultHandler

class SecurityScanManager:
    """Class to manage security scans, read results, and store findings."""

    SECURITY_SCAN_RESULTS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "security_scan_results.json"))

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def run_crawler(self):
        """Runs the web crawler."""
        print("🚀 Running Crawler...")
        target_url = input("Enter the target URL (e.g., http://example.com): ")
        WebCrawler(target_url)  # Direct function call from the crawler module

    def run_scanners(self):
        """Runs the security scanners."""
        print("\n🚀 Running Security Scanners...")
        scanner = SecurityScanner()
        scanner.run_all_scanners()  # Call the scanner function directly

        from scanner.http_scanner import URLSecurityScanner
        url_scanner = URLSecurityScanner()  # ✅ Create an instance
        url_scanner.run()

    def store_results(self):
        """Stores scan results in the database."""
        print("\n🚀 Storing Results...")
        scan_handler = ScanResultHandler(self.SECURITY_SCAN_RESULTS_FILE)
        scan_handler.store_scan_results()  # Call the function directly

    def run_full_scan(self):
        """Runs the full scan process: crawler, security scans, and result storage."""
        self.run_crawler()
        self.run_scanners()
        print("\n✅ Security Scan Completed! Results saved in", self.SECURITY_SCAN_RESULTS_FILE)
        self.store_results()


if __name__ == "__main__":
    manager = SecurityScanManager()
    manager.run_full_scan()
