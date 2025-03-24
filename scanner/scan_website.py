import json
import os
import time
from scanner.crawler import WebCrawler
from scanner.run_scanners import SecurityScanner
from scan_report.store_scan import ScanResultHandler

class SecurityScanManager:
    """Class to manage security scans, read results, and store findings."""

    SECURITY_SCAN_RESULTS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "security_scan_results.json"))

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def update_scan_results(self, key, value):
        """Update the security_scan_results.json file without overwriting existing data."""
        try:
            if os.path.exists(self.SECURITY_SCAN_RESULTS_FILE):
                with open(self.SECURITY_SCAN_RESULTS_FILE, "r") as file:
                    results = json.load(file)
            else:
                results = {}  # Create new file if not exists

            # Ensure "execution_times" key exists
            if "execution_times" not in results:
                results["execution_times"] = {}

            # Store execution time under the key (e.g., 'crawler_time', 'scanner_time')
            results["execution_times"][key] = value

            # Save updated results
            with open(self.SECURITY_SCAN_RESULTS_FILE, "w") as file:
                json.dump(results, file, indent=4)

        except (FileNotFoundError, json.JSONDecodeError):
            print("❌ Error: Unable to update security_scan_results.json")

    def run_crawler(self):
        """Runs the web crawler and logs execution time."""
        print("🚀 Running Crawler...")
        target_url = input("Enter the target URL (e.g., http://example.com): ")
        start_time = time.time()
        WebCrawler(target_url)  # Run crawler
        crawl_time = time.time() - start_time

        print(f"\n⏱️ Crawler completed in {crawl_time:.2f} seconds")

        # Store execution time in results file
        self.update_scan_results("crawler_time", round(crawl_time, 2))
        return crawl_time

    def run_scanners(self):
        """Runs the security scanners and logs execution time."""
        print("\n🚀 Running Security Scanners...")
        start_time = time.time()

        scanner = SecurityScanner()
        scanner.run_all_scanners()  # Run all security scanners

        from scanner.http_scanner import URLSecurityScanner
        url_scanner = URLSecurityScanner()  
        url_scanner.run()

        scan_time = time.time() - start_time

        print(f"\n⏱️ Security Scanners completed in {scan_time:.2f} seconds")

        # Store execution time in results file
        self.update_scan_results("scanner_time", round(scan_time, 2))
        return scan_time

    def store_results(self):
        """Stores scan results in the database and logs execution time."""
        print("\n🚀 Storing Results...")
        start_time = time.time()

        scan_handler = ScanResultHandler(self.SECURITY_SCAN_RESULTS_FILE)
        scan_handler.store_scan_results()  

        store_time = time.time() - start_time

        print(f"\n⏱️ Results stored in {store_time:.2f} seconds")

        # Store execution time in results file
        self.update_scan_results("store_time", round(store_time, 2))
        return store_time

    def run_full_scan(self):
        """Runs the full scan process and tracks total execution time."""
        total_start_time = time.time()

        crawl_time = self.run_crawler()
        scan_time = self.run_scanners()
        print("\n✅ Security Scan Completed! Results saved in", self.SECURITY_SCAN_RESULTS_FILE)
        store_time = self.store_results()

        total_time = time.time() - total_start_time  # Calculate total execution time

        # Store total execution time in results file
        self.update_scan_results("total_scan_time", round(total_time, 2))

        print("\n✅ Security Scan Completed!")
        print(f"🔹 Crawler Time: {crawl_time:.2f} seconds")
        print(f"🔹 Scanners Time: {scan_time:.2f} seconds")
        print(f"🔹 Storing Results Time: {store_time:.2f} seconds")
        print(f"\n🚀 **Total Scan Time:** {total_time:.2f} seconds")


if __name__ == "__main__":
    manager = SecurityScanManager()
    manager.run_full_scan()
