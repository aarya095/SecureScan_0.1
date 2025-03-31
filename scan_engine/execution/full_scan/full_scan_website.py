import json
import os
import time
from scanner.crawler import WebCrawler
from scan_engine.execution.full_scan.run_all_scanners import SecurityScanner
from scan_report.store_full_scan import FullScanResultHandler

class SecurityScanManager:
    """Class to manage security scans, read results, and store findings."""

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.scanner_results_dir = os.path.join(self.project_root, "scan_results_json")  # Directory for scanner outputs

    def update_scan_results(self, scanner_name, execution_time):
        """Update the execution time for a specific scanner in its result JSON file."""
        results_file = os.path.join(self.scanner_results_dir, f"{scanner_name}.json")

        try:
            if os.path.exists(results_file):
                with open(results_file, "r") as file:
                    results = json.load(file)
            else:
                results = {}

            # Ensure "execution_times" key exists
            if "execution_times" not in results:
                results["execution_times"] = {}

            # Store execution time
            results["execution_times"][scanner_name] = execution_time

            # Save updated results
            with open(results_file, "w") as file:
                json.dump(results, file, indent=4)

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"❌ Error updating {results_file}: {e}")

    def run_crawler(self):
        """Runs the web crawler and logs execution time."""
        print("🚀 Running Crawler...")
        target_url = input("Enter the target URL (e.g., http://example.com): ")
        start_time = time.time()
        WebCrawler(target_url)  # Run crawler
        crawl_time = time.time() - start_time

        print(f"\n⏱️ Crawler completed in {crawl_time:.2f} seconds")

        # Store execution time in crawler_results.json
        self.update_scan_results("crawler", round(crawl_time, 2))
        return crawl_time

    def run_scanners(self):
        """Runs all security scanners and logs execution time for each."""
        print("\n🚀 Running Security Scanners...")
        start_time = time.time()

        scanner = SecurityScanner()
        scanner.run_all_scanners()  # Run all security scanners

        from scanner.network.http_scanner import URLSecurityScanner
        url_scanner = URLSecurityScanner()
        url_scanner.run()

        scan_time = time.time() - start_time

        print(f"\n⏱️ Security Scanners completed in {scan_time:.2f} seconds")

        # Store execution time in scanner_results.json
        self.update_scan_results("scanner", round(scan_time, 2))
        return scan_time

    def store_results(self):
        """Stores scan results from all JSON files in the database and logs execution time."""
        print("\n🚀 Storing Results...")
        start_time = time.time()

        scan_files = [os.path.join(self.scanner_results_dir, file) for file in os.listdir(self.scanner_results_dir) if file.endswith("_results.json")]

        for scan_file in scan_files:
            scan_handler = FullScanResultHandler(scan_file)
            scan_handler.store_scan_results()  

        store_time = time.time() - start_time

        print(f"\n⏱️ Results stored in {store_time:.2f} seconds")

        # Store execution time in a general storage_results.json
        self.update_scan_results("store", round(store_time, 2))
        return store_time

    def run_full_scan(self):
        """Runs the full scan process and tracks total execution time."""
        total_start_time = time.time()

        crawl_time = self.run_crawler()
        scan_time = self.run_scanners()
        print("\n✅ Security Scan Completed! Results saved in individual scanner files")
        store_time = self.store_results()

        total_time = time.time() - total_start_time  # Calculate total execution time

        # Store total execution time
        self.update_scan_results("total_scan", round(total_time, 2))

        print("\n✅ Security Scan Completed!")
        print(f"🔹 Crawler Time: {crawl_time:.2f} seconds")
        print(f"🔹 Scanners Time: {scan_time:.2f} seconds")
        print(f"🔹 Storing Results Time: {store_time:.2f} seconds")
        print(f"\n🚀 **Total Scan Time:** {total_time:.2f} seconds")


if __name__ == "__main__":
    manager = SecurityScanManager()
    manager.run_full_scan()
