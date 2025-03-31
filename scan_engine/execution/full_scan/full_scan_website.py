import json
import os
import time
from scan_engine.scanner.crawler import WebCrawler
from scan_engine.execution.full_scan.run_all_scanners import SecurityScanner
from scan_engine.reports.scan_report.store_full_scan import FullScanResultHandler

class SecurityScanManager:
    """Class to manage security scans, read results, and store findings."""

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.scanner_results_dir = "scan_engine/reports/scan_resutls_json"

    def update_scan_results(self, scanner_name, execution_time):
        """Update the execution time for a specific scanner in its existing result JSON file."""

        # Define actual file paths for each scanner's JSON file
        scanner_file_paths = {
            "http": "scan_engine/reports/scan_results_json/http.json",
            "sql_injection": "scan_engine/reports/scan_results_json/sql_injection.json",
            "xss_injection": "scan_engine/reports/scan_results_json/xss_injection.json",
            "broken_authentication": "scan_engine/reports/scan_results_json/broken_authentication.json",
            "csrf": "scan_engine/reports/scan_results_json/csrf.json"
        }

        # Get the file path for the given scanner_name
        results_file = scanner_file_paths.get(scanner_name)

        # If scanner name is not found in the mapping
        if not results_file:
            print(f"⚠️ Scanner '{scanner_name}' does not have a predefined results file.")
            return

        # Check if the results file exists
        if not os.path.exists(results_file):
            print(f"⚠️ Skipping update: {results_file} not found.")
            return  # Exit the function without creating a new file

        try:
            # Read existing file
            with open(results_file, "r") as file:
                results = json.load(file)

            # Ensure "execution_times" key exists
            if "execution_times" not in results:
                results["execution_times"] = {}

            # Update execution time
            results["execution_times"][scanner_name] = execution_time

            # Write the updated data back to the file
            with open(results_file, "w") as file:
                json.dump(results, file, indent=4)

            print(f"✅ Updated execution time for {scanner_name} in {results_file}")

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

        results_file = "scan_engine/reports/scan_results.json"  
        scanner = SecurityScanner(results_file) 
        scanner.run_all_scanners() 

        from scan_engine.scanner.network.http_scanner import URLSecurityScanner
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

        # Directly provide paths to the result JSON files
        scan_files = [
            "scan_engine/reports/scan_results_json/http.json"
            "scan_engine/reports/scan_results_json/broken_authentication.json",
            "scan_engine/reports/scan_results_json/csrf.json",
            "scan_engine/reports/scan_results_json/sql_injection.json"
            "scan_engine/reports/scan_results_json/xss_injection.json"
        ]


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
