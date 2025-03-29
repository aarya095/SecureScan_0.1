import json
import os
import time
from scanner.crawler import WebCrawler
from scanner.run_selected_scanners import CustomSecurityScanner
from scan_report.store_custom_scan import CustomScanResultHandler

class SecurityCustomScanManager:
    """Manages security scans, stores findings, and provides selection menus."""

    SECURITY_SCAN_RESULTS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "security_scan_results.json"))

    SCANNERS = {
        1: "SQL-Injection",
        2: "XSS-Injection",
        3: "Broken Authentication",  # ✅ Fixed name
        4: "CSRF Scanner"  # ✅ Fixed name
    }

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def update_scan_results(self, key, value):
        """Update security_scan_results.json without overwriting existing data."""
        try:
            results = {}
            if os.path.exists(self.SECURITY_SCAN_RESULTS_FILE):
                with open(self.SECURITY_SCAN_RESULTS_FILE, "r") as file:
                    try:
                        results = json.load(file)
                    except json.JSONDecodeError:
                        results = {}

            if "execution_times" not in results:
                results["execution_times"] = {}

            results["execution_times"][key] = value

            with open(self.SECURITY_SCAN_RESULTS_FILE, "w") as file:
                json.dump(results, file, indent=4)

        except Exception as e:
            print(f"❌ Error updating scan results file: {e}")

    def run_crawler(self, target_url):
        """Runs the web crawler and logs execution time."""
        print("🚀 Running Crawler...")
        start_time = time.time()

        crawler = WebCrawler(target_url)  # ✅ Create instance
        crawler.crawl()  # ✅ Run the crawler

        crawl_time = time.time() - start_time
        print(f"\n⏱️ Crawler completed in {crawl_time:.2f} seconds")

        self.update_scan_results("crawler_time", round(crawl_time, 2))
        return crawl_time

    def run_scanners(self, target_url, selected_scanners):
        """Runs selected security scanners and logs execution time."""
        print("\n🚀 Running Selected Security Scanners...")
        start_time = time.time()

        scanner = CustomSecurityScanner()
        scanner.run_custom_scan(selected_scanners, target_url)

        scan_time = time.time() - start_time
        print(f"\n⏱️ Security Scanners completed in {scan_time:.2f} seconds")

        self.update_scan_results("scanner_time", round(scan_time, 2))
        return scan_time

    def store_results(self):
        """Stores scan results in the database and logs execution time."""
        print("\n🚀 Storing Results...")
        start_time = time.time()

        scan_handler = CustomScanResultHandler(self.SECURITY_SCAN_RESULTS_FILE)
        scan_handler.store_custom_scan_results()

        store_time = time.time() - start_time
        print(f"\n⏱️ Results stored in {store_time:.2f} seconds")

        self.update_scan_results("store_time", round(store_time, 2))
        return store_time

    def select_scanners_menu(self):
        """Displays a menu for scanner selection and returns the selected scanners."""
        print("\n🔹 **Select Security Scanners to Run** 🔹")
        for num, scanner in self.SCANNERS.items():
            print(f"[{num}] {scanner}")

        while True:
            try:
                user_input = input("\nEnter the numbers of the scanners you want to run (comma-separated): ")
                selected_numbers = [int(num.strip()) for num in user_input.split(",")]

                selected_scanners = [self.SCANNERS[num] for num in selected_numbers if num in self.SCANNERS]

                if not selected_scanners:
                    print("❌ Invalid selection. Please select at least one valid scanner.")
                else:
                    return selected_scanners

            except ValueError:
                print("❌ Invalid input. Please enter numbers only (e.g., 1,2,3).")

    def run_custom_scan(self):
        """Runs the full scan process and tracks execution time."""
        total_start_time = time.time()

        # ✅ Get user input
        target_url = input("Enter the target URL (e.g., http://example.com): ").strip()
        selected_scanners = self.select_scanners_menu()  # 🎯 Use menu to get scanner selection

        crawl_time = self.run_crawler(target_url)
        scan_time = self.run_scanners(target_url, selected_scanners)

        print("\n✅ Security Scan Completed! Results saved in", self.SECURITY_SCAN_RESULTS_FILE)
        store_time = self.store_results()

        total_time = time.time() - total_start_time
        self.update_scan_results("total_scan_time", round(total_time, 2))

        print("\n✅ Security Scan Completed!")
        print(f"🔹 Crawler Time: {crawl_time:.2f} seconds")
        print(f"🔹 Scanners Time: {scan_time:.2f} seconds")
        print(f"🔹 Storing Results Time: {store_time:.2f} seconds")
        print(f"\n🚀 **Total Scan Time:** {total_time:.2f} seconds")


if __name__ == "__main__":
    manager = SecurityCustomScanManager()
    manager.run_custom_scan()
