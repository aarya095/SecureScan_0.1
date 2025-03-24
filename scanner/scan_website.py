import subprocess
import json
import os


class SecurityScanManager:
    """Class to manage security scans, read results, and store findings."""

    SECURITY_SCAN_RESULTS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "security_scan_results.json"))

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

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

    def run_crawler(self):
        """Runs the web crawler to gather target URLs."""
        print("🚀 Running Crawler...")
        try:
            subprocess.run(["python", os.path.join(self.project_root, "scanner", "crawler.py")], check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ Error running crawler: {e}")

    def run_scanners(self):
        """Runs the security scanners."""
        print("\n🚀 Running Security Scanners...")
        try:
            subprocess.run(["python", os.path.join(self.project_root, "scanner", "run_scanners.py")], check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ Error running security scanners: {e}")

    def store_results(self):
        """Runs the script to store security scan results."""
        print("\n🚀 Storing Results...")
        try:
            subprocess.run(["python", os.path.join(self.project_root, "scan_report", "store_scan.py")], check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ Error storing scan results: {e}")

    def run_full_scan(self):
        """Runs the full scan process: crawler, security scans, and result storage."""
        self.run_crawler()
        self.run_scanners()
        print("\n✅ Security Scan Completed! Results saved in", self.SECURITY_SCAN_RESULTS_FILE)
        self.store_results()


if __name__ == "__main__":
    manager = SecurityScanManager()
    manager.run_full_scan()
