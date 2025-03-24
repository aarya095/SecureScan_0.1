import requests
import json
from datetime import datetime


class XSSScanner:
    """Class to scan for XSS vulnerabilities in web forms."""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>"
    ]

    def __init__(self, mapped_data_file="mapped_data.json", results_file="security_scan_results.json"):
        self.mapped_data_file = mapped_data_file
        self.results_file = results_file
        self.scan_results = {}

    def load_mapped_data(self):
        """Load mapped website data from JSON file."""
        try:
            with open(self.mapped_data_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"⚠️ Error loading JSON file: {e}")
            return None

    def check_sql_vulnerabilities(self):
        """Check if previous SQL Injection scan found vulnerabilities."""
        try:
            with open(self.results_file, "r") as f:
                scan_results = json.load(f)

            if not isinstance(scan_results, dict):
                print("❌ Error: Unexpected data format in security_scan_results.json")
                return False

            for timestamp, results in scan_results.items():
                if not isinstance(results, dict):
                    continue

                for url, issues in results.items():
                    if not isinstance(issues, list):
                        continue

                    for issue in issues:
                        if isinstance(issue, dict) and issue.get("vulnerable", False):
                            print(f"❌ SQL Injection detected at {url}. Skipping XSS scan.")
                            return True

        except FileNotFoundError:
            print("❌ Error: security_scan_results.json not found.")
        except json.JSONDecodeError:
            print("❌ Error: security_scan_results.json is corrupted or not in valid JSON format.")

        return False

    def detect_xss(self, target_url, form):
        """Test for XSS vulnerabilities in a given form."""
        print(f"\n📌 Testing: {target_url}")

        for param in form["inputs"]:
            print(f"🛠️  Testing parameter: {param}")

            for payload in self.XSS_PAYLOADS:
                print(f"🚀 Injecting: {payload}")
                data = {param: payload}

                try:
                    response = requests.post(target_url, data=data, timeout=5)

                    if payload in response.text or len(response.text) > 500:
                        print(f"  ⚠️ XSS Vulnerability Detected in {target_url}!")
                        print(f"  🔹 Vulnerable Parameter: {param}")
                        print(f"  🔹 Payload: {payload}\n")

                        if target_url not in self.scan_results:
                            self.scan_results[target_url] = []
                        self.scan_results[target_url].append({
                            "parameter": param,
                            "payload": payload,
                            "vulnerable": True
                        })

                        break  # Stop testing if a vulnerability is found

                except requests.RequestException as e:
                    print(f"  ❌ Error: {e}")

    def save_results(self):
        """Save scan results to a JSON file."""
        try:
            with open(self.results_file, "r") as f:
                previous_results = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            previous_results = {}

        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        previous_results[current_time] = self.scan_results

        with open(self.results_file, "w") as f:
            json.dump(previous_results, f, indent=4)

        print("\n✅ XSS scan complete! Results saved in security_scan_results.json")

    def run(self):
        """Run the XSS scanner."""
        print("\n🚀 Scanning for XSS vulnerabilities...\n")

        if self.check_sql_vulnerabilities():
            return

        mapped_data = self.load_mapped_data()
        if not mapped_data:
            print("❌ No mapped data found. Exiting XSS scan.")
            return

        for page in mapped_data.get("pages", []):
            for form in page.get("forms", []):
                if form["method"] == "POST" and form["inputs"]:
                    self.detect_xss(form["action"], form)

        self.save_results()


if __name__ == "__main__":
    scanner = XSSScanner()
    scanner.run()
