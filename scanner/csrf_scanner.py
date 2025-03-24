import requests
from bs4 import BeautifulSoup
import urllib.parse
import json
from datetime import datetime


class CSRFScanner:
    """A class to scan websites for CSRF vulnerabilities."""

    TOKEN_NAMES = ["csrf", "token", "authenticity_token", "_csrf"]

    def __init__(self, mapped_data_file="mapped_data.json", results_file="security_scan_results.json"):
        self.mapped_data_file = mapped_data_file
        self.results_file = results_file
        self.scan_results = {}

    def load_mapped_data(self):
        """Load mapped website data from a JSON file."""
        try:
            with open(self.mapped_data_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"⚠️ Error loading JSON file: {e}")
            return None

    def get_forms(self, url):
        """Extract all forms from a webpage."""
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.find_all("form")
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching {url}: {e}")
            return []

    def check_csrf_token(self, form):
        """Check if the form contains a CSRF token."""
        inputs = form.find_all("input")
        for field in inputs:
            if field.get("type") == "hidden":
                name = field.get("name", "").lower()
                if any(token in name for token in self.TOKEN_NAMES):
                    return True  # CSRF token found
        return False  # No CSRF token found

    def test_csrf_vulnerability(self, url):
        """Test if a website is vulnerable to CSRF attacks."""
        print(f"\n🔍 Scanning {url} for CSRF vulnerabilities...\n")

        forms = self.get_forms(url)
        if not forms:
            print("❌ No forms found on the page.")
            return None

        results = []

        for i, form in enumerate(forms, start=1):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            full_action = urllib.parse.urljoin(url, action)

            print(f"📝 Form {i}: Method = {method.upper()}, Action = {full_action}")

            if method == "post":
                has_token = self.check_csrf_token(form)
                status = "Protected" if has_token else "Vulnerable"
                print(f"✅ CSRF Protection Detected." if has_token else f"⚠️ WARNING: CSRF Token NOT found!")

                results.append({
                    "form_number": i,
                    "method": method.upper(),
                    "action": full_action,
                    "csrf_protection": has_token
                })
            else:
                print("ℹ️ This form uses GET request, CSRF is not applicable.")

        return results

    def save_scan_results(self):
        """Save scan results to a JSON file without overwriting previous results."""
        try:
            with open(self.results_file, "r") as f:
                previous_results = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            previous_results = {}

        # Ensure all results are stored under a common structure
        if "scans" not in previous_results:
            previous_results["scans"] = {}

        # Add current scan results under the scanner's name
        previous_results["scans"][self.__class__.__name__] = self.scan_results  # Using self.results now

        with open(self.results_file, "w") as f:
            json.dump(previous_results, f, indent=4)

        print("\n✅ CSRF scan complete! Results saved in security_scan_results.json")

    def run(self):
        """Run the CSRF scanner."""
        print("\n🚀 Scanning...\n")

        mapped_data = self.load_mapped_data()
        if not mapped_data:
            print("❌ No mapped data found. Exiting CSRF scan.")
            return

        for page in mapped_data.get("pages", []):
            url = page.get("url")
            if not url:
                continue  # Skip if no URL found

            csrf_results = self.test_csrf_vulnerability(url)
            if csrf_results:
                self.scan_results[url] = csrf_results

        self.save_scan_results()


if __name__ == "__main__":
    scanner = CSRFScanner()
    scanner.run()
