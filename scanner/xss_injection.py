import requests
import json
from datetime import datetime

# Define XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>"
]

def load_mapped_data(filename="mapped_data.json"):
    """Load mapped website data from JSON file."""
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"⚠️ Error loading JSON file: {e}")
        return None

def check_sql_vulnerabilities(filename="security_scan_results.json"):
    """Check if previous SQL Injection scan found vulnerabilities."""
    try:
        with open(filename, "r") as f:
            scan_results = json.load(f)

        if not isinstance(scan_results, dict):  # Ensure scan_results is a dictionary
            print("❌ Error: Unexpected data format in security_scan_results.json")
            return False

        for timestamp, results in scan_results.items():
            if not isinstance(results, dict):  # Ensure each entry is a dictionary
                continue

            for url, issues in results.items():
                if not isinstance(issues, list):  # Ensure issues is a list
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

def detect_xss(target_url, form):
    """Test for XSS vulnerabilities in a given form."""
    print(f"\n📌 Testing: {target_url}")

    scan_results = {}

    # Test each input field
    for param in form["inputs"]:
        print(f"🛠️  Testing parameter: {param}")

        for payload in XSS_PAYLOADS:
            print(f"🚀 Injecting: {payload}")
            data = {param: payload}

            try:
                response = requests.post(target_url, data=data, timeout=5)

                # Check vulnerability based on response content and length
                if payload in response.text or len(response.text) > 500:
                    print(f"  ⚠️ XSS Vulnerability Detected in {target_url}!")
                    print(f"  🔹 Vulnerable Parameter: {param}")
                    print(f"  🔹 Payload: {payload}\n")

                    if target_url not in scan_results:
                        scan_results[target_url] = []
                    scan_results[target_url].append({
                        "parameter": param,
                        "payload": payload,
                        "vulnerable": True
                    })

                    break  # Stop testing if a vulnerability is found

            except requests.RequestException as e:
                print(f"  ❌ Error: {e}")

    return scan_results

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

    print("\n✅ XSS scan complete! Results saved in security_scan_results.json")

def run():
    """Run the XSS scanner."""
    print("\n🚀 Scanning...\n")

    # Stop if SQL Injection is found
    if check_sql_vulnerabilities():
        return

    mapped_data = load_mapped_data()
    if not mapped_data:
        print("❌ No mapped data found. Exiting XSS scan.")
        return

    scan_results = {}

    # Iterate over discovered forms
    for page in mapped_data.get("pages", []):
        for form in page.get("forms", []): 
            if form["method"] == "POST" and form["inputs"]:
                target_url = form["action"]
                result = detect_xss(target_url, form)

                if result:
                    scan_results.update(result)

    save_results(scan_results)

# Ensure script only runs when executed directly
if __name__ == "__main__":
    run()
