import requests
from bs4 import BeautifulSoup
import urllib.parse
import json
from datetime import datetime

# Load mapped website data
with open("mapped_data.json", "r") as f:
    mapped_data = json.load(f)

def get_forms(url):
    """Extract all forms from a webpage."""
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching {url}: {e}")
        return []

def check_csrf_token(form):
    """Check if the form contains a CSRF token."""
    token_names = ["csrf", "token", "authenticity_token", "_csrf"]
    
    # Find all input fields
    inputs = form.find_all("input")
    
    for field in inputs:
        if field.get("type") == "hidden":
            name = field.get("name", "").lower()
            if any(token in name for token in token_names):
                return True  # CSRF token found
    return False  # No CSRF token found

def test_csrf_vulnerability(url):
    """Test if a website is vulnerable to CSRF attacks."""
    print(f"\n🔍 Scanning {url} for CSRF vulnerabilities...\n")
    
    forms = get_forms(url)
    if not forms:
        print("❌ No forms found on the page.")
        return None  # Return None if no forms found

    results = []
    
    for i, form in enumerate(forms, start=1):
        action = form.get("action")
        method = form.get("method", "get").lower()
        full_action = urllib.parse.urljoin(url, action) if action else url
        
        print(f"📝 Form {i}: Method = {method.upper()}, Action = {full_action}")

        if method == "post":
            has_token = check_csrf_token(form)
            vulnerability_status = "Vulnerable" if not has_token else "Protected"
            print(f"⚠️ WARNING: CSRF Token NOT found!" if not has_token else "✅ CSRF protection detected.")
            
            results.append({
                "form_number": i,
                "method": method.upper(),
                "action": full_action,
                "csrf_protection": not has_token
            })
        else:
            print("ℹ️ This form uses GET request, CSRF not applicable.")

    return results

# Load previous scan results
try:
    with open("security_scan_results.json", "r") as f:
        previous_results = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    previous_results = {}

# Run the CSRF scan on all pages in mapped_data.json
scan_results = {}

for page in mapped_data["pages"]:
    url = page.get("url")
    if not url:
        continue  # Skip if no URL found

    csrf_results = test_csrf_vulnerability(url)
    if csrf_results:
        scan_results[url] = csrf_results

# Save the results with a timestamp
current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
previous_results[current_time] = {"CSRF_Scan": scan_results}

with open("security_scan_results.json", "w") as f:
    json.dump(previous_results, f, indent=4)

print("\n✅ Scan complete! Results saved in security_scan_results.json")
