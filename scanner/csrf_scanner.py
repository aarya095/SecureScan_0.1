import requests
from bs4 import BeautifulSoup
import urllib.parse
import json
from datetime import datetime

TOKEN_NAMES = ["csrf", "token", "authenticity_token", "_csrf"]

def load_mapped_data(filename="mapped_data.json"):
    """Load mapped website data from JSON file."""
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"⚠️ Error loading JSON file: {e}")
        return None

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
    inputs = form.find_all("input")
    for field in inputs:
        if field.get("type") == "hidden":
            name = field.get("name", "").lower()
            if any(token in name for token in TOKEN_NAMES):
                return True  # CSRF token found
    return False  # No CSRF token found

def test_csrf_vulnerability(url):
    """Test if a website is vulnerable to CSRF attacks."""
    print(f"\n🔍 Scanning {url} for CSRF vulnerabilities...\n")
    
    forms = get_forms(url)
    if not forms:
        print("❌ No forms found on the page.")
        return None

    results = []
    
    for i, form in enumerate(forms, start=1):
        action = form.get("action") or url
        method = form.get("method", "get").lower()
        full_action = urllib.parse.urljoin(url, action)

        print(f"📝 Form {i}: Method = {method.upper()}, Action = {full_action}")

        if method == "post":
            has_token = check_csrf_token(form)
            status = "Protected" if has_token else "Vulnerable"
            print(f"✅ CSRF Protection Detected." if has_token else f"⚠️ WARNING: CSRF Token NOT found!")
            
            results.append({
                "form_number": i,
                "method": method.upper(),
                "action": full_action,
                "csrf_protection": has_token
            })
        else:
            print("ℹ️ This form uses GET request, CSRF is not applicable.")

    return results

def save_results(scan_results, filename="security_scan_results.json"):
    """Save scan results to a JSON file."""
    try:
        with open(filename, "r") as f:
            previous_results = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        previous_results = {}

    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    previous_results[current_time] = {"CSRF_Scan": scan_results}

    with open(filename, "w") as f:
        json.dump(previous_results, f, indent=4)

    print("\n✅ CSRF scan complete! Results saved in security_scan_results.json")

def run():
    """Run the CSRF scanner."""
    print("\n🚀 Scanning...\n")

    mapped_data = load_mapped_data()
    if not mapped_data:
        print("❌ No mapped data found. Exiting CSRF scan.")
        return

    scan_results = {}

    for page in mapped_data.get("pages", []):
        url = page.get("url")
        if not url:
            continue  # Skip if no URL found

        csrf_results = test_csrf_vulnerability(url)
        if csrf_results:
            scan_results[url] = csrf_results

    save_results(scan_results)

if __name__ == "__main__":
    run()
