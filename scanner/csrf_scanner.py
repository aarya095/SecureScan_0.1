import requests
from bs4 import BeautifulSoup
import urllib.parse

def get_forms(url):
    """Extract all forms from a webpage."""
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    return soup.find_all("form")

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
        return

    for i, form in enumerate(forms, start=1):
        action = form.get("action")
        method = form.get("method", "get").lower()
        full_action = urllib.parse.urljoin(url, action) if action else url
        
        print(f"📝 Form {i}: Method = {method.upper()}, Action = {full_action}")

        if method == "post":
            has_token = check_csrf_token(form)
            if not has_token:
                print("⚠️  WARNING: CSRF Token NOT found! This form might be vulnerable.")
            else:
                print("✅ CSRF protection detected.")
        else:
            print("ℹ️ This form uses GET request, CSRF not applicable.")

if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., http://example.com/login): ").strip()
    test_csrf_vulnerability(target_url)
