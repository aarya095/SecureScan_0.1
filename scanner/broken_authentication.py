import json
import requests
from datetime import datetime

# Common weak passwords list
WEAK_PASSWORDS = [
    "admin", "password", "123456", "password123", "letmein", "welcome",
    "qwerty", "abc123", "54321", "111111", "123123"
]

def load_mapped_data(filename="mapped_data.json"):
    """Load and parse URLs from mapped_data.json."""
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"⚠️ Error loading JSON file: {e}")
        return {}

def find_login_pages(data):
    """Extract login form URLs from mapped_data.json."""
    login_pages = []

    for page in data.get("pages", []):
        for form in page.get("forms", []):
            # Check if the form has a password field (indicating login page)
            if any("password" in field.lower() for field in form.get("inputs", [])):
                login_pages.append(form["action"])

    return login_pages

def test_weak_passwords(target_url):
    """Check for weak credentials."""
    print(f"\n🔍 Testing {target_url} for weak login credentials...")

    for password in WEAK_PASSWORDS:
        data = {"username": "admin", "password": password}
        try:
            response = requests.post(target_url, data=data, timeout=5)

            if "Invalid" not in response.text and response.status_code == 200:
                print(f"⚠️ Weak credentials found: admin / {password}")
                return True
        except requests.RequestException as e:
            print(f"❌ Error testing weak passwords: {e}")
            return False

    print("✅ No weak credentials detected.")
    return False

def test_brute_force_protection(target_url):
    """Check if account lockout is enforced."""
    print(f"\n🔍 Testing {target_url} for brute-force protection...")

    for _ in range(5):  # Simulating multiple failed login attempts
        data = {"username": "admin", "password": "wrongpassword"}
        try:
            response = requests.post(target_url, data=data, timeout=5)

            if "Locked" in response.text or response.status_code == 429:
                print("✅ Account lockout is enforced.")
                return False
        except requests.RequestException as e:
            print(f"❌ Error testing brute-force protection: {e}")
            return False

    print("❌ No account lockout detected! Brute-force attack is possible.")
    return True

def test_session_logout(target_url, dashboard_url, logout_url):
    """Check if session is properly invalidated after logout."""
    print(f"\n🔍 Checking session management for {target_url}...")

    session = requests.Session()

    # Log in with test credentials
    login_data = {"username": "admin", "password": "password123"}
    try:
        response = session.post(target_url, data=login_data, timeout=5)

        if "Invalid" in response.text:
            print("⚠️ Cannot log in with test credentials. Skipping session test.")
            return False
    except requests.RequestException as e:
        print(f"❌ Error logging in: {e}")
        return False

    # Check if dashboard is accessible
    try:
        dashboard_response = session.get(dashboard_url, timeout=5)
        if "Unauthorized" in dashboard_response.text:
            print("❌ Session not established correctly.")
            return False
    except requests.RequestException as e:
        print(f"❌ Error accessing dashboard: {e}")
        return False

    # Log out and check if session persists
    try:
        session.get(logout_url, timeout=5)
        dashboard_response_after_logout = session.get(dashboard_url, timeout=5)

        if "Unauthorized" not in dashboard_response_after_logout.text:
            print("❌ Session persists after logout! Logout is not secure.")
            return True
    except requests.RequestException as e:
        print(f"❌ Error testing session logout: {e}")
        return False

    print("✅ Session is properly invalidated after logout.")
    return False

def save_results(results, filename="security_scan_results.json"):
    """Save results to a JSON file with a timestamp."""
    try:
        with open(filename, "r") as file:
            previous_results = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        previous_results = {}

    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    previous_results[current_time] = {"Broken_Auth_Scan": results}

    with open(filename, "w") as file:
        json.dump(previous_results, file, indent=4)

    print("\n✅ Authentication Tests Complete! Results saved in security_scan_results.json")

def run():
    """Main function to run authentication tests on detected login pages."""
    print("\n🚀 Scanning...\n")

    mapped_data = load_mapped_data()

    if not mapped_data:
        print("❌ No mapped data found!")
        return

    login_pages = find_login_pages(mapped_data)

    if not login_pages:
        print("❌ No login forms found in the scanned website.")
        return

    results = {}

    for login_url in login_pages:
        print(f"\n🚀 Testing login page: {login_url}")

        # Guess dashboard and logout URLs based on login path
        base_url = "/".join(login_url.split("/")[:-1])
        dashboard_url = f"{base_url}/dashboard"
        logout_url = f"{base_url}/logout"

        weak_passwords_found = test_weak_passwords(login_url)
        no_account_lockout = test_brute_force_protection(login_url)
        session_issue = test_session_logout(login_url, dashboard_url, logout_url)

        results[login_url] = {
            "Weak Passwords": weak_passwords_found,
            "No Account Lockout": no_account_lockout,
            "Session Issue": session_issue
        }

    save_results(results)

if __name__ == "__main__":
    run()
