import json
import requests

# Common weak passwords list
weak_passwords = ["admin", "password", "123456", "password123", "letmein", "welcome","qwerty","abc123","54321","111111","123123"]

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

    for password in weak_passwords:
        data = {"username": "admin", "password": password}
        response = requests.post(target_url, data=data)

        if "Invalid" not in response.text and response.status_code == 200:
            print(f"⚠️ Weak credentials found: admin / {password}")
            return True

    print("✅ No weak credentials detected.")
    return False

def test_brute_force_protection(target_url):
    """Check if account lockout is enforced."""
    print(f"\n🔍 Testing {target_url} for brute-force protection...")

    for _ in range(5):  # Simulating multiple failed login attempts
        data = {"username": "admin", "password": "wrongpassword"}
        response = requests.post(target_url, data=data)

        if "Locked" in response.text or response.status_code == 429:
            print("✅ Account lockout is enforced.")
            return False

    print("❌ No account lockout detected! Brute-force attack is possible.")
    return True

def test_session_logout(target_url, dashboard_url, logout_url):
    """Check if session is properly invalidated after logout."""
    print(f"\n🔍 Checking session management for {target_url}...")

    session = requests.Session()

    # Log in with test credentials
    login_data = {"username": "admin", "password": "password123"}
    response = session.post(target_url, data=login_data)

    if "Invalid" in response.text:
        print("⚠️ Cannot log in with test credentials. Skipping session test.")
        return False

    # Check if dashboard is accessible
    dashboard_response = session.get(dashboard_url)
    if "Unauthorized" in dashboard_response.text:
        print("❌ Session not established correctly.")
        return False

    # Log out and check if session persists
    session.get(logout_url)
    dashboard_response_after_logout = session.get(dashboard_url)

    if "Unauthorized" not in dashboard_response_after_logout.text:
        print("❌ Session persists after logout! Logout is not secure.")
        return True

    print("✅ Session is properly invalidated after logout.")
    return False

def main():
    """Main function to run authentication tests on detected login pages."""
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

    # Save results to JSON
    with open("security_scan_results.json", "w") as file:
        json.dump(results, file, indent=4)

    print("\n✅ Authentication Tests Complete! Results saved in security_scan_results.json")

if __name__ == "__main__":
    main()
