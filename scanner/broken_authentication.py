import requests

# Common weak passwords
weak_passwords = ["admin", "password", "123456", "password123", "letmein", "welcome"]

# Function to test for weak credentials
def test_weak_passwords(target_url):
    print(f"\nTesting {target_url} for weak login credentials...")

    for password in weak_passwords:
        data = {"username": "admin", "password": password}
        response = requests.post(target_url, data=data)

        if "Invalid" not in response.text and response.status_code == 200:
            print(f"⚠️  Weak credentials found: admin / {password}")
            return True

    print("No weak credentials detected.")
    return False

# Function to check if account lockout is enforced
def test_brute_force_protection(target_url):
    print(f"\n🔍 Testing {target_url} for account lockout protection...")

    for i in range(5):  # Simulating multiple failed login attempts
        data = {"username": "admin", "password": "wrongpassword"}
        response = requests.post(target_url, data=data)

        if "Locked" in response.text or response.status_code == 429:
            print("Account lockout is enforced after multiple failed attempts.")
            return False

    print("No account lockout detected! Brute-force attack is possible.")
    return True

# Function to test if session is properly invalidated after logout
def test_session_logout(target_url, dashboard_url, logout_url):
    print(f"\n🔍 Checking session management on {target_url}...")

    session = requests.Session()

    # Log in with valid credentials
    login_data = {"username": "admin", "password": "password123"}
    response = session.post(target_url, data=login_data)

    if "Invalid" in response.text:
        print("Cannot log in with test credentials. Skipping session test.")
        return False

    # Check if dashboard is accessible
    dashboard_response = session.get(dashboard_url)
    if "Unauthorized" in dashboard_response.text:
        print("Session not established correctly.")
        return False

    # Log out and check if session persists
    session.get(logout_url)
    dashboard_response_after_logout = session.get(dashboard_url)

    if "Unauthorized" not in dashboard_response_after_logout.text:
        print("Session persists after logout! Logout is not secure.")
        return True

    print("Session is properly invalidated after logout.")
    return False

# Main Function
def main():
    target_url = input("Enter the target login URL (e.g., http://localhost:3000/login): ")
    dashboard_url = input("Enter the dashboard URL (e.g., http://localhost:3000/dashboard): ")
    logout_url = input("Enter the logout URL (e.g., http://localhost:3000/logout): ")

    # Run tests
    weak_passwords_found = test_weak_passwords(target_url)
    no_account_lockout = test_brute_force_protection(target_url)
    session_issue = test_session_logout(target_url, dashboard_url, logout_url)

    print("\n**Scan Summary**:")
    if weak_passwords_found:
        print("Weak passwords detected!")
    if no_account_lockout:
        print("No account lockout protection detected!")
    if session_issue:
        print("Session is not properly invalidated after logout!")
    if not (weak_passwords_found or no_account_lockout or session_issue):
        print("No critical Broken Authentication issues detected.")

if __name__ == "__main__":
    main()
