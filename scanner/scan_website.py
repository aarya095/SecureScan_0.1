import subprocess
import json

SECURITY_SCAN_RESULTS_FILE = "/../security_scan_results.json"

def read_security_results():
    """Reads and returns the security scan results from JSON file."""
    if not os.path.exists(SECURITY_SCAN_RESULTS_FILE):
        print("\n❌ Security results file not found.")
        return {}

    try:
        with open(SECURITY_SCAN_RESULTS_FILE, "r") as file:
            return json.load(file)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"\n❌ Error reading {SECURITY_SCAN_RESULTS_FILE}: {e}")
        return {}

print("🚀 Running Crawler...")
subprocess.run(["python", "scanner/crawler.py"])

print("\n🚀 Running Security Scanners...")
try:
    subprocess.run(["python", "scanner/run_scanners.py"])
except subprocess.CalledProcessError as e:
    print(f"❌ Error running security scanners: {e}")

print("\n✅ Security Scan Completed! Results saved in", SECURITY_SCAN_RESULTS_FILE)
