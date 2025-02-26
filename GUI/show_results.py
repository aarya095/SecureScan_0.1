import json
import os
import customtkinter as ctk

# Load scan results from JSON file
SECURITY_SCAN_RESULTS_FILE = "security_scan_results.json"

def load_security_results():
    """Loads security scan results from JSON file."""
    if not os.path.exists(SECURITY_SCAN_RESULTS_FILE):
        return {"Error": "No security scan results found!"}
    
    try:
        with open(SECURITY_SCAN_RESULTS_FILE, "r") as file:
            return json.load(file)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"Error": "Failed to read the scan results."}

# GUI Report Window
def show_security_report():
    results = load_security_results()

    # Create GUI Window
    root = ctk.CTk()
    root.title("🔍 Security Scan Report")
    root.geometry("800x600")
    root.configure(bg="#2b2b2b")  # Dark Theme

    # Scrollable Frame
    frame = ctk.CTkScrollableFrame(root, width=780, height=550)
    frame.pack(pady=10, padx=10, fill="both", expand=True)

    # Title
    title = ctk.CTkLabel(frame, text="🔍 Security Scan Report", font=("Arial", 20, "bold"))
    title.pack(pady=10)

    # Check if results exist
    if "Error" in results:
        error_label = ctk.CTkLabel(frame, text=results["Error"], font=("Arial", 16), fg_color="red")
        error_label.pack(pady=10)
    else:
        for key, value in results.items():
            # Target Site Information
            if key.startswith("http"):
                site_label = ctk.CTkLabel(frame, text=f"🌍 Target: {key}", font=("Arial", 18, "bold"))
                site_label.pack(pady=5, fill="x")

                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        sub_label = ctk.CTkLabel(frame, text=f"🔗 {sub_key}: {sub_value}", font=("Arial", 14))
                        sub_label.pack(pady=2)

            # Scan Results Processing
            elif key.replace("_", ":").count(":") == 2:  
                timestamp_label = ctk.CTkLabel(frame, text=f"🕒 Scan Timestamp: {key.replace('_', ':')}", font=("Arial", 14, "bold"))
                timestamp_label.pack(pady=5, fill="x")

                if isinstance(value, dict):
                    for scan_type, scan_results in value.items():
                        section_label = ctk.CTkLabel(frame, text=f"🔎 {scan_type.replace('_', ' ')}", font=("Arial", 16, "bold"))
                        section_label.pack(pady=5, fill="x")

                        if isinstance(scan_results, dict):
                            for url, issues in scan_results.items():
                                url_label = ctk.CTkLabel(frame, text=f"📌 URL: {url}", font=("Arial", 14, "bold"))
                                url_label.pack(pady=5)

                                if isinstance(issues, dict):
                                    for problem, status in issues.items():
                                        status_text = "✅ Safe" if not status else "⚠️ Issue Found!"
                                        issue_color = "green" if not status else "red"
                                        issue_label = ctk.CTkLabel(frame, text=f" - {problem}: {status_text}", font=("Arial", 12))
                                        issue_label.pack(pady=2, fill="x")

                        elif isinstance(scan_results, list):
                            for issue in scan_results:
                                payload = issue.get("payload", "Unknown")
                                vulnerable = issue.get("vulnerable", False)
                                vuln_text = "⚠️ Vulnerable" if vulnerable else "✅ Safe"
                                issue_color = "red" if vulnerable else "green"
                                issue_label = ctk.CTkLabel(frame, text=f" - {vuln_text} | Payload: {payload}", font=("Arial", 12))
                                issue_label.pack(pady=2, fill="x")


    # Run the GUI
    root.mainloop()

# Call the function to display the GUI
show_security_report()
