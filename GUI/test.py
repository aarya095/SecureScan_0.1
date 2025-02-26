import json
import customtkinter as ctk

# Function to analyze JSON data and display results
def load_json():
    try:
        with open("security_scan_results.json", "r") as file:
            data = json.load(file)
            
            # Clear previous content
            result_box.delete("1.0", ctk.END)
            recommendations_box.delete("1.0", ctk.END)
            
            # Extract main sections
            result_box.insert(ctk.END, "🔍 Scan Results\n\n", "header")

            for key, value in data.items():
                if "http" in key:  # Server Information
                    result_box.insert(ctk.END, f"🌐 Server: {key}\n", "subheader")
                    result_box.insert(ctk.END, f"  ➤ Protocol: {value['protocol']}\n", "info")
                    result_box.insert(ctk.END, f"  ➤ Secure: {'✅ Yes' if value['secure'] else '❌ No'}\n\n", "secure" if value['secure'] else "warning")

                elif "Broken_Auth_Scan" in value:  # Authentication Issues
                    result_box.insert(ctk.END, f"🛑 Authentication Issues Detected!\n", "warning")
                    auth_issues = value["Broken_Auth_Scan"]
                    for url, problems in auth_issues.items():
                        result_box.insert(ctk.END, f"  🔑 Endpoint: {url}\n", "subheader")
                        for issue, found in problems.items():
                            if found:
                                result_box.insert(ctk.END, f"  ❌ {issue}\n", "danger")

                else:  # Other vulnerabilities
                    result_box.insert(ctk.END, f"📅 Scan Time: {key}\n", "info")
                    for url, attacks in value.items():
                        result_box.insert(ctk.END, f"  🔍 Scanned: {url}\n", "subheader")
                        for attack in attacks:
                            if attack.get("vulnerable", False):
                                result_box.insert(ctk.END, f"  🚨 Vulnerability Found: {attack['payload']}\n", "danger")

            # Provide security recommendations
            recommendations_box.insert(ctk.END, "🛠 Security Recommendations\n\n", "header")

            if not data.get("http://localhost:3000", {}).get("secure", False):
                recommendations_box.insert(ctk.END, "❗ Enable HTTPS for better security.\n", "warning")
            
            if "Broken_Auth_Scan" in str(data):
                recommendations_box.insert(ctk.END, "🔑 Implement account lockout mechanisms.\n", "danger")
                recommendations_box.insert(ctk.END, "🔐 Enforce strong password policies.\n", "danger")

            recommendations_box.insert(ctk.END, "✅ Regularly scan and update your security measures.\n", "info")

    except Exception as e:
        result_box.delete("1.0", ctk.END)
        result_box.insert(ctk.END, f"Error loading file: {e}\n", "danger")

# Create the main CTk window
ctk.set_appearance_mode("dark")
app = ctk.CTk()
app.title("Security Scan Report")
app.geometry("700x600")

# Scan Results Textbox
result_box = ctk.CTkTextbox(app, wrap="none", width=680, height=300)
result_box.pack(pady=10, padx=10, fill="both", expand=True)

# Recommendations Textbox
recommendations_box = ctk.CTkTextbox(app, wrap="none", width=680, height=150)
recommendations_box.pack(pady=10, padx=10, fill="both", expand=True)

# Load JSON Button
load_button = ctk.CTkButton(app, text="Load Security Report", command=load_json)
load_button.pack(pady=10)

# ✅ Fix: Remove 'font' from tag_config
result_box.tag_config("header", foreground="white")
result_box.tag_config("subheader", foreground="lightblue")
result_box.tag_config("info", foreground="lightgreen")
result_box.tag_config("warning", foreground="yellow")
result_box.tag_config("danger", foreground="red")
result_box.tag_config("secure", foreground="green")

recommendations_box.tag_config("header", foreground="white")
recommendations_box.tag_config("info", foreground="lightgreen")
recommendations_box.tag_config("warning", foreground="yellow")
recommendations_box.tag_config("danger", foreground="red")

# Run the application
app.mainloop()
