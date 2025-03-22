import customtkinter as ctk
from PIL import Image
import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import sys
import threading

# Set BASE_DIR to the project's root directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCANNER_DIR = os.path.join(BASE_DIR, "scanner")

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR) 

print("🔍 BASE_DIR:", BASE_DIR)
print("🔍 SCANNER_DIR:", SCANNER_DIR)
print("🔍 sys.path:", sys.path)

def open_dashboard():
    """Main function to display the splash screen and dashboard."""
    
    def show_splash():
        """Display a splash screen before launching the dashboard."""
        splash = ctk.CTk()
        splash.geometry("672x378+540+270")
        splash.title("Loading...")
        splash.overrideredirect(True)

        # Load and display logo
        logo = ctk.CTkImage(light_image=Image.open("icons/SecureScan_dashboard_logo.png"), 
                            size=(672, 378))
        logo_label = ctk.CTkLabel(splash, image=logo, text="")
        logo_label.pack(expand=True)

        splash.after(1000, lambda: [splash.destroy(), show_dashboard()])
        splash.mainloop()

    def show_dashboard():
        """Display the main dashboard GUI."""
        ctk.set_appearance_mode("light") 
        ctk.set_default_color_theme("green") 

        root = ctk.CTk()
        root.title("SecureScan - Home")
        root.geometry("700x500+550+200")

        # Main Label
        main_label = ctk.CTkLabel(root, text="SecureScan", font=("Tahoma", 50, "bold"))
        main_label.place(x=450, y=80)

        # URL Entry Field
        url_txtfield = ctk.CTkEntry(root, font=("Arial", 20), width=200,
                                    corner_radius=10, border_width=2,
                                    border_color="black")
        url_txtfield.place(x=480, y=240)   

        def get_url():
            """Process the entered URL and run security scans."""
            url = url_txtfield.get().strip()
            if not url:
                messagebox.showwarning("Warning", "Please enter a URL.")
                return

            if not url.startswith(("http://", "https://")):
                messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
                return

            messagebox.showinfo("Processing", f"Scanning {url}... Please wait.")

            crawler_path = os.path.join(SCANNER_DIR, "crawler.py")
            if not os.path.exists(crawler_path):
                messagebox.showerror("Error", "crawler.py not found!")
                return

            def run_scans():
                """Run the scanning processes in a separate thread."""
                try:
                    # Run crawler.py
                    subprocess.run([sys.executable, crawler_path, url], check=True, cwd=BASE_DIR)

                    # Run security scanners
                    venv_python = os.path.join(BASE_DIR, ".venv", "Scripts", "python.exe")  # For Windows
                    if not os.path.exists(venv_python):  # Fallback to default Python
                        venv_python = sys.executable

                    subprocess.run([venv_python, os.path.join(SCANNER_DIR, "run_scanners.py")], check=True, cwd=BASE_DIR)

                    messagebox.showinfo("Complete", "Security scanning completed! Check the results.")
                except subprocess.CalledProcessError as e:
                    messagebox.showerror("Error", f"Process failed: {e}")
                except Exception as e:
                    messagebox.showerror("Error", f"Unexpected error: {e}")

            # Run the scan in a separate thread to keep the UI responsive
            root.after(100, lambda: threading.Thread(target=run_scans, daemon=True).start())

        # Scan Button
        scan_button = ctk.CTkButton(root, text="Scan Website", font=("Tahoma", 20, "bold"), 
                                    height=40, width=200, command=get_url)
        scan_button.place(x=430, y=300)    

        root.mainloop()

    show_splash()

if __name__ == "__main__":
    open_dashboard()
