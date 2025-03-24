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

def open_dashboard():
    """Main function to display the splash screen and dashboard."""

    def show_splash():
        """Display a splash screen before launching the dashboard."""
        splash = ctk.CTk()
        splash.geometry("672x378+540+270")
        splash.title("Loading...")
        splash.overrideredirect(True)

        # Load and display logo
        logo = ctk.CTkImage(light_image=Image.open("icons/SecureScan_dashboard_logo.png"), size=(672, 378))
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

        # 🔹 Configure grid for neat layout
        for i in range(7):  
            root.grid_columnconfigure(i, weight=1, uniform='a')  # Even column distribution
        for j in range(6):
            root.grid_rowconfigure(j, weight=1, uniform='b')  # Even row distribution

        # 🔹 Main Label (Centered)
        main_label = ctk.CTkLabel(root, text="SecureScan", font=("Tahoma", 40, "bold"))
        main_label.grid(row=0, column=1, columnspan=5, sticky='ew', pady=(10, 0))  # Spans across the center

        # 🔹 URL Entry Field (Centered)
        url_txtfield = ctk.CTkEntry(root, font=("Arial", 25), corner_radius=10, border_color="black")
        url_txtfield.grid(row=2, column=2, columnspan=4, padx=20, sticky='ew')   

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
                    subprocess.run([sys.executable, crawler_path, url], check=True, cwd=BASE_DIR)

                    venv_python = os.path.join(BASE_DIR, ".venv", "Scripts", "python.exe")  
                    if not os.path.exists(venv_python):  
                        venv_python = sys.executable

                    subprocess.run([venv_python, os.path.join(SCANNER_DIR, "run_scanners.py")], check=True, cwd=BASE_DIR)

                    messagebox.showinfo("Complete", "Security scanning completed! Check the results.")
                except subprocess.CalledProcessError as e:
                    messagebox.showerror("Error", f"Process failed: {e}")
                except Exception as e:
                    messagebox.showerror("Error", f"Unexpected error: {e}")

            root.after(100, lambda: threading.Thread(target=run_scans, daemon=True).start())

        # 🔹 Scan Button (Below URL Entry)
        scan_button = ctk.CTkButton(root, text="Scan Website", font=("Tahoma", 20, "bold"), height=40, width=200, command=get_url)
        scan_button.grid(row=3, column=2, columnspan=3, pady=10, sticky='ew')    

        # 🔹 Profile Button (Top Right Corner)
        profile_button = ctk.CTkButton(root, text="☰ Profile", width=100, command=lambda: toggle_menu())
        profile_button.grid(row=0, column=6, padx=10, pady=10, sticky='ne')

        menu_visible = False  

        def toggle_menu():
            """ Show or hide the dropdown menu """
            nonlocal menu_visible
            if menu_visible:
                menu_frame.place_forget()  # Hide menu
            else:
                menu_frame.place(relx=0.9, rely=0.1, anchor="ne")  # Show menu
            menu_visible = not menu_visible  # Toggle state

        # 🔹 Custom Scan Button (At the bottom)
        custom_scan_button = ctk.CTkButton(root, text="Custom Scan", height=40)
        custom_scan_button.grid(row=5, column=2, columnspan=3, pady=(10, 20), sticky="ew")

        # 🔹 Dropdown Menu (Initially Hidden)
        menu_frame = ctk.CTkFrame(root, fg_color="gray25", corner_radius=10)

        # 🔹 Menu Buttons inside Dropdown
        menu_buttons = [
            ctk.CTkButton(menu_frame, text="Settings"),
            ctk.CTkButton(menu_frame, text="Logout", command=root.quit)
        ]
        for btn in menu_buttons:
            btn.pack(fill="x", padx=5, pady=2)

        root.mainloop()

    show_splash()

if __name__ == "__main__":
    open_dashboard()
