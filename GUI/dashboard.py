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


class Dashboard:
    def __init__(self):
        """Initialize the SecureScan application."""
        self.menu_visible = False
        self.root = None  # Will be assigned in show_dashboard()

    def open_dashboard(self):
        """Launch splash screen before opening the main dashboard."""
        self.show_splash()

    def show_splash(self):
        """Display the splash screen."""
        splash = ctk.CTk()
        splash.geometry("672x378+540+270")
        splash.title("Loading...")
        splash.overrideredirect(True)

        # Load and display logo
        logo = ctk.CTkImage(
            light_image=Image.open("icons/SecureScan_dashboard_logo.png"), size=(672, 378)
        )
        logo_label = ctk.CTkLabel(splash, image=logo, text="")
        logo_label.pack(expand=True)

        splash.after(1000, lambda: [splash.destroy(), self.show_dashboard()])
        splash.mainloop()

    def show_dashboard(self):
        """Display the main dashboard."""
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("green")

        self.root = ctk.CTk()
        self.root.title("SecureScan - Home")
        self.root.geometry("700x500+550+200")

        # Configure grid layout
        for i in range(7):
            self.root.grid_columnconfigure(i, weight=1, uniform='a')
        for j in range(6):
            self.root.grid_rowconfigure(j, weight=1, uniform='b')

        # Title Label
        main_label = ctk.CTkLabel(self.root, text="SecureScan", font=("Tahoma", 40, "bold"))
        main_label.grid(row=0, column=1, columnspan=5, sticky='ew', pady=(10, 0))

        # URL Entry Field
        self.url_txtfield = ctk.CTkEntry(self.root, font=("Arial", 25), corner_radius=10, border_color="black")
        self.url_txtfield.grid(row=2, column=2, columnspan=4, padx=20, sticky='ew')

        # Scan Button
        scan_button = ctk.CTkButton(
            self.root, text="Scan Website", font=("Tahoma", 20, "bold"), height=40, width=200,
            command=self.get_url
        )
        scan_button.grid(row=3, column=2, columnspan=3, pady=10, sticky='ew')

        # Profile Button
        profile_button = ctk.CTkButton(self.root, text="☰ Profile", width=100, command=self.toggle_menu)
        profile_button.grid(row=0, column=6, padx=10, pady=10, sticky='ne')

        # Custom Scan Button
        custom_scan_button = ctk.CTkButton(self.root, text="Custom Scan", height=40)
        custom_scan_button.grid(row=5, column=2, columnspan=3, pady=(10, 20), sticky="ew")

        # Dropdown Menu (Initially Hidden)
        self.menu_frame = ctk.CTkFrame(self.root, fg_color="gray25", corner_radius=10)

        # Menu Buttons inside Dropdown
        menu_buttons = [
            ctk.CTkButton(self.menu_frame, text="Settings"),
            ctk.CTkButton(self.menu_frame, text="Logout", command=self.root.quit)
        ]
        for btn in menu_buttons:
            btn.pack(fill="x", padx=5, pady=2)

        self.root.mainloop()

    def toggle_menu(self):
        """Show or hide the dropdown menu."""
        if self.menu_visible:
            self.menu_frame.place_forget()
        else:
            self.menu_frame.place(relx=0.9, rely=0.1, anchor="ne")
        self.menu_visible = not self.menu_visible

    def get_url(self):
        """Process the entered URL and start scanning."""
        url = self.url_txtfield.get().strip()
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

        # Run scans in a separate thread to avoid UI freezing
        threading.Thread(target=self.run_scans, args=(url,), daemon=True).start()

    def run_scans(self, url):
        """Run the scanning processes in a separate thread."""
        try:
            subprocess.run([sys.executable, os.path.join(SCANNER_DIR, "crawler.py"), url], check=True, cwd=BASE_DIR)

            venv_python = os.path.join(BASE_DIR, ".venv", "Scripts", "python.exe")
            if not os.path.exists(venv_python):
                venv_python = sys.executable

            subprocess.run([venv_python, os.path.join(SCANNER_DIR, "run_scanners.py")], check=True, cwd=BASE_DIR)

            messagebox.showinfo("Complete", "Security scanning completed! Check the results.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Process failed: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")


if __name__ == "__main__":
    app = SecureScanApp()
    app.open_dashboard()
