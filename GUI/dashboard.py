import customtkinter as ctk
from PIL import Image
import tkinter as tk
from tkinter import messagebox
import subprocess

def open_dashboard():
    def show_splash():
        splash = ctk.CTk()
        splash.geometry("672x378+540+270")
        splash.title("Loading...")
        splash.overrideredirect(True)

        logo = ctk.CTkImage(light_image=Image.open("icons/SecureScan_dashboard_logo.png"), 
                            size=(672, 378))
        logo_label = ctk.CTkLabel(splash, image=logo, text="")
        logo_label.pack(expand=True)

        splash.after(3000, lambda: [splash.destroy(), show_dashboard()])
        
    def show_dashboard():
        ctk.set_appearance_mode("light") 
        ctk.set_default_color_theme("green") 

        root = ctk.CTk()
        root.title("Home")
        root.geometry("700x500+550+200")

        main_label = ctk.CTkLabel(root, text="SecureScan", font=("Tahoma", 50, "bold"))
        main_label.place(x=450, y=80)

        url_txtfield = ctk.CTkEntry(root, font=("Arial", 20), width=200,
                                    corner_radius=10, border_width=2,
                                    border_color="black")
        url_txtfield.place(x=480, y=240)   

        def get_url():
            url = url_txtfield.get().strip()
            if url:
                if not url.startswith("http"):
                    messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
                    return

                messagebox.showinfo("Processing", f"Scanning {url}... Please wait.")
                
                # Run crawler.py with the URL as an argument
                subprocess.run(["python", "scanner/crawler.py", url], check=True)

                # Run run_scanners.py after crawling is complete
                subprocess.run(["python", "run_scanners.py"], check=True)

                messagebox.showinfo("Complete", "Security scanning completed! Check the results.")

            else:
                messagebox.showwarning("Warning", "Please enter a URL.")

        scan_button = ctk.CTkButton(root, text="Scan Website", font=("Tahoma", 20, "bold"), 
                                    height=40, width=200, command=get_url)
        scan_button.place(x=430, y=300)    

        root.mainloop()

    show_splash()

if __name__ == "__main__":
    open_dashboard()
