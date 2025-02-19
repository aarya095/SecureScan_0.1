import customtkinter as ctk
from PIL import Image
import tkinter as tk
from tkinter import messagebox
import subprocess
import threading
import os 
import queue

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
        splash.mainloop()

    def show_dashboard():

        ctk.set_appearance_mode("light") 
        ctk.set_default_color_theme("green") 

        root = ctk.CTk()
        root.title("Home")
        root.geometry("700x500+550+200")

        placeholder_text = "Enter URL here..."

        def on_entry_click(event):
            if url_entry.get() == placeholder_text:
                url_entry.delete(0, ctk.END)
                url_entry.configure(text_color="black") 
        def on_focus_out(event):
            if not url_entry.get().strip():
                url_entry.insert(0, placeholder_text)
                url_entry.configure(text_color="gray")  

        title_label = ctk.CTkLabel(root, text="URL Analyzer", 
                                font=("Arial", 20, "bold"),
                                text_color="white",
                                fg_color="#16A085", 
                                corner_radius=10,  
                                width=250, height=40)
        title_label.place(x=225, y=30)

        url_entry = ctk.CTkEntry(root, width=300, font=("Verdana", 20),
                                text_color="black",
                                fg_color="white",  
                                border_width=2,
                                border_color="black")
        url_entry.insert(0, placeholder_text)
        url_entry.bind("<FocusIn>", on_entry_click)
        url_entry.bind("<FocusOut>", on_focus_out)
        url_entry.place(x=200, y=100)

        output_textbox = ctk.CTkTextbox(root, width=650, height=250,
                                        font=("Arial",15))
        output_textbox.place(x=25,y=250)

        output_queue = queue.Queue()

        def run_scripts(scanner):

            process = subprocess.Popen(["python","-m", scanner], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE, 
                                       text=True)
            
            for line in process.stdout:
                output_queue.put(line)
            for line in process.stderr:
                output_queue.put(line)
            process.wait()

        def update_output():
                try:
                    while True:
                        line = output_queue.get_nowait()
                        output_textbox.insert(ctk.END, line)
                        output_textbox.see(ctk.END)
                except queue.Empty:
                    pass
                root.after(100, update_output)

        def run_scanners():

            url = url_entry.get().strip()
            if not url or url == placeholder_text:
                messagebox.showwarning("Input Error", "Please enter a valid URL.")
                return
            
            def run_crawler():
                first_script_crawler = os.path.join("scanner","crawler.py")

                proc = subprocess.Popen(["python", first_script_crawler, url],
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, 
                                        text=True)
                
                proc.stdin.write(url + '\n')
                proc.stdin.flush()

                stdout, stderr = proc.communicate()

                output_queue.put(stdout)
                if stderr:
                     output_queue.put(stderr)

                if proc.returncode !=0:
                    output_queue.put("Crawler failed. Aborting scanner runs.\n")

                scanner_scripts = ["scanner.http",
                                "scanner.sql_injection",
                                "scanner.xss_injection",
                                "scanner.csrf_scanner",
                                "scanner.broken_authentication"]

                for script in scanner_scripts:
                        threading.Thread(target = run_scripts, args=(script,)).start()

            threading.Thread(target = run_crawler).start()

        scan_button = ctk.CTkButton(root, text="Analyze",
                                    font=("Arial", 15, "bold"),
                                    fg_color="#16A085", 
                                    text_color="white",
                                    hover_color="#1ABC9C", 
                                    width=150, height=40,
                                    command=run_scanners)
        scan_button.place(x=275, y=160)

        """back_button = ctk.CTkButton(root, text="Back",
                                    font=("Arial", 15, "bold"),
                                    fg_color="#16A085", 
                                    text_color="white",
                                    hover_color="#1ABC9C", 
                                    width=150, height=40,
                                    command=run_scanners)
        back_button.place(x=600, y=400)"""

        update_output()
        root.mainloop()

    show_splash()

if __name__ == "__main__":
    open_dashboard()