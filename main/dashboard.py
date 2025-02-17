import customtkinter as ctk
from PIL import Image
import tkinter as tk

def open_dashboard():

    def show_splash():
        splash = ctk.CTk()
        splash.geometry("672x378+540+270")
        splash.title("Loading...")
        splash.overrideredirect(True)

        logo = ctk.CTkImage(light_image=Image.open("icons/SecureScan_dashboard_logo.png"), size=(672, 378))
        logo_label = ctk.CTkLabel(splash, image=logo, text="")
        logo_label.pack(expand=True)

        splash.after(2500, lambda: [splash.destroy(), show_dashboard()])
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

        url_entry = ctk.CTkEntry(root, width=300, font=("Verdana", 15),
                                text_color="black",
                                fg_color="white",  
                                border_width=2,
                                border_color="black")
        url_entry.insert(0, placeholder_text)
        url_entry.bind("<FocusIn>", on_entry_click)
        url_entry.bind("<FocusOut>", on_focus_out)
        url_entry.place(x=150, y=100)

        def analyze_url():
            print(f"Analyzing: {url_entry.get()}")

        scan_button = ctk.CTkButton(root, text="Analyze",
                                    font=("Arial", 15, "bold"),
                                    fg_color="#16A085", 
                                    text_color="white",
                                    hover_color="#1ABC9C", 
                                    width=150, height=40,
                                    command=analyze_url)
        scan_button.place(x=275, y=160)

        root.mainloop()

    show_splash()

if __name__ == "__main__":
    open_dashboard()